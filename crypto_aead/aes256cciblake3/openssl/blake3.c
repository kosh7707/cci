#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "blake3.h"
#include "blake3_impl.h"

// The idea here is that this file can be copied verbatim for all the different
// SUPERCOP platform directories, along with different platform-specific
// implementation files also included verbatim from github.com/BLAKE3-team/BLAKE3,
// and only this one header file needs to be changed in each directory.
#include "blake3_static_dispatch.h"

// all-at-once chunk hashing
INLINE void hash_chunk(const uint8_t *chunk, size_t chunk_len, const uint32_t key[8],
                       uint64_t chunk_counter, uint8_t flags, bool is_root, uint8_t out[BLAKE3_OUT_LEN]) {
  uint32_t cv[8];
  memcpy(cv, key, BLAKE3_KEY_LEN);
  uint8_t block_flags = flags | CHUNK_START;
  // Compress all the blocks prior to the last one.
  while (chunk_len > BLAKE3_BLOCK_LEN) {
    blake3_compress_in_place(cv, chunk, BLAKE3_BLOCK_LEN, chunk_counter, block_flags);
    chunk += BLAKE3_BLOCK_LEN;
    chunk_len -= BLAKE3_BLOCK_LEN;
    block_flags = flags;
  }
  // If the last block is short, copy it into a block buffer.
  const uint8_t *last_block_ptr;
  uint8_t last_block_buf[BLAKE3_BLOCK_LEN];
  if (chunk_len == BLAKE3_BLOCK_LEN) {
    last_block_ptr = chunk;
  } else {
    memset(last_block_buf, 0, BLAKE3_BLOCK_LEN);
    memcpy(last_block_buf, chunk, chunk_len);
    last_block_ptr = last_block_buf;
  }
  // Compress the final block.
  block_flags |= CHUNK_END;
  if (is_root) {
      block_flags |= ROOT;
  }
  blake3_compress_in_place(cv, last_block_ptr, chunk_len, chunk_counter, block_flags);
  memcpy(out, cv, BLAKE3_OUT_LEN);
}

// Given some input larger than one chunk, return the number of bytes that
// should go in the left subtree. This is the largest power-of-2 number of
// chunks that leaves at least 1 byte for the right subtree.
INLINE size_t left_len(size_t content_len) {
  // Subtract 1 to reserve at least one byte for the right side. content_len
  // should always be greater than BLAKE3_CHUNK_LEN.
  size_t full_chunks = (content_len - 1) / BLAKE3_CHUNK_LEN;
  return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
}

// Use SIMD parallelism to hash up to MAX_SIMD_DEGREE chunks at the same time
// on a single thread. Write out the chunk chaining values and return the
// number of chunks hashed. These chunks are never the root and never empty;
// those cases use a different codepath.
INLINE size_t compress_chunks_parallel(const uint8_t *input, size_t input_len,
                                       const uint32_t key[8],
                                       uint64_t chunk_counter, uint8_t flags,
                                       uint8_t *out) {
#if defined(BLAKE3_TESTING)
  assert(0 < input_len);
  assert(input_len <= MAX_SIMD_DEGREE * BLAKE3_CHUNK_LEN);
#endif

  const uint8_t *chunks_array[MAX_SIMD_DEGREE];
  size_t input_position = 0;
  size_t chunks_array_len = 0;
  while (input_len - input_position >= BLAKE3_CHUNK_LEN) {
    chunks_array[chunks_array_len] = &input[input_position];
    input_position += BLAKE3_CHUNK_LEN;
    chunks_array_len += 1;
  }

  blake3_hash_many(chunks_array, chunks_array_len,
                   BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, key, chunk_counter,
                   true, flags, CHUNK_START, CHUNK_END, out);

  // Hash the remaining partial chunk, if there is one. Note that the empty
  // chunk (meaning the empty message) is a different codepath.
  if (input_len > input_position) {
    uint64_t counter = chunk_counter + (uint64_t)chunks_array_len;
    hash_chunk(&input[input_position], input_len - input_position, key,
               counter, flags, false, &out[chunks_array_len * BLAKE3_OUT_LEN]);
    return chunks_array_len + 1;
  } else {
    return chunks_array_len;
  }
}

// Use SIMD parallelism to hash up to MAX_SIMD_DEGREE parents at the same time
// on a single thread. Write out the parent chaining values and return the
// number of parents hashed. (If there's an odd input chaining value left over,
// return it as an additional output.) These parents are never the root and
// never empty; those cases use a different codepath.
INLINE size_t compress_parents_parallel(const uint8_t *child_chaining_values,
                                        size_t num_chaining_values,
                                        const uint32_t key[8], uint8_t flags,
                                        uint8_t *out) {
#if defined(BLAKE3_TESTING)
  assert(2 <= num_chaining_values);
  assert(num_chaining_values <= 2 * MAX_SIMD_DEGREE_OR_2);
#endif

  const uint8_t *parents_array[MAX_SIMD_DEGREE_OR_2];
  size_t parents_array_len = 0;
  while (num_chaining_values - (2 * parents_array_len) >= 2) {
    parents_array[parents_array_len] =
        &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN];
    parents_array_len += 1;
  }

  blake3_hash_many(parents_array, parents_array_len, 1, key,
                   0, // Parents always use counter 0.
                   false, flags | PARENT,
                   0, // Parents have no start flags.
                   0, // Parents have no end flags.
                   out);

  // If there's an odd child left over, it becomes an output.
  if (num_chaining_values > 2 * parents_array_len) {
    memcpy(&out[parents_array_len * BLAKE3_OUT_LEN],
           &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN],
           BLAKE3_OUT_LEN);
    return parents_array_len + 1;
  } else {
    return parents_array_len;
  }
}

// The wide helper function returns (writes out) an array of chaining values
// and returns the length of that array. The number of chaining values returned
// is the dynamically detected SIMD degree, at most MAX_SIMD_DEGREE. Or fewer,
// if the input is shorter than that many chunks. The reason for maintaining a
// wide array of chaining values going back up the tree, is to allow the
// implementation to hash as many parents in parallel as possible.
//
// As a special case when the SIMD degree is 1, this function will still return
// at least 2 outputs. This guarantees that this function doesn't perform the
// root compression. (If it did, it would use the wrong flags, and also we
// wouldn't be able to implement exendable output.) Note that this function is
// not used when the whole input is only 1 chunk long; that's a different
// codepath.
//
// Why not just have the caller split the input on the first update(), instead
// of implementing this special rule? Because we don't want to limit SIMD or
// multi-threading parallelism for that update().
static size_t blake3_compress_subtree_wide(const uint8_t *input,
                                           size_t input_len,
                                           const uint32_t key[8],
                                           uint64_t chunk_counter,
                                           uint8_t flags, uint8_t *out) {
  // Note that the single chunk case does *not* bump the SIMD degree up to 2
  // when it is 1. If this implementation adds multi-threading in the future,
  // this gives us the option of multi-threading even the 2-chunk case, which
  // can help performance on smaller platforms.
  if (input_len <= SIMD_DEGREE * BLAKE3_CHUNK_LEN) {
    return compress_chunks_parallel(input, input_len, key, chunk_counter, flags,
                                    out);
  }

  // With more than simd_degree chunks, we need to recurse. Start by dividing
  // the input into left and right subtrees. (Note that this is only optimal
  // as long as the SIMD degree is a power of 2. If we ever get a SIMD degree
  // of 3 or something, we'll need a more complicated strategy.)
  size_t left_input_len = left_len(input_len);
  size_t right_input_len = input_len - left_input_len;
  const uint8_t *right_input = &input[left_input_len];
  uint64_t right_chunk_counter =
      chunk_counter + (uint64_t)(left_input_len / BLAKE3_CHUNK_LEN);

  // Make space for the child outputs. Here we use MAX_SIMD_DEGREE_OR_2 to
  // account for the special case of returning 2 outputs when the SIMD degree
  // is 1.
  uint8_t cv_array[2 * MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t degree = SIMD_DEGREE;
  if (left_input_len > BLAKE3_CHUNK_LEN && degree == 1) {
    // The special case: We always use a degree of at least two, to make
    // sure there are two outputs. Except, as noted above, at the chunk
    // level, where we allow degree=1. (Note that the 1-chunk-input case is
    // a different codepath.)
    degree = 2;
  }
  uint8_t *right_cvs = &cv_array[degree * BLAKE3_OUT_LEN];

  // Recurse! If this implementation adds multi-threading support in the
  // future, this is where it will go.
  size_t left_n = blake3_compress_subtree_wide(input, left_input_len, key,
                                               chunk_counter, flags, cv_array);
  size_t right_n = blake3_compress_subtree_wide(
      right_input, right_input_len, key, right_chunk_counter, flags, right_cvs);

  // The special case again. If simd_degree=1, then we'll have left_n=1 and
  // right_n=1. Rather than compressing them into a single output, return
  // them directly, to make sure we always have at least two outputs.
  if (left_n == 1) {
    memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
    return 2;
  }

  // Otherwise, do one layer of parent node compression.
  size_t num_chaining_values = left_n + right_n;
  return compress_parents_parallel(cv_array, num_chaining_values, key, flags,
                                   out);
}

// Hash a subtree with compress_subtree_wide(), and then condense the resulting
// list of chaining values down to a single parent node. Don't compress that
// last parent node, however. Instead, return its message bytes (the
// concatenated chaining values of its children). This is necessary when the
// first call to update() supplies a complete subtree, because the topmost
// parent node of that subtree could end up being the root. It's also necessary
// for extended output in the general case.
//
// As with compress_subtree_wide(), this function is not used on inputs of 1
// chunk or less. That's a different codepath.
INLINE void compress_subtree_to_parent_node(
    const uint8_t *input, size_t input_len, const uint32_t key[8],
    uint64_t chunk_counter, uint8_t flags, uint8_t out[2 * BLAKE3_OUT_LEN]) {
#if defined(BLAKE3_TESTING)
  assert(input_len > BLAKE3_CHUNK_LEN);
#endif

  uint8_t cv_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t num_cvs = blake3_compress_subtree_wide(input, input_len, key,
                                                chunk_counter, flags, cv_array);
  assert(num_cvs <= MAX_SIMD_DEGREE_OR_2);

  // If MAX_SIMD_DEGREE is greater than 2 and there's enough input,
  // compress_subtree_wide() returns more than 2 chaining values. Condense
  // them into 2 by forming parent nodes repeatedly.
  uint8_t out_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN / 2];
  // The second half of this loop condition is always true, and we just
  // asserted it above. But GCC can't tell that it's always true, and if NDEBUG
  // is set on platforms where MAX_SIMD_DEGREE_OR_2 == 2, GCC emits spurious
  // warnings here. GCC 8.5 is particularly sensitive, so if you're changing
  // this code, test it against that version.
  while (num_cvs > 2 && num_cvs <= MAX_SIMD_DEGREE_OR_2) {
    num_cvs =
        compress_parents_parallel(cv_array, num_cvs, key, flags, out_array);
    memcpy(cv_array, out_array, num_cvs * BLAKE3_OUT_LEN);
  }
  memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
}

void blake3_default_hash(const uint8_t *input, size_t input_len, uint8_t output[BLAKE3_OUT_LEN]) {
  if (input_len <= BLAKE3_CHUNK_LEN) {
    hash_chunk(input, input_len, IV, 0, 0, true, output);
    return;
  }

  uint8_t root_node[2 * BLAKE3_OUT_LEN];
  compress_subtree_to_parent_node(input, input_len, IV, 0, 0, root_node);
  uint32_t cv[8];
  memcpy(cv, IV, BLAKE3_OUT_LEN);
  blake3_compress_in_place(cv, root_node, BLAKE3_BLOCK_LEN, 0, PARENT | ROOT);
  memcpy(output, cv, BLAKE3_OUT_LEN);
}

/* ================================================================== */
/* Streaming (incremental) API                                        */
/* ================================================================== */

// Merge a new CV into the Merkle tree stack.  The number of trailing
// zero bits in chunk_counter tells us how many completed subtree
// pairs to merge.
INLINE void hasher_merge_cv_stack(blake3_hasher *self, uint64_t total_chunks) {
  while ((total_chunks & 1) == 0) {
    // Pop two CVs, compress as parent, push result
    self->cv_stack_len -= 1;
    uint8_t parent_block[BLAKE3_BLOCK_LEN];
    memcpy(parent_block,
           &self->cv_stack[(size_t)(self->cv_stack_len - 1) * BLAKE3_OUT_LEN],
           BLAKE3_OUT_LEN);
    memcpy(parent_block + BLAKE3_OUT_LEN,
           &self->cv_stack[(size_t)self->cv_stack_len * BLAKE3_OUT_LEN],
           BLAKE3_OUT_LEN);
    uint32_t cv[8];
    memcpy(cv, self->key, BLAKE3_KEY_LEN);
    blake3_compress_in_place(cv, parent_block, BLAKE3_BLOCK_LEN, 0, PARENT);
    memcpy(&self->cv_stack[(size_t)(self->cv_stack_len - 1) * BLAKE3_OUT_LEN],
           cv, BLAKE3_OUT_LEN);
    total_chunks >>= 1;
  }
}

// Push one complete chunk's CV onto the stack and merge.
INLINE void hasher_push_chunk_cv(blake3_hasher *self, const uint8_t *chunk,
                                  size_t chunk_len) {
  uint8_t cv_out[BLAKE3_OUT_LEN];
  hash_chunk(chunk, chunk_len, self->key, self->chunk_counter, 0, false, cv_out);
  memcpy(&self->cv_stack[(size_t)self->cv_stack_len * BLAKE3_OUT_LEN],
         cv_out, BLAKE3_OUT_LEN);
  self->cv_stack_len += 1;
  self->chunk_counter += 1;
  hasher_merge_cv_stack(self, self->chunk_counter);
}

void blake3_hasher_init(blake3_hasher *self) {
  memcpy(self->key, IV, BLAKE3_KEY_LEN);
  self->chunk_counter = 0;
  self->buf_len = 0;
  self->cv_stack_len = 0;
}

void blake3_hasher_update(blake3_hasher *self, const uint8_t *input,
                           size_t input_len) {
  if (input_len == 0) return;

  // If there's a partial chunk in buf, try to complete it.
  if (self->buf_len > 0) {
    size_t want = BLAKE3_CHUNK_LEN - self->buf_len;
    if (input_len <= want) {
      memcpy(self->buf + self->buf_len, input, input_len);
      self->buf_len += input_len;
      return;
    }
    memcpy(self->buf + self->buf_len, input, want);
    input += want;
    input_len -= want;
    hasher_push_chunk_cv(self, self->buf, BLAKE3_CHUNK_LEN);
    self->buf_len = 0;
  }

  // SIMD batch: process SIMD_DEGREE full chunks at a time using
  // compress_chunks_parallel() for 4-way SSE4.1 parallelism.
  while (input_len > SIMD_DEGREE * BLAKE3_CHUNK_LEN) {
    size_t batch_len = SIMD_DEGREE * BLAKE3_CHUNK_LEN;
    uint8_t cv_out[SIMD_DEGREE * BLAKE3_OUT_LEN];
    size_t num_cvs = compress_chunks_parallel(
        input, batch_len, self->key, self->chunk_counter, 0, cv_out);
    for (size_t i = 0; i < num_cvs; i++) {
      memcpy(&self->cv_stack[(size_t)self->cv_stack_len * BLAKE3_OUT_LEN],
             &cv_out[i * BLAKE3_OUT_LEN], BLAKE3_OUT_LEN);
      self->cv_stack_len += 1;
      self->chunk_counter += 1;
      hasher_merge_cv_stack(self, self->chunk_counter);
    }
    input += batch_len;
    input_len -= batch_len;
  }

  // Process remaining full chunks one at a time.
  while (input_len > BLAKE3_CHUNK_LEN) {
    hasher_push_chunk_cv(self, input, BLAKE3_CHUNK_LEN);
    input += BLAKE3_CHUNK_LEN;
    input_len -= BLAKE3_CHUNK_LEN;
  }

  // Buffer remaining bytes (1..BLAKE3_CHUNK_LEN).
  if (input_len > 0) {
    memcpy(self->buf, input, input_len);
    self->buf_len = input_len;
  }
}

void blake3_hasher_finalize(const blake3_hasher *self,
                             uint8_t output[BLAKE3_OUT_LEN]) {
  // If no data was ever pushed to the stack, the entire message is
  // in buf (possibly empty).  This is the single-chunk case.
  if (self->cv_stack_len == 0) {
    hash_chunk(self->buf, self->buf_len, self->key,
               self->chunk_counter, 0, true, output);
    return;
  }

  // Hash the remaining partial chunk (there must be one, since we only
  // push complete chunks in update).
  uint8_t cv_out[BLAKE3_OUT_LEN];
  hash_chunk(self->buf, self->buf_len, self->key,
             self->chunk_counter, 0, false, cv_out);

  // Merge cv_out with the stack from right to left.
  uint8_t parent_block[BLAKE3_BLOCK_LEN];
  int i = (int)self->cv_stack_len - 1;

  // Start: rightmost parent = stack[i] || cv_out
  memcpy(parent_block,
         &self->cv_stack[(size_t)i * BLAKE3_OUT_LEN], BLAKE3_OUT_LEN);
  memcpy(parent_block + BLAKE3_OUT_LEN, cv_out, BLAKE3_OUT_LEN);

  // Walk up.  The last merge gets ROOT flag.
  while (i > 0) {
    uint32_t cv[8];
    memcpy(cv, self->key, BLAKE3_KEY_LEN);
    blake3_compress_in_place(cv, parent_block, BLAKE3_BLOCK_LEN, 0, PARENT);
    i--;
    memcpy(parent_block,
           &self->cv_stack[(size_t)i * BLAKE3_OUT_LEN], BLAKE3_OUT_LEN);
    memcpy(parent_block + BLAKE3_OUT_LEN, cv, BLAKE3_OUT_LEN);
  }

  // Final root compression.
  uint32_t cv[8];
  memcpy(cv, self->key, BLAKE3_KEY_LEN);
  blake3_compress_in_place(cv, parent_block, BLAKE3_BLOCK_LEN, 0,
                           PARENT | ROOT);
  memcpy(output, cv, BLAKE3_OUT_LEN);
}
