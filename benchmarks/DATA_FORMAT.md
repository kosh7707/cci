# SUPERCOP Benchmark Data Format

This document describes the format of the `data` file produced by the
[SUPERCOP](https://bench.cr.yp.to/supercop.html) benchmarking framework
(version 20260217).  The file is a plain-text, space-delimited log where each
line is a self-contained record.  Understanding this format is essential for
anyone who wants to parse or reproduce the measurements independently.

## Common Header (fields 1-7)

Every line follows the same 7-field prefix:

```
<version> <hostname> <abi> <date> <operation> <primitive/security> <record_type> [payload...]
```

| Field | Index | Example | Description |
|-------|-------|---------|-------------|
| version | 1 | `20260217` | SUPERCOP release identifier |
| hostname | 2 | `desktopm6o2vdi` | Machine name (auto-generated) |
| abi | 3 | `amd64` | Target ABI |
| date | 4 | `20260226` | Date the measurement was taken |
| operation | 5 | `crypto_aead` | SUPERCOP operation category |
| primitive/security | 6 | `aes128gcm/timingleaks` | Primitive name and security model, separated by `/` |
| record_type | 7 | `encrypt_cycles` | Type of record (see below) |

The **primitive name** is everything before the `/` in field 6
(e.g., `aes128cciblake3` from `aes128cciblake3/timingleaks`).

## Record Types

### Measurement records

These contain the actual cycle-count data.  Three measurement types exist:

- `encrypt_cycles` -- encryption + tag generation
- `decrypt_cycles` -- decryption + tag verification
- `forgery_decrypt_cycles` -- decryption of an intentionally corrupted ciphertext (must reject)

**Format:**

```
<header...> encrypt_cycles <encoded_size> <stq2> <deltas>
```

| Field | Description |
|-------|-------------|
| `encoded_size` | `1000000 * adlen + mlen`.  For example, `2048002048` means adlen=2048, mlen=2048.  A value of `1` means adlen=0, mlen=1. |
| `stq2` | Stabilized quartile 2 (robust median) over 7 independent timings.  This is the primary cycle count. |
| `deltas` | Signed offsets of the 7 individual timings relative to `stq2`, encoded as `+d1-d2+d3...` (no spaces). |

**Example:**

```
20260217 desktopm6o2vdi amd64 20260226 crypto_aead aes128gcm/timingleaks encrypt_cycles 1 1805 +3316+75-3-4+3-6-12
```

This means: AES-128-GCM, encrypting 1 byte of plaintext with 0 bytes of AD,
median cycle count = 1805.  The seven individual measurements were
1805+3316=5121, 1805+75=1880, 1805-3=1802, etc.

**Multiple records per (primitive, size) pair** are normal.  SUPERCOP tries
multiple compiler flag combinations; each produces a separate measurement line.
The best (lowest stq2) across compilers represents the primitive's performance.

### Metadata records

| record_type | Payload | Description |
|-------------|---------|-------------|
| `compiler` | `<flags> <version>` | Compiler flags selected as optimal for measurement |
| `keybytes` | `<integer>` | Key size in bytes |
| `npubbytes` | `<integer>` | Public nonce size in bytes |
| `abytes` | `<integer>` | Authentication tag size in bytes |
| `implementation` | `<path> -` | Which implementation directory was selected |
| `cpucycles_persecond` | `<integer>` | CPU frequency in Hz (e.g., `3417599000`) |
| `cpucycles_implementation` | `<string>` | Cycle-counting method (e.g., `amd64-tsc`) |
| `cpuid` | `<string>` | CPUID signature |

**Example:**

```
20260217 desktopm6o2vdi amd64 20260226 crypto_aead aes128gcm/timingleaks compiler gcc_-march=native_-mtune=native_-O2_-fwrapv_-fPIC_-fPIE_-gdwarf-4_-Wall 13.3.0
20260217 desktopm6o2vdi amd64 20260226 crypto_aead aes128gcm/timingleaks keybytes 16
20260217 desktopm6o2vdi amd64 20260226 crypto_aead aes128gcm/timingleaks cpucycles_persecond 3417599000
```

### Build/test records

| record_type | Payload | Description |
|-------------|---------|-------------|
| `try` | `<checksum> unknown <median> <sum> <hz> <impl> <compiler> <deltas>` | Correctness-test result (try.c).  The checksum is a hash of encrypt/decrypt outputs; `unknown` means no reference to compare against.  Includes wall-clock timing data. |
| `tryfails` | `<message>` | Correctness test failure (e.g., decrypt produced wrong output) |
| `fromcompiler` | `<impl> <compiler> <srcfile> <message>` | Compiler diagnostic (warnings, errors) |
| `objsize` | `<impl> <compiler> <text> <data> <bss> <objname>` | Object file section sizes |
| `namespace` | `<impl> <compiler> <objname> <symbol> <type>` | Exported symbols (namespace check) |

## Computing Cycles per Byte (CPB)

To compute CPB from the raw data:

1. **Filter** records by `record_type` (e.g., `encrypt_cycles`) and desired `adlen` (typically 0)
2. **Decode** the encoded size: `adlen = encoded_size // 1000000`, `mlen = encoded_size % 1000000`
3. **Group** by `(primitive, mlen)` across all compiler variants
4. **Select** the minimum `stq2` per group (best compiler)
5. **Divide** `stq2 / mlen` to get CPB
6. For mlen=1, report raw cycles (overhead) rather than CPB

The included `parse.py` script automates this process.

## Using parse.py

```bash
# Generate summary + CPB tables
python3 parse.py data

# Write results to a file
python3 parse.py data --txt result.txt

# Export all measurements as CSV
python3 parse.py data --csv

# Include build/test errors in output
python3 parse.py data --errors
```

## Message Sizes in the Benchmark

SUPERCOP's `measure-anything.c` generates measurements for a fixed set of
`(adlen, mlen)` combinations.  With the default configuration, each primitive
is tested at 6900 measurement points covering:

- **mlen**: 1 through 2048 (every integer), plus selected larger sizes
- **adlen**: 0, and selected values from 1 through 2048
- **Combined**: various `(adlen, mlen)` pairs for cross-size behavior

The `result.txt` file summarizes these at representative sizes (0, 16, 64, 128,
256, 512, 1024, 1536, 2048 bytes) with adlen=0.
