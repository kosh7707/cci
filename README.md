# CCI: Counter Composite Integrity

SUPERCOP benchmark implementations and measurement results for the CCI authenticated encryption scheme, as described in:

> **CCI: An AEAD with Modular Hash-Based Authentication**
> *(IEEE Access, 2026)* -- [DOI: TBD]

## Overview

CCI is an authenticated encryption with associated data (AEAD) scheme that combines AES in CTR mode with a cryptographic hash function in a Mac-then-Encrypt paradigm.  The hash is computed over serialized plaintext, associated data, and a secret nonce, then encrypted alongside the plaintext.

This repository contains the exact source code and raw benchmark data used in the paper.  All implementations conform to the [SUPERCOP](https://bench.cr.yp.to/supercop.html) `crypto_aead` API (eBAEAD).

## Primitives

16 AEAD primitives are included: 8 CCI variants and 8 standard baselines.  Each primitive has an optimized implementation (using OpenSSL/AES-NI) and a portable reference implementation in Portable-C.

| Primitive | Key (bytes) | Nonce (bytes) | Tag (bytes) | Type |
|-----------|-------------|---------------|-------------|------|
| `aes128cciblake3` | 16 | 28 | 16 | CCI with BLAKE3 (AVX2) |
| `aes128ccisha256` | 16 | 28 | 16 | CCI with SHA-256 (SHA-NI) |
| `aes256cciblake3` | 32 | 28 | 16 | CCI with BLAKE3 (AVX2) |
| `aes256ccisha256` | 32 | 28 | 16 | CCI with SHA-256 (SHA-NI) |
| `aes128gcm` | 16 | 12 | 16 | AES-GCM baseline |
| `aes256gcm` | 32 | 12 | 16 | AES-GCM baseline |
| `aes128ccm` | 16 | 12 | 16 | AES-CCM baseline |
| `chacha20poly1305` | 32 | 12 | 16 | ChaCha20-Poly1305 baseline |

Each has a corresponding `*ref` variant (e.g., `aes128cciblake3ref`) that uses only portable C code with no hardware acceleration.

CCI variants use a 28-byte nonce: the first 12 bytes are the public nonce (n1) for CTR mode, and the last 16 bytes are the secret nonce (n2) that is hashed into the authentication tag.

## Repository Structure

```
.
├── README.md
├── crypto_aead/
│   ├── _shared/                    # Shared source files
│   │   ├── cci_core.inc            # CCI encrypt/decrypt (OpenSSL)
│   │   ├── cci_core_ref.inc        # CCI encrypt/decrypt (portable C)
│   │   ├── aes_portable.inc        # Portable AES-128/256
│   │   ├── sha256_portable.inc     # Portable SHA-256
│   │   ├── blake3_common/          # BLAKE3 core (blake3.c, blake3.h)
│   │   ├── blake3_avx2/            # BLAKE3 AVX2+SSE4.1 dispatch
│   │   └── blake3_portable/        # BLAKE3 portable-only dispatch
│   ├── aes128cciblake3/openssl/    # CCI-128-BLAKE3 (optimized)
│   ├── aes128cciblake3ref/ref/     # CCI-128-BLAKE3 (reference)
│   ├── ...                         # (16 primitives total)
│   └── chacha20poly1305ref/ref/
└── benchmarks/
    ├── reproduce.sh                # Runs the whole benchmark with SUPERCOP and writes data + result.txt
    ├── data                        # Raw SUPERCOP measurement data (three sections, see below)
    ├── result.txt                  # Parsed benchmark summary
    ├── parse.py                    # Benchmark data parser
    └── DATA_FORMAT.md              # Guide to reading the raw data
```

## Reproducing the Benchmarks

The implementations are built and timed by SUPERCOP's own orchestration. One script runs the whole experiment:

1. Obtain SUPERCOP (version 20260217 or later) from
   https://bench.cr.yp.to/supercop.html and unpack it.

2. Run:
   ```bash
   sh benchmarks/reproduce.sh /path/to/supercop
   ```

The script copies the 16 primitive directories into `<supercop>/crypto_aead/`, sets `TIMINGS` to 7 in `<supercop>/crypto_aead/measure.c` (the value used for the paper), runs `./do-part crypto_aead <primitive>` for each primitive in turn, and appends SUPERCOP's output to `benchmarks/data`.  It then takes the four AES-128 OpenSSL-backed binaries that SUPERCOP selected and runs them again with OpenSSL's instruction-set support restricted (see below), appending those records below separator lines, and finally writes
`benchmarks/result.txt` with `parse.py`.  On a fresh SUPERCOP tree the script first runs `./do-part init`, which builds SUPERCOP's support libraries and can take a long time; the measurements themselves take a few minutes.

**Note:** OpenSSL implementations (`openssl/` subdirectories) require OpenSSL development headers and libraries to be installed.  Reference implementations (`ref/` subdirectories) have no external dependencies.

## Benchmark Results

**Environment:**

| Item | Value |
|------|-------|
| CPU | Intel Core i7-14700K (3.40 GHz base) |
| Host OS | Windows 11 Education 24H2 |
| Guest OS | Ubuntu 24.04.4 LTS (WSL2, kernel 6.6.87.2) |
| OpenSSL | 3.0.13 |
| Compiler | gcc 13.3.0 |
| Cycle counter | RDTSC (amd64-tsc) |
| SUPERCOP | 20260217 |

### Encrypt -- Cycles per Byte (adlen=0)

| Primitive | 0\* | 64 | 256 | 1024 | 2048 |
|-----------|----:|----:|-----:|------:|------:|
| AES-128-GCM | 1,819 | 26.9 | 7.0 | 2.0 | 1.2 |
| AES-256-GCM | 1,808 | 27.4 | 7.0 | 2.1 | 1.2 |
| AES-128-CCM | 1,612 | 22.9 | 6.6 | 2.6 | 2.0 |
| ChaCha20-Poly1305 | 2,144 | 30.9 | 9.1 | 2.9 | 2.0 |
| CCI-128-SHA256 | 1,467 | 32.3 | 9.2 | 3.4 | 2.5 |
| CCI-256-SHA256 | 1,566 | 38.3 | 9.1 | 3.6 | 2.7 |
| CCI-128-BLAKE3 | 688 | 23.6 | 7.7 | 3.9 | 3.2 |
| CCI-256-BLAKE3 | 887 | 30.2 | 7.7 | 4.0 | 3.3 |

\* Column "0" shows raw cycle count for a 1-byte message (overhead), not CPB.

Cycle counts are SUPERCOP's *stq2* metric (stabilized second quartile over seven independent timings).  For each primitive SUPERCOP measures only the
compiler variant that scored best in its `try` stage (the `compiler` record
in the data file names it); every measurement point is timed in three rounds
(`LOOPS=3`), and the table reports the minimum across those three rounds.

### Instruction-set masking (same binaries, OpenSSL restricted)

The table above is measured with every instruction-set extension of the host
available.  In the same run, the four AES-128 OpenSSL-backed binaries that
SUPERCOP selected are executed again with OpenSSL's CPU-capability vector
masked through the `OPENSSL_ia32cap` environment variable, which libcrypto
reads once at load time.  This shows how the relative cost of the AES-based
options changes when AES-NI stays available but PCLMULQDQ (used by GHASH)
does not, and how the choice of hash inside CCI changes when the SHA
extensions are also unavailable.

| `OPENSSL_ia32cap` | Effect |
|-------------------|--------|
| `~0x200000000:~0x0` | bit 33 (PCLMULQDQ) cleared; AES-NI, AVX2 and SHA extensions kept |
| `~0x200000000:~0x20000000` | additionally bit 64+29 (SHA extensions) cleared |

The second, colon-separated value must be written explicitly: if it is
omitted, OpenSSL zeroes every CPUID(7) bit (AVX2, SHA, and others).  Masking
changes only OpenSSL's internal code-path selection; BLAKE3, which is compiled
into the primitive, is unaffected.  For messages up to 64 bytes the CCI
implementation uses OpenSSL's low-level table-based AES, so those cells do not
isolate authentication acceleration.  The masks emulate missing instruction
support on this host; they do not reproduce any specific CPU.

Encrypt, cycles per byte, `OPENSSL_ia32cap=~0x200000000:~0x0`:

| Primitive | 0\* | 64 | 256 | 1024 | 2048 |
|-----------|----:|----:|-----:|------:|------:|
| AES-128-GCM | 1,886 | 35.4 | 12.2 | 6.1 | 5.1 |
| AES-128-CCM | 1,580 | 30.8 | 7.9 | 2.8 | 2.2 |
| CCI-128-SHA256 | 1,372 | 35.2 | 9.3 | 3.8 | 2.5 |
| CCI-128-BLAKE3 | 707 | 23.5 | 8.7 | 4.1 | 3.3 |

Encrypt, cycles per byte, `OPENSSL_ia32cap=~0x200000000:~0x20000000`:

| Primitive | 0\* | 64 | 256 | 1024 | 2048 |
|-----------|----:|----:|-----:|------:|------:|
| AES-128-GCM | 1,869 | 34.1 | 12.2 | 6.2 | 5.0 |
| AES-128-CCM | 1,602 | 25.3 | 7.5 | 2.9 | 2.1 |
| CCI-128-SHA256 | 1,661 | 39.9 | 13.7 | 7.1 | 6.1 |
| CCI-128-BLAKE3 | 697 | 23.8 | 8.5 | 4.2 | 3.3 |

Full results, including reference implementations, decrypt measurements and
all message sizes for every section, are in
[`benchmarks/result.txt`](benchmarks/result.txt).

## Parsing Raw Data

The raw SUPERCOP `data` file contains about 221,000 lines of measurement,
compiler, and test records in three sections: the default run of all 16
primitives, then, below a separator line of the form
`==================== OPENSSL_ia32cap=... ====================`, the records
of each masked run.  `parse.py` prints one set of tables per section.  See
[`benchmarks/DATA_FORMAT.md`](benchmarks/DATA_FORMAT.md) for a detailed
description of the file format.

```bash
cd benchmarks

# Summary tables (terminal)
python3 parse.py data

# Write to file
python3 parse.py data --txt result.txt

# CSV export for further analysis
python3 parse.py data --csv > measurements.csv
```

## License

The CCI implementation code is provided under the public domain
(or CC0, at your option).  The BLAKE3 source files retain their
original Apache-2.0 / CC0 dual license.

## Citation

If you use this code or data in your research, please cite:

```bibtex
@article{cci2026,
  title   = {CCI: An AEAD with Modular Hash-Based Authentication},
  author  = {Sehwa Ko and Kyeongmin Lee and Junyoung Son},
  journal = {IEEE Access},
  year    = {2026},
  doi     = {TBD}
}
```

## Acknowledgement

The implementations and the benchmark tooling in this repository were
developed together with Claude (Anthropic), used through Claude Code.
