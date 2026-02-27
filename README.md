# CCI: Counter Composite Integrity

SUPERCOP benchmark implementations and measurement results for the CCI
authenticated encryption scheme, as described in:

> **CCI: An AEAD with Modular Hash-Based Authentication**
> *(IEEE Access, 2026)* -- [DOI: TBD]

## Overview

CCI is an authenticated encryption with associated data (AEAD) scheme that
combines AES in CTR mode with a cryptographic hash function in a
Mac-then-Encrypt paradigm.  The hash is computed over serialized plaintext,
associated data, and a secret nonce, then encrypted alongside the plaintext.

This repository contains the exact source code and raw benchmark data used in
the paper.  All implementations conform to the
[SUPERCOP](https://bench.cr.yp.to/supercop.html) `crypto_aead` API (eBAEAD).

## Primitives

Sixteen AEAD primitives are included: eight CCI variants and eight standard
baselines.  Each primitive has an optimized implementation (using OpenSSL/AES-NI)
and a portable reference implementation in pure C.

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

Each has a corresponding `*ref` variant (e.g., `aes128cciblake3ref`) that uses
only portable C code with no hardware acceleration.

CCI variants use a 28-byte nonce: the first 12 bytes are the public nonce (n1)
for CTR mode, and the last 16 bytes are the secret nonce (n2) that is hashed
into the authentication tag.

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
    ├── data                        # Raw SUPERCOP measurement data
    ├── result.txt                  # Parsed benchmark summary
    ├── parse.py                    # Benchmark data parser
    └── DATA_FORMAT.md              # Guide to reading the raw data
```

## Building with SUPERCOP

These implementations are designed to be built by SUPERCOP's automated
orchestration.  To reproduce the benchmarks:

1. Obtain SUPERCOP (version 20260217 or later) from
   https://bench.cr.yp.to/supercop.html

2. Copy each primitive directory into SUPERCOP's `crypto_aead/` tree:
   ```bash
   cp -r crypto_aead/aes128cciblake3 /path/to/supercop/crypto_aead/
   # repeat for all 16 primitives and _shared
   ```

3. Run the benchmark:
   ```bash
   cd /path/to/supercop
   ./do-part crypto_aead    # benchmarks all crypto_aead primitives
   ```

4. Parse the results:
   ```bash
   python3 benchmarks/parse.py /path/to/supercop/bench/*/data --txt results.txt
   ```

**Note:** OpenSSL implementations (`openssl/` subdirectories) require OpenSSL
development headers and libraries to be installed.  Reference implementations
(`ref/` subdirectories) have no external dependencies.

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
| AES-128-GCM | 1,873 | 28.0 | 7.3 | 2.1 | 1.2 |
| AES-256-GCM | 1,867 | 28.4 | 7.4 | 2.2 | 1.3 |
| AES-128-CCM | 1,657 | 24.9 | 7.0 | 2.7 | 2.0 |
| ChaCha20-Poly1305 | 2,215 | 32.7 | 9.6 | 3.0 | 2.2 |
| CCI-128-SHA256 | 1,455 | 32.4 | 9.4 | 3.5 | 2.7 |
| CCI-256-SHA256 | 1,645 | 39.1 | 9.4 | 3.6 | 2.6 |
| CCI-128-BLAKE3 | 709 | 23.5 | 7.7 | 4.0 | 3.3 |
| CCI-256-BLAKE3 | 898 | 30.0 | 7.9 | 4.0 | 3.3 |

\* Column "0" shows raw cycle count for a 1-byte message (overhead), not CPB.

Full results including reference implementations and decrypt measurements are
in [`benchmarks/result.txt`](benchmarks/result.txt).

Cycle counts are SUPERCOP's *stq2* metric (stabilized second quartile over
seven independent timings); the minimum across compiler variants is reported.

## Parsing Raw Data

The raw SUPERCOP `data` file contains 147,000+ lines of measurement,
compiler, and test records.  See [`benchmarks/DATA_FORMAT.md`](benchmarks/DATA_FORMAT.md)
for a detailed description of the file format.

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
  author  = {TBD},
  journal = {IEEE Access},
  year    = {2026},
  doi     = {TBD}
}
```
