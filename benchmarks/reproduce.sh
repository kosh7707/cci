#!/bin/sh
# Reproduce every measurement in benchmarks/data with SUPERCOP.
#
#   sh benchmarks/reproduce.sh /path/to/supercop
#
# Requirements: a SUPERCOP tree (https://bench.cr.yp.to/supercop.html, 20260217 or later),
# gcc, OpenSSL development headers and library (the primitives link libcrypto dynamically),
# python3 for result.txt.  On a fresh SUPERCOP tree the first run executes ./do-part init,
# which builds SUPERCOP's support libraries and can take a long time; everything else takes
# a few minutes.
#
# What it does:
#  1. copies the 16 primitive directories of this repository into <supercop>/crypto_aead/
#  2. sets TIMINGS to 7 in <supercop>/crypto_aead/measure.c (the value used for the paper)
#  3. runs ./do-part crypto_aead <primitive> for each primitive, one at a time, and appends
#     SUPERCOP's data output to benchmarks/data; the measure binary SUPERCOP selected
#     (best compiler flags by its try score) is kept for step 4
#  4. appends, below a "==== OPENSSL_ia32cap=... ====" separator line, the output of the kept
#     AES-128 OpenSSL-backed binaries run again with OpenSSL's CPU-capability vector masked
#     (OPENSSL_ia32cap is read once when libcrypto loads, so it is set per process):
#        ~0x200000000:~0x0          bit 33 (PCLMULQDQ) cleared: GHASH loses its instruction support
#        ~0x200000000:~0x20000000   additionally bit 64+29 (SHA extensions) cleared
#     The second, colon-separated value must be written: omitting it clears every CPUID(7) bit.
#  5. writes benchmarks/result.txt with parse.py (one table per section)
set -e
SUPERCOP=${1:?usage: reproduce.sh /path/to/supercop}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$HERE")
OUT=$HERE/data
MASKED="aes128gcm aes128ccm aes128ccisha256 aes128cciblake3"
MASKS="~0x200000000:~0x0 ~0x200000000:~0x20000000"

[ "$(uname -m)" = x86_64 ] || { echo "this benchmark is x86-64 only (OPENSSL_ia32cap masking, amd64 ABI)" >&2; exit 1; }
[ -f "$SUPERCOP/version" ] && [ -x "$SUPERCOP/do-part" ] || { echo "$SUPERCOP is not a SUPERCOP root (no version file / do-part)" >&2; exit 1; }
cd "$SUPERCOP"
HOST=$(hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]' | tr '[A-Z]' '[a-z]')
BENCH=bench/$HOST
VERSION=$(cat version)
KEEP=$(mktemp -d)

sed -i 's/^#define TIMINGS 16$/#define TIMINGS 7/' crypto_aead/measure.c
grep -q '^#define TIMINGS 7$' crypto_aead/measure.c || { echo "could not set TIMINGS to 7 in crypto_aead/measure.c" >&2; exit 1; }
PRIMS=$(ls "$REPO/crypto_aead" | grep -v '^_shared$')
for p in $PRIMS; do
  rm -rf "crypto_aead/$p"
  cp -r "$REPO/crypto_aead/$p" crypto_aead/
done

[ -x "$BENCH/bin/okc-amd64" ] || ./do-part init > "$KEEP/init.log" 2>&1

: > "$OUT"
for p in $PRIMS; do
  echo "=== $p"
  ./do-part crypto_aead "$p" > "$KEEP/$p.log" 2>&1
  cat "$BENCH/data" >> "$OUT"
  [ -x "$BENCH/work/timingleaks/best/measure" ] || { echo "$p: SUPERCOP produced no measure binary, see $KEEP/$p.log" >&2; exit 1; }
  cp -p "$BENCH/work/timingleaks/best/measure" "$KEEP/$p.measure"
done

DATE=$(date +%Y%m%d)
for mask in $MASKS; do
  echo "=== OPENSSL_ia32cap=$mask"
  echo "==================== OPENSSL_ia32cap=$mask ====================" >> "$OUT"
  for p in $MASKED; do
    OPENSSL_ia32cap="$mask" "$KEEP/$p.measure" > "$KEEP/run.out"
    sed "s|^|$VERSION $HOST amd64 $DATE crypto_aead $p/timingleaks |" "$KEEP/run.out" >> "$OUT"
  done
done

if command -v python3 > /dev/null; then
  python3 "$HERE/parse.py" "$OUT" --txt "$HERE/result.txt"
else
  echo "python3 not found: data written, result.txt not regenerated" >&2
fi
echo "data: $OUT"
echo "logs and kept binaries: $KEEP"
