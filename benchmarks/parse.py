#!/usr/bin/env python3
"""
SUPERCOP benchmark data parser for CCI paper.

Parses the SUPERCOP 'data' file (measure-anything.c, version 20260214+)
and produces CPB (cycles per byte) comparison tables.

Data format (space-delimited):
  version hostname abi date operation primitive/security record_type payload...

Measurement record:
  ... encrypt_cycles <1000000*adlen+mlen> <stq2> <+d1-d2+d3...>
  stq2 = stabilized quartile 2 (robust median over 7 timings)

Usage:
  python3 parse.py <data_file>              # summary + table
  python3 parse.py <data_file> --csv        # CSV export
  python3 parse.py <data_file> --errors     # show build/test failures
"""

import sys
import re
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field


# ── Data structures ──────────────────────────────────────────────

@dataclass
class Measurement:
    primitive: str
    measure_type: str  # encrypt_cycles, decrypt_cycles, forgery_decrypt_cycles
    adlen: int
    mlen: int
    stq2: int          # robust median cycles
    deltas: list[int] = field(default_factory=list)


@dataclass
class PrimitiveInfo:
    implementation: str = ""
    keybytes: int = 0
    npubbytes: int = 0
    abytes: int = 0
    compiler: str = ""
    cpucycles_persecond: int = 0


# ── Parsing ──────────────────────────────────────────────────────

def parse_deltas(s: str) -> list[int]:
    """Parse '+1234+567-89' into [1234, 567, -89]."""
    return [int(x) for x in re.findall(r'[+-]\d+', s)]


def parse_data(filepath: str):
    measurements: list[Measurement] = []
    info: dict[str, PrimitiveInfo] = defaultdict(PrimitiveInfo)
    errors: dict[str, list[str]] = defaultdict(list)

    measure_types = {'encrypt_cycles', 'decrypt_cycles', 'forgery_decrypt_cycles'}
    meta_keys = {'keybytes', 'npubbytes', 'abytes', 'nsecbytes',
                 'implementation', 'compiler', 'cpucycles_persecond',
                 'cpucycles_implementation', 'cpuid'}

    with open(filepath) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 7:
                continue

            prim_sec = parts[5]  # e.g. "aes128ccmv1/timingleaks"
            slash = prim_sec.find('/')
            primitive = prim_sec[:slash] if slash >= 0 else prim_sec
            record_type = parts[6]

            if record_type in measure_types and len(parts) >= 9:
                encoded_size = int(parts[7])
                stq2 = int(parts[8])
                deltas = parse_deltas(parts[9]) if len(parts) > 9 else []
                measurements.append(Measurement(
                    primitive=primitive,
                    measure_type=record_type,
                    adlen=encoded_size // 1_000_000,
                    mlen=encoded_size % 1_000_000,
                    stq2=stq2,
                    deltas=deltas,
                ))

            elif record_type in meta_keys and len(parts) >= 8:
                pi = info[primitive]
                val = ' '.join(parts[7:])
                if record_type == 'keybytes':
                    pi.keybytes = int(val)
                elif record_type == 'npubbytes':
                    pi.npubbytes = int(val)
                elif record_type == 'abytes':
                    pi.abytes = int(val)
                elif record_type == 'implementation':
                    pi.implementation = val.rstrip(' -')
                elif record_type == 'compiler':
                    pi.compiler = val
                elif record_type == 'cpucycles_persecond':
                    pi.cpucycles_persecond = int(val)

            elif record_type == 'tryfails':
                msg = ' '.join(parts[7:])
                errors[primitive].append(f"tryfails: {msg}")

            elif record_type == 'fromcompiler' and 'error' in line.lower():
                msg = ' '.join(parts[9:]) if len(parts) > 9 else ''
                if msg and msg not in [e.split(': ', 1)[-1] for e in errors[primitive]]:
                    errors[primitive].append(f"compile: {msg}")

    return measurements, info, errors


# ── Analysis ─────────────────────────────────────────────────────

def group_measurements(measurements: list[Measurement]):
    """Group by (primitive, measure_type, adlen, mlen), take min stq2."""
    groups = defaultdict(list)
    for m in measurements:
        key = (m.primitive, m.measure_type, m.adlen, m.mlen)
        groups[key].append(m.stq2)

    result = {}
    for key, values in groups.items():
        result[key] = min(values)  # best (least-noisy) run
    return result


def compute_cpb_table(grouped, measure_type='encrypt_cycles',
                      target_sizes=None):
    """Build {primitive: {mlen: cpb}} for adlen=0 rows."""
    if target_sizes is None:
        target_sizes = [0, 16, 32, 64, 128, 256, 512, 1024, 2048]

    # collect all primitives and available mlens for adlen=0
    prim_data = defaultdict(dict)
    for (prim, mtype, adlen, mlen), cycles in grouped.items():
        if mtype != measure_type or adlen != 0:
            continue
        prim_data[prim][mlen] = cycles

    # for mlen=0, use mlen=1 as "overhead" (mlen never actually is 0)
    table = {}
    for prim, size_map in prim_data.items():
        row = {}
        for sz in target_sizes:
            if sz == 0:
                # overhead: use smallest available mlen
                c = size_map.get(1, size_map.get(2))
                row[sz] = c  # raw cycles, not CPB
            elif sz in size_map:
                row[sz] = size_map[sz] / sz  # CPB
            else:
                # find nearest available size
                nearest = min(size_map.keys(), key=lambda k: abs(k - sz),
                              default=None)
                if nearest and nearest > 0:
                    row[sz] = size_map[nearest] / nearest
                else:
                    row[sz] = None
        table[prim] = row

    return table


# ── Display helpers ──────────────────────────────────────────────

# friendly display names
DISPLAY_NAMES = {
    'aes128gcm':           'AES-128-GCM',
    'aes128gcmref':        'AES-128-GCM-ref',
    'aes256gcm':           'AES-256-GCM',
    'aes256gcmref':        'AES-256-GCM-ref',
    'aes128ccm':           'AES-128-CCM',
    'aes128ccmref':        'AES-128-CCM-ref',
    'chacha20poly1305':    'ChaCha20-Poly1305',
    'chacha20poly1305ref': 'ChaCha20-Poly1305-ref',
    'aes128ccisha256':     'CCI-128-SHA256',
    'aes128ccisha256ref':  'CCI-128-SHA256-ref',
    'aes256ccisha256':     'CCI-256-SHA256',
    'aes256ccisha256ref':  'CCI-256-SHA256-ref',
    'aes128cciblake3':     'CCI-128-BLAKE3',
    'aes128cciblake3ref':  'CCI-128-BLAKE3-ref',
    'aes256cciblake3':     'CCI-256-BLAKE3',
    'aes256cciblake3ref':  'CCI-256-BLAKE3-ref',
}

def display_name(prim: str) -> str:
    return DISPLAY_NAMES.get(prim, prim)


def fmt_cpb(val) -> str:
    if val is None:
        return '—'
    if isinstance(val, int) or (isinstance(val, float) and val > 1000):
        return f'{val:,.0f}'
    return f'{val:.1f}'


# ── Output: environment info (hardcoded) ───────────────────────

EVAL_ENV = {
    'CPU':           'Intel(R) Core(TM) i7-14700K (base 3.40 GHz)',
    'Memory':        '64 GB DDR5',
    'Host OS':       'Windows 11 Education 24H2 (build 26200, 64-bit)',
    'Guest OS':      'Ubuntu 24.04.4 LTS (WSL2, kernel 6.6.87.2-microsoft-standard-WSL2)',
    'OpenSSL':       '3.0.13 (30 Jan 2024)',
    'SUPERCOP':      '20260217',
    'Compiler':      'gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0',
    'Cycle counter': 'amd64-tsc (RDTSC)',
}


def print_eval_env():
    print("=" * 60)
    print("Evaluation Environment")
    print("=" * 60)
    key_w = max(len(k) for k in EVAL_ENV)
    for k, v in EVAL_ENV.items():
        print(f"  {k:<{key_w}}  {v}")
    print()


# ── Output: summary ─────────────────────────────────────────────

def print_summary(measurements, info, errors):
    measured_prims = sorted({m.primitive for m in measurements})
    all_prims = sorted(set(list(info.keys()) + list(errors.keys()) + measured_prims))

    print("=" * 60)
    print("SUPERCOP Benchmark Summary")
    print("=" * 60)

    # environment info (from first primitive with data)
    for prim in measured_prims:
        pi = info.get(prim)
        if pi and pi.cpucycles_persecond:
            print(f"  CPU freq:   {pi.cpucycles_persecond / 1e9:.2f} GHz")
            break

    # collect unique compilers across all primitives
    compilers = {}
    for prim in measured_prims:
        pi = info.get(prim)
        if pi and pi.compiler:
            compilers[prim] = pi.compiler

    unique_compilers = sorted(set(compilers.values()))
    if len(unique_compilers) == 1:
        print(f"  Compiler:   {unique_compilers[0]}")
    elif unique_compilers:
        print(f"  Compilers:  {len(unique_compilers)} variants (gcc 13.3.0)")

    print()
    name_w = max((len(display_name(p)) for p in all_prims), default=28)
    name_w = max(name_w, 9)  # at least "Primitive"
    print(f"  {'Primitive':<{name_w}}  {'Compiler Opt':<14} {'Status':<12} {'Points':>8}")
    print(f"  {'—' * name_w}  {'—' * 14} {'—' * 12} {'—' * 8}")

    for prim in all_prims:
        name = display_name(prim)
        n_enc = sum(1 for m in measurements
                    if m.primitive == prim and m.measure_type == 'encrypt_cycles')
        # extract optimization flag from compiler string
        comp = compilers.get(prim, '')
        opt_flag = ''
        if comp:
            for part in comp.split('_'):
                if part.startswith('-O'):
                    opt_flag = part
                    break
        if n_enc > 0:
            status = f'OK ({n_enc})'
        elif prim in errors:
            status = 'FAIL'
        else:
            status = 'no data'
        print(f"  {name:<{name_w}}  {opt_flag:<14} {status:<12} {n_enc:>8}")

    if errors:
        print()
        failed = [p for p in all_prims if p in errors and
                  not any(m.primitive == p for m in measurements)]
        if failed:
            print(f"  Failed: {len(failed)} primitive(s)")


def print_errors(errors):
    print()
    print("=" * 60)
    print("Build / Test Failures")
    print("=" * 60)
    for prim in sorted(errors.keys()):
        name = display_name(prim)
        print(f"\n  {name}:")
        seen = set()
        for err in errors[prim]:
            short = err[:120]
            if short not in seen:
                seen.add(short)
                print(f"    {short}")


# ── Output: CPB table (markdown) ────────────────────────────────

def print_cpb_table(grouped, measure_type='encrypt_cycles'):
    sizes = [0, 16, 32, 64, 128, 256, 512, 1024, 2048]
    table = compute_cpb_table(grouped, measure_type, sizes)

    if not table:
        print("  (no measurement data)")
        return

    type_label = measure_type.replace('_cycles', '').replace('_', ' ').title()
    print()
    print(f"### {type_label} — Cycles per Byte (adlen=0)")
    print()

    # header
    hdr_sizes = ['0*'] + [str(s) for s in sizes[1:]]
    name_w = max(len(display_name(p)) for p in table) + 2
    print(f"| {'Primitive':<{name_w}} |" +
          ''.join(f' {s:>8} |' for s in hdr_sizes))
    print(f"|{'—' * (name_w + 1)}|" +
          ''.join(f"{'—' * 10}|" for _ in sizes))

    # sort: non-ref first, then ref; within group alphabetical
    def sort_key(p):
        is_ref = 'ref' in p
        return (is_ref, display_name(p))

    for prim in sorted(table.keys(), key=sort_key):
        row = table[prim]
        name = display_name(prim)
        cells = []
        for sz in sizes:
            val = row.get(sz)
            cells.append(fmt_cpb(val))
        print(f"| {name:<{name_w}} |" +
              ''.join(f' {c:>8} |' for c in cells))

    print()
    print("_* 0 = 1-byte message overhead (raw cycles, not CPB)_")


# ── Output: CSV ──────────────────────────────────────────────────

def print_csv(measurements):
    import csv as csvmod
    import io

    out = io.StringIO()
    writer = csvmod.writer(out)
    writer.writerow(['primitive', 'display_name', 'type', 'adlen', 'mlen',
                     'stq2_cycles', 'delta_min', 'delta_max'])

    for m in sorted(measurements, key=lambda x: (x.primitive, x.measure_type,
                                                   x.adlen, x.mlen)):
        dmin = min(m.deltas) if m.deltas else 0
        dmax = max(m.deltas) if m.deltas else 0
        writer.writerow([m.primitive, display_name(m.primitive),
                         m.measure_type, m.adlen, m.mlen,
                         m.stq2, dmin, dmax])

    print(out.getvalue(), end='')


# ── Main ─────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <data_file> [--csv|--errors|--txt <outfile>]")
        sys.exit(1)

    data_path = Path(sys.argv[1])
    if not data_path.exists():
        print(f"Error: {data_path} not found", file=sys.stderr)
        sys.exit(1)

    flags = list(sys.argv[2:])

    # --txt <outfile>: redirect all output to a text file
    out_file = None
    if '--txt' in flags:
        idx = flags.index('--txt')
        if idx + 1 < len(flags):
            out_file = flags[idx + 1]
            del flags[idx:idx + 2]
        else:
            # default name based on data file
            out_file = data_path.stem + '_result.txt'
            del flags[idx]

    flags = set(flags)
    orig_stdout = sys.stdout
    fh = None

    if out_file:
        fh = open(out_file, 'w', encoding='utf-8')
        sys.stdout = fh

    try:
        measurements, info, errors = parse_data(str(data_path))
        grouped = group_measurements(measurements)

        if '--csv' in flags:
            print_csv(measurements)
            return

        print_eval_env()
        print_summary(measurements, info, errors)

        if '--errors' in flags:
            print_errors(errors)

        print_cpb_table(grouped, 'encrypt_cycles')
        print_cpb_table(grouped, 'decrypt_cycles')
    finally:
        if fh:
            sys.stdout = orig_stdout
            fh.close()
            print(f"Results written to {out_file}")


if __name__ == "__main__":
    main()
