#!/usr/bin/env python3
"""Every NFSU2 (SPEED2.EXE v1.2 NA) address the runtime and the lift lists name.

The runtime was written against SPEED2.EXE: its overrides, hooks, guest calls
and the game's globals are literal addresses of that exe.  Porting to NFS Most
Wanted (speed.exe) means finding each one's counterpart; tools/sigport.py does
that from the two exes, this tool says what has to be found.

    tools/u2refs.py                 table on stdout (TSV)
    tools/u2refs.py --summary       counts per file and kind
    tools/u2refs.py --addrs         the distinct addresses, one per line, kind first

Kinds, from how the address is used:
    func   a function entry: sub_X / sub_X_orig, dispatch_patch, call_guest,
           DX_WRAP, tools/retpast.txt, tools/inline_hot.txt
    site   an instruction inside a function: HOOK_SITE, a return address
           compared against, a PUSH32 of a return address
    data   a global: MR*/MW* reads and writes, #define G_*/A_* and the rest
           above the U2 code section
    code?  in the U2 code section but used in no way above (a constant, a
           comment): needs a look
"""
import os, re, sys, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
U2_TEXT = (0x00401000, 0x00401000 + 0x00381af1)   # runtime/cpu.h DISPATCH_TEXT_*
U2_IMAGE = (0x00400000, 0x00932000)               # runtime/heap.c

ADDR = re.compile(r'(?<![0-9A-Za-z_])0x(00[4-9a-fA-F][0-9a-fA-F]{5})u?\b')
SUBN = re.compile(r'\bsub_(00[4-9a-f][0-9a-f]{5})(_orig)?\b')
DXW = re.compile(r'DX_WRAP\(\s*[A-Z0-9_]+\s*,\s*(00[0-9a-f]{6})\)')
FUNC_CTX = re.compile(r'(dispatch_patch|dispatch_indirect|call_guest|call_guest_\w+|dispatch_call|guest_call|CALLG?)\s*\([^;]*$|#\s*define\s+(FN|F|SUB)_\w+\s')
SITE_CTX = re.compile(r'HOOK_SITE\s*\(|PUSH32\s*\(|\bret\w*\s*[!=]=|[!=]=\s*\w*ret|#\s*define\s+\w*(_RET|_SITE|_AT)\w*\s')
DATA_CTX = re.compile(r'\b(MR|MW|MRF|MWF)\w*\s*\(|#\s*define\s+[A-Z_]*[GA]_\w+|#\s*define\s+\w+\s+0x')

def kind_of(addr, line, pre):
    ctx = pre + line[:line.find('0x') if '0x' in line else 0]
    if not (U2_IMAGE[0] <= addr < U2_IMAGE[1]): return None
    in_text = U2_TEXT[0] <= addr < U2_TEXT[1]
    if SITE_CTX.search(line): return 'site' if in_text else 'data'
    if in_text and FUNC_CTX.search(ctx): return 'func'
    if not in_text: return 'data'
    if DATA_CTX.search(line): return 'code?'
    return 'code?'

def scan_c(path):
    rel = os.path.relpath(path, ROOT)
    out = []
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.read().split('\n')
    for n, line in enumerate(lines, 1):
        code = line.split('//')[0]
        is_comment = code.strip().startswith(('*', '/*')) and not re.search(r'\*/.*\S', code)
        seen = set()
        for m in SUBN.finditer(code):
            a = int(m.group(1), 16); seen.add(a)
            out.append((rel, n, a, 'func', 'sub_' + m.group(1) + (m.group(2) or ''), is_comment))
        for m in DXW.finditer(code):
            a = int(m.group(1), 16); seen.add(a)
            out.append((rel, n, a, 'func', 'DX_WRAP', is_comment))
        for m in ADDR.finditer(code):
            a = int(m.group(1), 16)
            if a in seen: continue
            k = kind_of(a, code, lines[n - 2] if n >= 2 else '')
            if k: out.append((rel, n, a, k, code.strip()[:90], is_comment))
    return out

def scan_list(path, kind):
    rel = os.path.relpath(path, ROOT); out = []
    for n, line in enumerate(open(path), 1):
        s = line.split('#')[0].strip()
        for m in re.finditer(r'\b(?:0x)?(00[4-9a-f][0-9a-f]{5})\b', s):
            out.append((rel, n, int(m.group(1), 16), kind, s[:90], False))
    return out

def collect():
    rows = []
    for d in ('runtime', 'runtime/web'):
        for fn in sorted(os.listdir(os.path.join(ROOT, d))):
            if fn.endswith(('.c', '.h', '.m', '.inc')):
                rows += scan_c(os.path.join(ROOT, d, fn))
    for fn, k in (('tools/retpast.txt', 'func'), ('tools/inline_hot.txt', 'func')):
        p = os.path.join(ROOT, fn)
        if os.path.exists(p): rows += scan_list(p, k)
    lift = os.path.join(ROOT, 'tools/lift.py')
    for n, line in enumerate(open(lift), 1):
        for m in re.finditer(r'\b0x(00[4-9a-f][0-9a-f]{5}|[4-9a-f][0-9a-f]{5})\b', line.split('#')[0]):
            a = int(m.group(1), 16)
            if U2_TEXT[0] <= a < U2_TEXT[1] and a != 0x00401000:
                rows.append(('tools/lift.py', n, a, 'func', line.strip()[:90], False))
    return rows

def main():
    rows = collect()
    if '--summary' in sys.argv:
        per = collections.defaultdict(collections.Counter)
        for r in rows:
            if not r[5]: per[r[0]][r[3]] += 1
        allk = collections.Counter()
        for f in sorted(per, key=lambda f: -sum(per[f].values())):
            c = per[f]; allk.update(c)
            print(f"{sum(c.values()):5d}  {f:34s} " + ' '.join(f"{k}={v}" for k, v in sorted(c.items())))
        distinct = {(r[2], r[3]) for r in rows if not r[5]}
        print(f"\ntotal {sum(allk.values())} uses, {len({a for a, _ in distinct})} distinct addresses: "
              + ' '.join(f"{k}={len({a for a, kk in distinct if kk == k})}" for k in sorted(allk)))
        return
    if '--addrs' in sys.argv:
        best = {}
        rank = {'func': 0, 'site': 1, 'data': 2, 'code?': 3}
        for r in rows:
            if r[5]: continue
            if r[2] not in best or rank[r[3]] < rank[best[r[2]]]: best[r[2]] = r[3]
        for a in sorted(best): print(f"{best[a]}\t0x{a:08x}")
        return
    print("file\tline\taddr\tkind\tcomment\tcontext")
    for f, n, a, k, ctx, cm in rows:
        print(f"{f}\t{n}\t0x{a:08x}\t{k}\t{int(cm)}\t{ctx}")

if __name__ == '__main__':
    main()
