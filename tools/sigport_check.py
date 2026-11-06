#!/usr/bin/env python3
"""How well tools/sigport.py ports functions between two real builds of a DLL.

The answer key is the export table: an export of build A is matched right
when sigport gives the address build B exports under the same name.  Nothing
is run, the files are only read.  Two builds of one 32-bit DLL a few months
apart (Wine's i386-windows/*.dll serve) stand in for SPEED2.EXE and speed.exe.

    tools/sigport_check.py old/wined3d.dll new/wined3d.dll
"""
import collections, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pefile, sigport

def exports(path):
    pe = pefile.PE(path)
    ib = pe.OPTIONAL_HEADER.ImageBase
    out = {}
    for e in getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None).symbols if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else []:
        if e.name and not e.forwarder: out[e.name.decode()] = ib + e.address
    return out

def main(a_path, b_path):
    A = sigport.Analysis(sigport.Image.from_pe(a_path))
    B = sigport.Analysis(sigport.Image.from_pe(b_path))
    ea, eb = exports(a_path), exports(b_path)
    names = sorted(n for n in ea if n in eb and ea[n] in A.funcs and eb[n] in B.funcs)
    # the porter is not told the exports: it works as for the game, from the code alone
    P = sigport.Porter(A, B, lambda *a: print(*a, file=sys.stderr))
    P.run([ea[n] for n in names])
    res = collections.Counter(); wrong = []
    for n in names:
        to, how, s = P.port('func', ea[n])
        k = how.split('/')[0]
        if to is None: res['none'] += 1
        elif to == eb[n]: res['ok ' + k] += 1
        else: res['WRONG ' + k] += 1; wrong.append((n, how, s))
    tot = len(names)
    ok = sum(v for k, v in res.items() if k.startswith('ok'))
    bad = sum(v for k, v in res.items() if k.startswith('WRONG'))
    print(f"{os.path.basename(a_path)}: {tot} exports in both; right {ok} ({100*ok/max(tot,1):.1f}%), "
          f"wrong {bad} ({100*bad/max(tot,1):.1f}%), not found {res['none']}")
    for k, v in sorted(res.items()): print(f"  {k:14s} {v}")
    for n, how, s in wrong[:15]: print(f"  wrong: {n} ({how} {s})")
    return 0 if bad * 50 <= tot else 1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2]))
