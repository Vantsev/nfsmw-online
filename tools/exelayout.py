#!/usr/bin/env python3
"""What the lift and the runtime need to know about the exe's layout.

    tools/exelayout.py <exe>                 shell assignments (gen.sh evals them)
    tools/exelayout.py <exe> --header <h>    also writes them as a C header
                                             (gen/all/layout.h, read by runtime/cpu.h)

    TEXT_BASE TEXT_SIZE   the code section (the dispatch table covers it)
    IMAGE_END             ImageBase + SizeOfImage
    FTOL2                 the CRT's _ftol2 (lift.py inlines its calls with FTOL2INL=1)

The values for SPEED2.EXE v1.2 NA are the ones runtime/cpu.h had written in:
0x00401000, 0x00381af1, 0x00932000, 0x0075bed4.
"""
import os, struct, sys
import pefile

# MSVC 7.x _ftol2: push ebp; mov ebp,esp; sub esp,20h; and esp,-16; fld st0;
# fst [esp+18h]; fistp qword [esp+10h]; fild qword [esp+10h]
FTOL2_SIG = bytes.fromhex('558bec83ec2083e4f0d9c0d9542418df7c2410df6c2410')

def layout(path):
    pe = pefile.PE(path, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    text = next((s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text'), None) or \
           next(s for s in pe.sections if s.Characteristics & 0x20000000)
    tb = ib + text.VirtualAddress
    data = text.get_data()
    ts = text.Misc_VirtualSize or len(data)
    out = {'IMAGE_BASE': ib, 'TEXT_BASE': tb, 'TEXT_SIZE': ts, 'IMAGE_END': ib + pe.OPTIONAL_HEADER.SizeOfImage}
    k = data.find(FTOL2_SIG)
    hits = []
    while k >= 0:
        hits.append(tb + k); k = data.find(FTOL2_SIG, k + 1)
    if len(hits) == 1:
        out['FTOL2'] = hits[0]; out['FTOL2_HOW'] = 'signature'
    else:
        # the most called function that converts with fistp qword and aligns esp to 16
        calls = {}
        for o in range(len(data) - 5):
            if data[o] == 0xe8:
                t = (tb + o + 5 + struct.unpack_from('<i', data, o + 1)[0]) & 0xffffffff
                if tb <= t < tb + ts: calls[t] = calls.get(t, 0) + 1
        best = None
        for t, n in sorted(calls.items(), key=lambda x: -x[1])[:200]:
            body = data[t - tb:t - tb + 48]
            if b'\x83\xe4\xf0' in body and b'\xdf\x7c\x24' in body:
                best = t; break
        out['FTOL2'] = best or 0; out['FTOL2_HOW'] = 'structure' if best else 'not found'
    return out

def main():
    if len(sys.argv) < 2: print(__doc__); return 2
    L = layout(sys.argv[1])
    for k in ('IMAGE_BASE', 'TEXT_BASE', 'TEXT_SIZE', 'IMAGE_END', 'FTOL2'):
        print(f"{k}=0x{L[k]:08x}")
    print(f"FTOL2_HOW='{L['FTOL2_HOW']}'")
    if '--header' in sys.argv:
        h = sys.argv[sys.argv.index('--header') + 1]
        with open(h, 'w') as f:
            f.write("/* tools/exelayout.py: the lifted exe's layout (gen.sh) */\n#ifndef GUEST_LAYOUT_H\n#define GUEST_LAYOUT_H\n")
            for k in ('IMAGE_BASE', 'TEXT_BASE', 'TEXT_SIZE', 'IMAGE_END', 'FTOL2'):
                f.write(f"#define GUEST_{k} 0x{L[k]:08x}u\n")
            name = os.path.basename(sys.argv[1]).replace('\\', '').replace('"', '')
            f.write(f'#define GUEST_EXE_NAME "{name}"\n')
            f.write("#endif\n")
    return 0

if __name__ == '__main__':
    sys.exit(main())
