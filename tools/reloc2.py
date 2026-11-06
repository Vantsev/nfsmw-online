#!/usr/bin/env python3
"""The exe's absolute-address fixup slots -> out/relocs.txt (genall.py's and
argcount.py's seeds: every pointer into the code they hold is an entry).

Where they come from, in this order:
  1. the PE's base relocation directory, when it has one (a normal exe);
  2. an unnamed section that holds the relocation table, its directory entry
     zeroed: SPEED2.EXE v1.2 NA is like that (the original reloc2.py, its
     output unchanged);
  3. neither (relocations stripped, /FIXED): every 4-byte value in the data
     sections that points into the image, and every absolute operand of an
     instruction that points into the code.  More slots than a real table
     would have; each is only a seed, so a few extra entries cost little.

    tools/reloc2.py <exe> [out/relocs.txt]
"""
import sys, os, struct, collections
import pefile

EXE = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else 'out/relocs.txt'
pe = pefile.PE(EXE); IB = pe.OPTIONAL_HEADER.ImageBase
IMG_LO, IMG_HI = IB, IB + pe.OPTIONAL_HEADER.SizeOfImage
secs = []
for s in pe.sections:
    nm = s.Name.rstrip(b'\x00').decode('latin1').strip() or '<none>'
    secs.append((nm, IB + s.VirtualAddress, s.Misc_VirtualSize, s.get_data(), bool(s.Characteristics & 0x20000000)))

def rd32(a):
    for nm, va, vs, d, ex in secs:
        if va <= a < va + len(d) - 3: return struct.unpack_from('<I', d, a - va)[0]
    return None

def sec_of(a):
    for nm, va, vs, d, ex in secs:
        if va <= a < va + vs: return nm
    return '<outside>'

def parse_table(blob):
    off = 0; tot = 0; types = collections.Counter(); addrs = []; blocks = 0; bad = 0
    while off + 8 <= len(blob):
        page, size = struct.unpack_from('<II', blob, off)
        if size == 0: break
        if size < 8 or off + size > len(blob) + 8:
            bad += 1; break
        n = (min(size, len(blob) - off) - 8) // 2
        for i in range(n):
            (w,) = struct.unpack_from('<H', blob, off + 8 + i * 2)
            t = w >> 12; o = w & 0xfff
            types[t] += 1; tot += 1
            if t == 3: addrs.append(IB + page + o)
        blocks += 1; off += size
    print(f"blocks parsed: {blocks}   entries in total: {tot}   bad: {bad}")
    for t, c in sorted(types.items()): print(f"  type {t}: {c}")
    return addrs

def from_directory():
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
    if not d.VirtualAddress or not d.Size: return None
    blob = pe.get_data(d.VirtualAddress, d.Size)
    print(f"source: the base relocation directory ({d.Size} bytes)")
    return parse_table(blob)

def from_unnamed():
    blob = next((d for nm, va, vs, d, ex in secs if nm == '<none>'), None)
    if blob is None: return None
    print("source: the unnamed section (relocation table, directory entry zeroed)")
    a = parse_table(blob)
    return a or None

def from_scan():
    print("source: no relocation table; scanned the data and the code's operands")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    addrs = set()
    text = [(va, d) for nm, va, vs, d, ex in secs if ex]
    in_code = lambda v: any(va <= v < va + len(d) for va, d in text)
    for nm, va, vs, d, ex in secs:
        if ex: continue
        for o in range(0, len(d) - 3, 4):
            v = struct.unpack_from('<I', d, o)[0]
            if IMG_LO <= v < IMG_HI: addrs.add(va + o)
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    for va, d in text:
        off = 0
        while off < len(d):
            got = False
            for i in md.disasm(d[off:], va + off):
                got = True; off = i.address + i.size - va
                if i.mnemonic in ('call', 'jmp') or i.mnemonic.startswith('j'): continue
                for op in i.operands:
                    v = (op.imm if op.type == X86_OP_IMM else op.mem.disp if op.type == X86_OP_MEM else 0) & 0xffffffff
                    if not in_code(v): continue
                    raw = bytes(i.bytes); k = raw.rfind(struct.pack('<I', v))
                    if k >= 0: addrs.add(i.address + k)
            if not got: off += 1
    return sorted(addrs)

addrs = from_directory()
if addrs is None: addrs = from_unnamed()
if addrs is None: addrs = from_scan()

print("\nsections holding the absolute-address fixups:")
for k, v in collections.Counter(map(sec_of, addrs)).most_common(): print(f"  {k:10s} {v}")
ok = sum(1 for a in addrs if (v := rd32(a)) is not None and IMG_LO <= v < IMG_HI)
print(f"\nCHECK: the values at {ok}/{len(addrs)} locations point into the image ({IMG_LO:#x}-{IMG_HI:#x}) = {100.0*ok/max(len(addrs),1):.2f}%")
os.makedirs(os.path.dirname(OUT) or '.', exist_ok=True)
open(OUT, 'w').write('\n'.join(f'{a:08x}' for a in sorted(addrs)))
print(f"-> {OUT} ({len(addrs)} addresses)")
