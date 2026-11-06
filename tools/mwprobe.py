#!/usr/bin/env python3
"""Is this NFS Most Wanted folder (or speed.exe) fit for the lift?  Reads files only.

    tools/mwprobe.py <game folder | speed.exe> [SPEED2.EXE]   (with SPEED2.EXE: are both from one toolchain?)

The lift translates the exe's code as it lies in the file, so the exe has to
be the game's own code: not packed or encrypted (SecuROM's wrapper, a
packer), its entry point in its code.  Mods that come as DLLs next to the exe
(an ASI loader as dinput8.dll / d3d9.dll / winmm.dll, scripts/*.asi:
WidescreenFix, MWFixes, Extra Options, XenonEffects) are not loaded by the
port: they change the game in memory on Windows, which the browser build
never does.  They can stay in the folder, they are simply not there for the
port; an exe they patched on disk is another exe, though.

Checks (exit status 0 when nothing is fatal):
  exe        PE32, x86, a GUI program; size and SHA-256 (recorded in out/mw-exe.txt)
  layout     image end below 0x00A00000, where the runtime puts the second
             module (module.c) and its own heap (win32_ext.c H_BASE)
  packed     section names of known wrappers, the entry point outside the code,
             code that looks compressed (entropy)
  imports    the DLLs the exe imports: each needs its runtime counterpart
  mods       ASI loaders and plugins in the folder (not loaded by the port)
  data       the game's data folders
"""
import hashlib, math, os, sys, collections
import pefile

WRAPPERS = {b'.securom', b'.securo', b'.dsstext', b'.bind', b'UPX0', b'UPX1', b'.aspack', b'.adata',
            b'.petite', b'.nsp0', b'.MPRESS1', b'.vmp0', b'.themida', b'.enigma1'}
ASI_LOADERS = ('dinput8.dll', 'd3d9.dll', 'winmm.dll', 'dsound.dll', 'version.dll', 'vorbisfile.dll', 'msacm32.dll')
DATA_DIRS = ('CARS', 'FRONTEND', 'GLOBAL', 'LANGUAGES', 'MOVIES', 'NIS', 'SOUND', 'TRACKS')
MODULE_BASE = 0x00A00000
# DLLs the runtime has a counterpart for (runtime/win32*.c, com.c, dinput*, winsock.c ...)
KNOWN_DLLS = {'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'winmm.dll', 'd3d9.dll', 'dinput8.dll',
              'dsound.dll', 'ws2_32.dll', 'wsock32.dll', 'ole32.dll', 'shell32.dll', 'version.dll', 'netapi32.dll',
              'shlwapi.dll', 'oleaut32.dll', 'comctl32.dll', 'imm32.dll', 'dxguid.dll'}

def runtime_imports():
    """the import names the runtime answers (win32*.c, com.c ...: strcmp(n, "Name"))"""
    import glob, re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    names = set()
    for p in glob.glob(os.path.join(root, 'runtime', '*.c')):
        names |= set(re.findall(r'str(?:case)?cmp\(n, *"([A-Za-z0-9_#@?]+)"\)', open(p, errors='replace').read()))
    return names

def toolchain(pe):
    """the linker's Rich header: the compiler builds that made the most objects (MSVC only)"""
    r = pe.parse_rich_header() if hasattr(pe, 'parse_rich_header') else None
    if not r or not r.get('values'): return None
    v = r['values']; ent = collections.Counter()
    for k in range(0, len(v) - 1, 2):
        comp, cnt = v[k], v[k + 1]
        ent[(comp >> 16, comp & 0xffff)] += cnt
    top = sorted(ent.items(), key=lambda x: -x[1])[:3]
    return ', '.join(f"prod {p} build {b} x{n}" for (p, b), n in top)

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def find_exe(p):
    if os.path.isfile(p): return p, os.path.dirname(os.path.abspath(p))
    for fn in os.listdir(p):
        if fn.lower() == 'speed.exe': return os.path.join(p, fn), p
    return None, p

def main(argv):
    if len(argv) < 2: print(__doc__); return 2
    exe, folder = find_exe(argv[1])
    fatal = []; warn = []
    say = lambda tag, msg: print(f"  {tag:8s} {msg}")
    if not exe:
        print(f"no speed.exe in {folder}"); return 1
    raw = open(exe, 'rb').read()
    sha = hashlib.sha256(raw).hexdigest()
    print(f"{exe}\n  {'exe':8s} {len(raw):,} bytes, SHA-256 {sha}")
    pe = pefile.PE(data=raw)
    if pe.FILE_HEADER.Machine != 0x14c: fatal.append('not an x86 exe')
    if pe.OPTIONAL_HEADER.Magic != 0x10b: fatal.append('not PE32')
    if pe.FILE_HEADER.Characteristics & 0x2000: fatal.append('a DLL, not the exe')
    if pe.FILE_HEADER.Characteristics & 0x20: say('note', 'LARGE_ADDRESS_AWARE set (a 4 GB patch): harmless for the port')
    tc = toolchain(pe)
    say('compiler', tc or 'no Rich header (not linked by MSVC, or stripped)')
    if len(argv) > 2 and os.path.isfile(argv[2]):
        tu = toolchain(pefile.PE(argv[2], fast_load=True))
        same = tc == tu
        say('compiler', f"{os.path.basename(argv[2])}: {tu or 'no Rich header'} -> "
                        + ('unknown (no Rich header to compare)' if tc is None or tu is None else
                           'the same toolchain: tools/sigport.py matches code well' if same else
                           'another toolchain: expect fewer exact matches in tools/sigport.py'))
    ib = pe.OPTIONAL_HEADER.ImageBase; end = ib + pe.OPTIONAL_HEADER.SizeOfImage
    ep = ib + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    say('layout', f"image 0x{ib:08x}-0x{end:08x}, entry 0x{ep:08x}")
    if end > MODULE_BASE:
        warn.append(f"image ends at 0x{end:08x}, above 0x{MODULE_BASE:08x}: module.c's module base and "
                    f"win32_ext.c's H_BASE have to move up")
    code = None
    for s in pe.sections:
        nm = s.Name.rstrip(b'\0')
        d = s.get_data(); ent = entropy(d)
        ex = bool(s.Characteristics & 0x20000000)
        flags = ('x' if ex else '-') + ('w' if s.Characteristics & 0x80000000 else '-')
        say('section', f"{nm.decode('latin1') or '<none>':10s} 0x{ib + s.VirtualAddress:08x} {s.Misc_VirtualSize:>9,} "
                       f"{flags} entropy {ent:.2f}")
        if nm in WRAPPERS or any(nm.lower().startswith(w.lower()) for w in WRAPPERS):
            fatal.append(f"section {nm.decode('latin1')}: a protection or packer wrapper; the lift needs the unwrapped exe")
        if ex and code is None and nm == b'.text': code = s
        if ex and len(d) > 65536 and ent > 7.3:
            fatal.append(f"section {nm.decode('latin1')} looks compressed or encrypted (entropy {ent:.2f})")
    if code is None: code = next((s for s in pe.sections if s.Characteristics & 0x20000000), None)
    if code is None: fatal.append('no code section')
    elif not (ib + code.VirtualAddress <= ep < ib + code.VirtualAddress + code.Misc_VirtualSize):
        fatal.append(f"entry point 0x{ep:08x} outside {code.Name.rstrip(b'\0').decode('latin1')}: a wrapper runs first")
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    dlls = []; have = runtime_imports(); missing_fn = []
    for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        n = e.dll.decode('latin1'); dlls.append((n, len(e.imports)))
        for imp in e.imports:
            nm = imp.name.decode('latin1') if imp.name else f"#{imp.ordinal}"
            if nm not in have: missing_fn.append(f"{n}!{nm}")
    say('imports', ', '.join(f"{n} ({k})" for n, k in dlls))
    say('imports', f"{sum(k for _, k in dlls) - len(missing_fn)} answered by the runtime, {len(missing_fn)} not yet")
    for x in missing_fn: say('', '  not yet: ' + x)
    os.makedirs('out', exist_ok=True)
    with open('out/mw-imports-missing.txt', 'w') as f: f.write('\n'.join(missing_fn) + '\n')
    for n, k in dlls:
        if n.lower() not in KNOWN_DLLS: warn.append(f"imports {n}: the runtime has no counterpart yet")
    files = {f.lower(): f for f in os.listdir(folder)}
    mods = [files[f] for f in ASI_LOADERS if f in files]
    asis = [f for f in files.values() if f.lower().endswith('.asi')]
    sd = files.get('scripts')
    if sd and os.path.isdir(os.path.join(folder, sd)):
        asis += [f"{sd}/{f}" for f in os.listdir(os.path.join(folder, sd)) if f.lower().endswith('.asi')]
    if mods or asis:
        say('mods', f"ASI loader {', '.join(mods) or '-'}; plugins {', '.join(sorted(asis)) or '-'} "
                    f"(not loaded by the port)")
    missing = [d for d in DATA_DIRS if d.lower() not in files]
    say('data', 'all of ' + ' '.join(DATA_DIRS) if not missing else f"missing {' '.join(missing)}")
    if missing and os.path.isdir(folder) and len(missing) == len(DATA_DIRS):
        warn.append('no data folders here: only the exe can be lifted, the game cannot run')
    os.makedirs('out', exist_ok=True)
    with open('out/mw-exe.txt', 'w') as f:
        f.write(f"{os.path.basename(exe)} {len(raw)} {sha}\nimage {ib:#010x}-{end:#010x} entry {ep:#010x}\n")
    for w in warn: print(f"  WARNING  {w}")
    for x in fatal: print(f"  FATAL    {x}")
    print("result: " + ("cannot be lifted as it is" if fatal else "fit for the lift" + (" (see the warnings)" if warn else "")))
    return 1 if fatal else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
