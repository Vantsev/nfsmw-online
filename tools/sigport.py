#!/usr/bin/env python3
"""Port addresses from one build of the game engine to another.

The runtime names its overrides, hooks, guest calls and globals by their
addresses in NFSU2's SPEED2.EXE.  NFS Most Wanted's speed.exe is the same
engine a year later, compiled by the same compiler: most functions are the
same code at other addresses.  This tool finds, for each address the runtime
needs (tools/u2refs.py --addrs), its counterpart in the other exe.

    tools/sigport.py SPEED2.EXE speed.exe [addrs.txt] > port.tsv
        addrs.txt: "kind<TAB>0xADDR" lines (default: tools/u2refs.py --addrs)

How:
  1. Both exes' code is cut into functions (the entry, every direct call
     target, every pointer into the code from the data that follows padding).
  2. Each instruction becomes a token that is the same in both builds:
     registers and small constants as they are, an absolute address replaced
     by what it points at (the string, the read-only constant, "code" or
     "data"), branch targets dropped.
  3. Functions whose token lists are identical and unique on both sides are
     matched ("exact").  Then, from every matched pair, the aligned
     instructions vote: the callee at the same place is the counterpart of
     the callee ("call"), the global read at the same place the counterpart
     of the global ("data" votes).  New pairs are matched until nothing
     changes.  Functions still needed are matched by similarity ("fuzzy").
  4. A hook site inside a function moves with its aligned instruction; a
     global the code never names exactly is taken from the nearest one it
     does name, at the same distance ("near").

Output (TSV): kind, from, to, how, score.  "to" is empty when nothing was
found; everything but "exact"/"call"/"data" with a high score wants a look.
"""
import bisect, collections, difflib, hashlib, os, pickle, struct, sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
except ImportError:  # pragma: no cover
    sys.exit("sigport.py needs capstone: .venv/bin/pip install -r requirements.txt")


# ---------------------------------------------------------------- images
class Image:
    """A module's sections in memory: [(name, va, bytes, executable, writable)]."""
    def __init__(self, sections, entry=None, name='?'):
        self.name = name
        self.secs = sorted(sections, key=lambda s: s[1])
        self.entry = entry
        self.lo = min(s[1] for s in self.secs)
        self.hi = max(s[1] + len(s[2]) for s in self.secs)
        self._starts = [s[1] for s in self.secs]

    @classmethod
    def from_pe(cls, path):
        import pefile
        pe = pefile.PE(path, fast_load=True)
        ib = pe.OPTIONAL_HEADER.ImageBase
        secs = []
        for s in pe.sections:
            nm = s.Name.rstrip(b'\0').decode('latin1')
            data = s.get_data()
            vs = max(s.Misc_VirtualSize, len(data))
            data = data[:vs] + b'\0' * (vs - len(data))
            ex = bool(s.Characteristics & 0x20000000)
            wr = bool(s.Characteristics & 0x80000000)
            secs.append((nm, ib + s.VirtualAddress, data, ex, wr))
        return cls(secs, ib + pe.OPTIONAL_HEADER.AddressOfEntryPoint, os.path.basename(path))

    def sec(self, a):
        k = bisect.bisect_right(self._starts, a) - 1
        if k >= 0:
            s = self.secs[k]
            if s[1] <= a < s[1] + len(s[2]): return s
        return None

    def u32(self, a):
        s = self.sec(a)
        if s and a + 4 <= s[1] + len(s[2]): return struct.unpack_from('<I', s[2], a - s[1])[0]
        return None

    def cstr(self, a, lo=4, hi=64):
        s = self.sec(a)
        if not s or s[3]: return None
        d, o = s[2], a - s[1]
        e = d.find(b'\0', o, o + 256)
        if e < 0 or e - o < lo: return None
        b = d[o:e]
        if all(32 <= c < 127 or c in (9, 10, 13) for c in b): return b[:hi].decode('latin1')
        return None

    def code(self):
        return [s for s in self.secs if s[3]]


# ---------------------------------------------------------------- tokens
def _hx(v): return '%x' % v

class Analysis:
    """Instructions, functions and tokens of one image."""
    def __init__(self, img):
        self.img = img
        md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
        self.md = md
        self.ins = []          # (addr, size, token, refs) ; refs: tuple of ('T'|'D', value)
        self.addrs = []
        calls = set()
        for nm, va, data, ex, wr in img.code():
            off = 0
            while off < len(data):
                got = False
                for i in md.disasm(data[off:], va + off):
                    got = True
                    t, refs, ct = self._token(i)
                    self.ins.append((i.address, i.size, t, refs))
                    if ct is not None: calls.add(ct)
                    off = i.address + i.size - va
                if not got: off += 1
        self.addrs = [x[0] for x in self.ins]
        self.funcs = self._functions(calls)
        self.fstart = sorted(self.funcs)

    def _cls(self, v):
        img = self.img
        s = img.sec(v)
        if s is None: return None
        if s[3]: return 'T'
        st = img.cstr(v)
        if st is not None: return 'S:' + st
        if not s[4]:
            w = img.u32(v)
            if w is not None and img.sec(w) is None: return 'R:' + _hx(w)
        return 'D'

    def _token(self, i):
        m = i.mnemonic
        refs = []
        ct = None
        if (i.group(CS_GRP_JUMP) or i.group(CS_GRP_CALL)) and i.operands and i.operands[0].type == X86_OP_IMM:
            tgt = i.operands[0].imm & 0xffffffff
            if i.group(CS_GRP_CALL):
                refs.append(('T', tgt)); ct = tgt
                return 'call T', tuple(refs), ct
            return m + ' J', (), None
        ops = []
        for op in i.operands:
            if op.type == X86_OP_REG:
                ops.append(i.reg_name(op.reg))
            elif op.type == X86_OP_IMM:
                v = op.imm & 0xffffffff
                c = self._cls(v)
                if c is None: ops.append(_hx(v))
                else:
                    ops.append(c); refs.append(('T' if c == 'T' else 'D', v))
            elif op.type == X86_OP_MEM:
                mm = op.mem
                p = []
                if mm.segment: p.append(i.reg_name(mm.segment) + ':')
                if mm.base: p.append(i.reg_name(mm.base))
                if mm.index: p.append('%s*%d' % (i.reg_name(mm.index), mm.scale))
                d = mm.disp & 0xffffffff
                c = self._cls(d) if (d and not mm.segment) else None
                if c is None:
                    if d: p.append(_hx(d))
                else:
                    p.append(c); refs.append(('T' if c == 'T' else 'D', d))
                ops.append('%d[%s]' % (op.size, '+'.join(p)))
        return m + ' ' + ','.join(ops), tuple(refs), ct

    def _functions(self, calls):
        img = self.img
        idx = {a: k for k, a in enumerate(self.addrs)}
        starts = {a for a in calls if a in idx}
        if img.entry in idx: starts.add(img.entry)
        for nm, va, data, ex, wr in img.secs:
            if ex: continue
            for o in range(0, len(data) - 3, 4):
                v = struct.unpack_from('<I', data, o)[0]
                if v in idx and v not in starts:
                    s = img.sec(v); pb = s[2][v - s[1] - 1] if v > s[1] else 0xcc
                    if pb in (0xcc, 0x90, 0xc3): starts.add(v)
        st = sorted(starts)
        funcs = {}
        for n, a in enumerate(st):
            k0 = idx[a]
            end = st[n + 1] if n + 1 < len(st) else None
            k1 = k0
            while k1 < len(self.ins) and (end is None or self.ins[k1][0] < end):
                t = self.ins[k1][2]
                k1 += 1
                if end is None and t.startswith(('ret', 'int3')): break
            # trailing padding is not the function
            while k1 > k0 + 1 and self.ins[k1 - 1][2] in ('int3 ', 'nop '): k1 -= 1
            funcs[a] = (k0, k1)
        return funcs

    def body(self, f):
        k0, k1 = self.funcs[f]
        return self.ins[k0:k1]

    def toks(self, f):
        return [x[2] for x in self.body(f)]

    def owner(self, a):
        k = bisect.bisect_right(self.fstart, a) - 1
        if k < 0: return None
        f = self.fstart[k]
        k0, k1 = self.funcs[f]
        return f if self.ins[k0][0] <= a < (self.ins[k1 - 1][0] + self.ins[k1 - 1][1]) else None

    def hash(self, f):
        return hashlib.sha1('\n'.join(self.toks(f)).encode()).hexdigest()


# ---------------------------------------------------------------- matching
def align(A, B, fa, fb):
    """Aligned instruction index pairs of two functions (equal blocks only)."""
    ta, tb = A.toks(fa), B.toks(fb)
    if ta == tb: return [(k, k) for k in range(len(ta))]
    sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    out = []
    for tag, i0, i1, j0, j1 in sm.get_opcodes():
        if tag == 'equal': out += [(i0 + k, j0 + k) for k in range(i1 - i0)]
    return out

def similarity(A, B, fa, fb):
    ta, tb = A.toks(fa), B.toks(fb)
    if not ta or not tb: return 0.0
    if ta == tb: return 1.0
    return difflib.SequenceMatcher(None, ta, tb, autojunk=False).ratio()

class Porter:
    def __init__(self, A, B, log=None):
        self.A, self.B = A, B
        self.fmap = {}       # A func -> (B func, how, score)
        self.rev = {}
        self.dvotes = collections.defaultdict(collections.Counter)
        self.log = log or (lambda *a: None)

    def _pair(self, fa, fb, how, score):
        if fa in self.fmap or fb in self.rev: return False
        self.fmap[fa] = (fb, how, score); self.rev[fb] = fa
        return True

    def exact(self):
        ha = collections.defaultdict(list); hb = collections.defaultdict(list)
        for f in self.A.funcs:
            if self.A.funcs[f][1] - self.A.funcs[f][0] >= 3: ha[self.A.hash(f)].append(f)
        for f in self.B.funcs:
            if self.B.funcs[f][1] - self.B.funcs[f][0] >= 3: hb[self.B.hash(f)].append(f)
        n = 0
        for h, la in ha.items():
            lb = hb.get(h)
            if lb and len(la) == 1 and len(lb) == 1:
                n += self._pair(la[0], lb[0], 'exact', 1.0)
        self.log(f"exact: {n} unique identical functions")

    def callers(self, an):
        if not hasattr(an, '_callers'):
            cl = collections.defaultdict(set)
            for f in an.funcs:
                for x in an.body(f):
                    for k, v in x[3]:
                        if k == 'T' and v in an.funcs: cl[v].add(f)
            an._callers = cl
        return an._callers

    def up(self, min_sim=0.6):
        """callers: a matched pair's only unmatched callers on both sides, when alike"""
        ca, cb = self.callers(self.A), self.callers(self.B)
        n = 0
        for fa, (fb, _, _) in list(self.fmap.items()):
            ua = [f for f in ca.get(fa, ()) if f not in self.fmap]
            ub = [f for f in cb.get(fb, ()) if f not in self.rev]
            if len(ua) == 1 and len(ub) == 1:
                s = similarity(self.A, self.B, ua[0], ub[0])
                if s >= min_sim: n += self._pair(ua[0], ub[0], 'caller', round(s, 3))
        return n

    def propagate(self, min_sim=0.6):
        while True:
            self._down(min_sim)
            if not self.up(min_sim): break

    def _down(self, min_sim=0.6):
        done = getattr(self, '_done', set()); self._done = done
        rounds = 0
        while True:
            rounds += 1
            cand = collections.defaultdict(collections.Counter)
            todo = [fa for fa in self.fmap if fa not in done]
            if not todo: break
            for fa in todo:
                done.add(fa)
                fb = self.fmap[fa][0]
                ba, bb = self.A.body(fa), self.B.body(fb)
                for i, j in align(self.A, self.B, fa, fb):
                    ra, rb = ba[i][3], bb[j][3]
                    if len(ra) != len(rb): continue
                    for (ka, va), (kb, vb) in zip(ra, rb):
                        if ka != kb: continue
                        if ka == 'T':
                            if va in self.A.funcs and vb in self.B.funcs: cand[va][vb] += 1
                        else:
                            self.dvotes[va][vb] += 1
            added = 0
            for va, c in cand.items():
                if va in self.fmap: continue
                (vb, nv), = c.most_common(1)
                if vb in self.rev: continue
                if len(c) > 1 and c.most_common(2)[1][1] * 2 >= nv: continue
                s = similarity(self.A, self.B, va, vb)
                if s >= min_sim: added += self._pair(va, vb, 'call', round(s, 3))
            self.log(f"propagate round {rounds}: +{added} (now {len(self.fmap)})")
            if not added and not [fa for fa in self.fmap if fa not in done]: break
        self._done = done

    def fuzzy(self, wanted, min_sim=0.8, margin=0.05):
        A, B = self.A, self.B
        bfree = [f for f in B.funcs if f not in self.rev]
        blen = sorted((B.funcs[f][1] - B.funcs[f][0], f) for f in bfree)
        lens = [x[0] for x in blen]
        n = 0
        for fa in wanted:
            if fa in self.fmap or fa not in A.funcs: continue
            la = A.funcs[fa][1] - A.funcs[fa][0]
            if la < 4: continue
            lo = bisect.bisect_left(lens, int(la * 0.8)); hi = bisect.bisect_right(lens, int(la * 1.25) + 1)
            ta = A.toks(fa); sa = set(ta)
            scored = []
            for _, fb in blen[lo:hi]:
                if fb in self.rev: continue
                tb = B.toks(fb)
                if len(sa & set(tb)) < 0.5 * len(sa): continue
                sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
                if sm.real_quick_ratio() < min_sim or sm.quick_ratio() < min_sim: continue
                scored.append((sm.ratio(), fb))
            scored.sort(reverse=True)
            if scored and scored[0][0] >= min_sim and (len(scored) == 1 or scored[0][0] - scored[1][0] >= margin):
                n += self._pair(fa, scored[0][1], 'fuzzy', round(scored[0][0], 3))
        self.log(f"fuzzy: +{n}")

    def entry(self):
        ea, eb = self.A.img.entry, self.B.img.entry
        if ea in self.A.funcs and eb in self.B.funcs:
            self._pair(ea, eb, 'entry', round(similarity(self.A, self.B, ea, eb), 3))

    def run(self, wanted_funcs=()):
        self.exact(); self.entry(); self.propagate()
        if wanted_funcs:
            self.fuzzy(wanted_funcs); self.propagate()

    # ------------------------------------------------ lookups
    def func(self, a):
        if a in self.fmap:
            fb, how, s = self.fmap[a]; return fb, how, s
        return None, 'none', 0.0

    def site(self, a):
        fa = self.A.owner(a)
        if fa is None or fa not in self.fmap: return None, 'none', 0.0
        fb, how, s = self.fmap[fa]
        ba, bb = self.A.body(fa), self.B.body(fb)
        ka = next((k for k, x in enumerate(ba) if x[0] == a), None)
        if ka is None:
            # inside an instruction (an operand's bytes): its instruction, same offset
            ka = next((k for k, x in enumerate(ba) if x[0] < a < x[0] + x[1]), None)
            if ka is None: return None, 'none', 0.0
        for i, j in align(self.A, self.B, fa, fb):
            if i == ka:
                return bb[j][0] + (a - ba[ka][0]), 'site/' + how, s
        return None, 'site-unaligned', 0.0

    def data(self, a):
        c = self.dvotes.get(a)
        if c:
            (vb, n), = c.most_common(1)
            return vb, 'data', round(n / sum(c.values()), 3)
        # nearest named global below, same distance (a field of a struct the code names by its base)
        keys = sorted(self.dvotes)
        k = bisect.bisect_right(keys, a) - 1
        if k >= 0 and a - keys[k] <= 0x400:
            base = keys[k]
            (vb, n), = self.dvotes[base].most_common(1)
            return vb + (a - base), 'near+0x%x' % (a - base), round(0.5 * n / sum(self.dvotes[base].values()), 3)
        return None, 'none', 0.0

    def port(self, kind, a):
        if kind == 'func':
            r = self.func(a)
            if r[0] is None and self.A.owner(a) is not None and a not in self.A.funcs: r = self.site(a)
            return r
        if kind == 'site': return self.site(a)
        if kind == 'data': return self.data(a)
        # unknown use: whichever is known
        if self.A.img.sec(a) and self.A.img.sec(a)[3]:
            r = self.func(a)
            return r if r[0] is not None else self.site(a)
        return self.data(a)


# ---------------------------------------------------------------- cli
def load(path, cache_dir='out/sigport'):
    os.makedirs(cache_dir, exist_ok=True)
    h = hashlib.sha256(open(path, 'rb').read()).hexdigest()[:16]
    me = hashlib.sha256(open(__file__, 'rb').read()).hexdigest()[:8]
    cp = os.path.join(cache_dir, f'{h}-{me}.pickle')
    if os.path.exists(cp):
        with open(cp, 'rb') as f: return pickle.load(f)
    an = Analysis(Image.from_pe(path))
    an.md = None
    with open(cp, 'wb') as f: pickle.dump(an, f)
    return an

def read_wanted(path):
    out = []
    for line in open(path):
        p = line.split()
        if len(p) >= 2 and p[1].startswith('0x'): out.append((p[0], int(p[1], 16)))
    return out

def main(argv):
    if len(argv) < 3:
        print(__doc__); return 2
    log = lambda *a: print(*a, file=sys.stderr)
    log(f"analysing {argv[1]} ..."); A = load(argv[1]); log(f"  {len(A.ins)} instructions, {len(A.funcs)} functions")
    log(f"analysing {argv[2]} ..."); B = load(argv[2]); log(f"  {len(B.ins)} instructions, {len(B.funcs)} functions")
    if len(argv) > 3: wanted = read_wanted(argv[3])
    else:
        import subprocess
        txt = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), 'u2refs.py'), '--addrs'],
                             capture_output=True, text=True, check=True).stdout
        wanted = [(l.split()[0], int(l.split()[1], 16)) for l in txt.splitlines() if l.strip()]
    P = Porter(A, B, log)
    wf = [a for k, a in wanted if k == 'func'] + [A.owner(a) for k, a in wanted if k == 'site' and A.owner(a)]
    P.run(wf)
    stats = collections.Counter()
    print("kind\tfrom\tto\thow\tscore")
    for k, a in wanted:
        to, how, s = P.port(k, a)
        stats[how.split('/')[0].split('+')[0]] += 1
        print(f"{k}\t0x{a:08x}\t{'' if to is None else '0x%08x' % to}\t{how}\t{s}")
    log("ported: " + ', '.join(f"{k}={v}" for k, v in stats.most_common()))
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
