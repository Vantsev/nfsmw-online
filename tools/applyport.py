#!/usr/bin/env python3
"""Rewrite the runtime's SPEED2.EXE addresses as another exe's (tools/sigport.py's table).

    tools/applyport.py port.tsv [--min 0.9] [--dry] [files...]

    port.tsv   sigport.py's output: kind, from, to, how, score
    --min S    take a "fuzzy", "near" or "site" result only from score S (default 0.9);
               exact/entry/call/caller/data results are taken as they are
    --dry      write nothing, only the report
    files      default: runtime/*.c *.h *.inc, runtime/web/*.c, tools/retpast.txt,
               tools/inline_hot.txt

Every form the runtime writes an address in is rewritten in one pass (a value
ported to an address that is itself on the list is not ported twice):
0x00XXXXXXu literals (case and suffix kept), sub_00xxxxxx / sub_00xxxxxx_orig,
DX_WRAP(NAME, 00xxxxxx), bare 00xxxxxx in the lift lists.

The report (stderr, and out/applyport.txt) lists, per file, the addresses left
as they were: not found, or found with too low a score.  Those lines still
name SPEED2.EXE and are what is left to do by hand.
"""
import collections, glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SURE = ('exact', 'entry', 'call', 'caller', 'data', 'site/exact', 'site/entry', 'site/call', 'site/caller')

def load(path, min_score):
    m, weak = {}, {}
    for line in open(path):
        p = line.rstrip('\n').split('\t')
        if len(p) < 5 or not p[1].startswith('0x'): continue
        a = int(p[1], 16)
        if not p[2]: weak[a] = 'not found'; continue
        how, s = p[3], float(p[4])
        if how in SURE or s >= min_score: m[a] = int(p[2], 16)
        else: weak[a] = f'{how} {s}'
    return m, weak

PAT = re.compile(r'(?P<lit>(?<![0-9A-Za-z_])0x(?P<lh>00[4-9a-fA-F][0-9a-fA-F]{5})(?P<ls>[uU]?)\b)'
                 r'|(?P<sub>\bsub_(?P<sh>00[4-9a-f][0-9a-f]{5})(?P<so>_orig)?\b)'
                 r'|(?P<dx>DX_WRAP\(\s*[A-Z0-9_]+\s*,\s*)(?P<dh>00[0-9a-f]{6})(?=\))')
LIST = re.compile(r'(?<![0-9A-Za-z_])(?P<pre>0x)?(?P<h>00[4-9a-f][0-9a-f]{5})\b')

def rewrite(text, amap, is_list, left):
    def hexlike(orig, v):
        s = '%08x' % v
        return s.upper() if orig.isupper() and any(c.isalpha() for c in orig) else s
    def f(m):
        if is_list:
            a = int(m.group('h'), 16)
            if a in amap: return (m.group('pre') or '') + hexlike(m.group('h'), amap[a])
            left[a] += 1; return m.group(0)
        if m.group('lit'):
            a = int(m.group('lh'), 16)
            if a in amap: return '0x' + hexlike(m.group('lh'), amap[a]) + m.group('ls')
        elif m.group('sub'):
            a = int(m.group('sh'), 16)
            if a in amap: return 'sub_%08x' % amap[a] + (m.group('so') or '')
        else:
            a = int(m.group('dh'), 16)
            if a in amap: return m.group('dx') + '%08x' % amap[a]
        left[a] += 1
        return m.group(0)
    out = []
    for line in text.split('\n'):
        if is_list and line.lstrip().startswith('#'): out.append(line); continue
        out.append((LIST if is_list else PAT).sub(f, line))
    return '\n'.join(out)

def main(argv):
    args = [a for a in argv[1:]]
    if not args: print(__doc__); return 2
    tsv = args.pop(0)
    min_score = 0.9; dry = False
    if '--min' in args:
        k = args.index('--min'); min_score = float(args[k + 1]); del args[k:k + 2]
    if '--dry' in args: args.remove('--dry'); dry = True
    files = args or sorted(glob.glob(os.path.join(ROOT, 'runtime/*.[ch]')) + glob.glob(os.path.join(ROOT, 'runtime/*.inc'))
                           + glob.glob(os.path.join(ROOT, 'runtime/web/*.c'))
                           + [os.path.join(ROOT, 'tools/retpast.txt'), os.path.join(ROOT, 'tools/inline_hot.txt')])
    amap, weak = load(tsv, min_score)
    rep = []; tot_left = 0; tot_files = 0
    for p in files:
        if not os.path.exists(p): continue
        src = open(p, encoding='utf-8', errors='surrogateescape').read()
        left = collections.Counter()
        dst = rewrite(src, amap, p.endswith('.txt'), left)
        if dst != src:
            tot_files += 1
            if not dry: open(p, 'w', encoding='utf-8', errors='surrogateescape').write(dst)
        if left:
            tot_left += len(left)
            rep.append(f"{os.path.relpath(p, ROOT)}: {len(left)} left: " +
                       ', '.join(f"0x{a:08x} ({weak.get(a, 'not in table')})" for a in sorted(left)))
    summary = f"applyport: {len(amap)} addresses ported, {tot_files} files changed, {tot_left} addresses left as they were"
    rep.insert(0, summary)
    os.makedirs(os.path.join(ROOT, 'out'), exist_ok=True)
    open(os.path.join(ROOT, 'out/applyport.txt'), 'w').write('\n'.join(rep) + '\n')
    print('\n'.join(rep), file=sys.stderr)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
