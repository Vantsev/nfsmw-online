#!/bin/bash
# Port the core runtime's SPEED2.EXE addresses to NFS Most Wanted's speed.exe.
#
#   tools/mwport.sh <SPEED2.EXE> <Most Wanted folder>           report only
#   tools/mwport.sh <SPEED2.EXE> <Most Wanted folder> --apply   rewrite the sources
#
# Needs both exes: the runtime's addresses are SPEED2.EXE's (Underground 2
# v1.2 NA, the one the original project checks by SHA-256), and the only way
# to find their counterparts is to compare its code with speed.exe's.
#
#   1. tools/mwprobe.py   the Most Wanted folder: a clean, unpacked speed.exe
#   2. tools/u2refs.py    the addresses the Most Wanted build's files name
#   3. tools/sigport.py   their counterparts in speed.exe -> out/mw/port.tsv
#   4. tools/applyport.py the sources rewritten (--apply) or the report only
#
# Then: web/gen.sh "<folder>/speed.exe" && GAME=mw web/build.sh
set -e -o pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
U2="$1"; MW="$2"; APPLY="${3:-}"
[ -f "$U2" ] && [ -e "$MW" ] || { sed -n '2,16p' "$0"; exit 2; }
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "no .venv: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"; exit 1; }
mkdir -p out/mw

U2_SHA=f9dd86c054878ce6276beb07c1fd61874f7a1e4bf1f241b084c65b73e24168a7
have=$(shasum -a 256 "$U2" | cut -d' ' -f1)
if [ "$have" != "$U2_SHA" ] && [ "${MWPORT_ANY_U2:-}" != 1 ]; then   # MWPORT_ANY_U2=1: the plumbing test only
  echo "mwport: $U2 is not SPEED2.EXE v1.2 NA (SHA-256 $have); the runtime's addresses are that exe's"; exit 1
fi

echo "== 1. the Most Wanted folder"
"$PY" tools/mwprobe.py "$MW" | tee out/mw/probe.txt || [ "${MWPORT_ANY_U2:-}" = 1 ] || { echo "mwport: this folder cannot be lifted (above)"; exit 1; }
MWEXE="$MW"; [ -d "$MW" ] && MWEXE="$(find "$MW" -maxdepth 1 -iname speed.exe | head -1)"

echo "== 2. the addresses to port"
"$PY" tools/u2refs.py --core --addrs > out/mw/wanted.txt
"$PY" tools/u2refs.py --core --summary | tail -1

echo "== 3. their counterparts in $(basename "$MWEXE") (a few minutes the first time; out/sigport caches the analysis)"
"$PY" tools/sigport.py "$U2" "$MWEXE" out/mw/wanted.txt > out/mw/port.tsv
awk -F'\t' 'NR>1 { split($4, h, /[\/+]/); n[h[1]]++ } END { for (k in n) printf "  %-8s %d\n", k, n[k] }' out/mw/port.tsv | sort

echo "== 4. the sources"
CORE=$(grep -v '^#' tools/mw_core.txt | tr ' ' '\n' | grep . | sed 's|^|runtime/|; s|$|.c|')
FILES="$CORE $(ls runtime/web/*.c) $(ls runtime/*.h) tools/retpast.txt tools/inline_hot.txt"
if [ "$APPLY" = --apply ]; then
  "$PY" tools/applyport.py out/mw/port.tsv $FILES
  echo "applied; what is left is in out/applyport.txt.  Next: web/gen.sh \"$MWEXE\" && GAME=mw web/build.sh"
else
  "$PY" tools/applyport.py out/mw/port.tsv --dry $FILES
  echo "report only (out/applyport.txt); --apply rewrites the sources"
fi
