#!/usr/bin/env bash
# generate_inputs.sh — sign a user-provided message with MAYO and UOV and stage
# the 8 files the notebook expects under ./inputs/ (at the project root).
#
# Uses the two `sign_message` programs (added separately, without modifying
# upstream sources):
#   - mayo/apps/sign_message.c        (built via cmake target sign_message_mayo_<L>)
#   - uov/Source/sign_message.c       (built via uov/Source/build_sign_message.sh)
#
# Active UOV scheme/params come from whatever `uov/Source/common/parameters.h`
# currently selects — this script does NOT edit upstream files.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAYO_DIR="$ROOT/mayo"
UOV_DIR="$ROOT/uov/Source"
OUT_DIR="$ROOT/inputs"

# ---- CLI args -----------------------------------------------------------
MESSAGE=""
MAYO_LEVEL="${MAYO_LEVEL:-1}"   # 1/2/3/5; can also come from env

while [ $# -gt 0 ]; do
  case "$1" in
    -m|--message)     MESSAGE="$2"; shift 2 ;;
    --mayo-level)     MAYO_LEVEL="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $0 -m "<message>" [--mayo-level 1|2|3|5]
EOF
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$MESSAGE" ]; then
  echo "error: --message is required (use -m \"...\")" >&2
  exit 1
fi

# MAYO parameter table (from mayo/README.md).
case "$MAYO_LEVEL" in
  1) MAYO_N=86;  MAYO_M=78;  MAYO_O=8;  MAYO_K=10 ;;
  2) MAYO_N=81;  MAYO_M=64;  MAYO_O=17; MAYO_K=4  ;;
  3) MAYO_N=118; MAYO_M=108; MAYO_O=10; MAYO_K=11 ;;
  5) MAYO_N=154; MAYO_M=142; MAYO_O=12; MAYO_K=12 ;;
  *) echo "unknown MAYO level: $MAYO_LEVEL"; exit 1 ;;
esac

mkdir -p "$OUT_DIR"

# =========================================================================
# 1. MAYO
# =========================================================================
echo "[mayo] building sign_message_mayo_$MAYO_LEVEL…"
mkdir -p "$MAYO_DIR/build"
(
  cd "$MAYO_DIR/build"
  if [ ! -f Makefile ]; then
    cmake -DMAYO_BUILD_TYPE=ref -DENABLE_AESNI=OFF .. >/dev/null
  fi
  make -j "sign_message_mayo_$MAYO_LEVEL" >/dev/null
)

echo "[mayo] signing…"
"$MAYO_DIR/build/apps/sign_message_mayo_$MAYO_LEVEL" \
    --message "$MESSAGE" --out-dir "$OUT_DIR"

cat > "$OUT_DIR/mayo_params.json" <<JSON
{"n":$MAYO_N,"m":$MAYO_M,"q":16,"k":$MAYO_K,"o":$MAYO_O}
JSON
echo "[mayo] wrote $OUT_DIR/mayo_params.json"

# =========================================================================
# 2. UOV
# =========================================================================
echo "[uov] building sign_message…"
(
  cd "$UOV_DIR"
  ./build_sign_message.sh >/dev/null
)

ACTIVE_SCHEME="$(grep -E '^[[:space:]]*#define (LUOV|UOVCLASSIC|UOVHASH)' "$UOV_DIR/common/parameters.h" | head -1 | awk '{print $2}')"
echo "[uov] signing (active scheme = $ACTIVE_SCHEME)…"
"$UOV_DIR/sign_message" --message "$MESSAGE" --out-dir "$OUT_DIR"
# uov_params.json is written by the binary itself (uses compile-time macros).

# =========================================================================
echo
echo "Done. Inputs staged in $OUT_DIR:"
ls -lh "$OUT_DIR"

# Notebook compatibility note: the parser in ks_vs_intersection_attacks.ipynb
# only knows q ∈ {16, 256, 251}. ThesisCode's "F16" actually means GF(2^16), so
# uov_params.json's q value will not match the notebook's parser out of the box.
# Edit parameters.h to pick a different scheme/field, then rerun.
