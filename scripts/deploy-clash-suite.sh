#!/usr/bin/env bash
#
# Deploy / drift-check the mihomo config-writer suite to the shared /personal/clash.
#
# Why this exists
# ---------------
# clash/*.py are the live config writers and the keeper loop. They were copied by
# hand, so the repo and production drifted in *both* directions: the 2026-10-22
# fix to clash-keeper-loop.sh (pgrep -x mihomo false-positives, proxy-selector-guard
# invocation) lived only on tebi, while the 2026-11-04 cross-host lock lived only
# in the repo. Nothing compared the two.
#
# This script is the single source of truth check + install path:
#   --check     compare every managed file, report SAME/DIFF, change nothing
#   --dry-run   stage + verify only (no install)
#   (default)   verify each file, back up the old one, atomically replace it
#
# It only ever touches the managed files listed in MANAGED below. Production-only
# helpers (start-clash.sh, native-recovery-monitor.sh, proxy-selector-guard.py,
# tcp-bridge.py) are deliberately left alone, and nothing is ever pruned.
#
# /personal/clash is the shared NFS mount, so one install reaches both hosts.
#
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLASH_SRC="$REPO_ROOT/clash"
HOST=${DEPLOY_HOST:-tebi}
REMOTE_DIR=${REMOTE_DIR:-/personal/clash}

MANAGED=(
  apply-local-import.py
  clash_lock.py
  cluster_reload.py
  hutao-bridge-guard.py
  probe_clash_nodes.py
  rules-reconciler.py
  subscription-manager.py
  clash-keeper-loop.sh
)

MODE=install
for arg in "$@"; do
  case "$arg" in
    --check)   MODE=check ;;
    --dry-run) MODE=dry-run ;;
    -h|--help) sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[clash] %s\n' "$*"; }
warn() { printf '[clash] WARN: %s\n' "$*" >&2; }
die()  { printf '[clash] ERROR: %s\n' "$*" >&2; exit 1; }

local_hash() { shasum -a 256 "$1" | cut -d' ' -f1; }
remote_hash() { ssh -o BatchMode=yes "$HOST" "sha256sum '$REMOTE_DIR/$1' 2>/dev/null | cut -d' ' -f1" || true; }

[ -d "$CLASH_SRC" ] || die "missing $CLASH_SRC"

# every managed file must exist in the repo — a typo here must not silently skip
for f in "${MANAGED[@]}"; do
  [ -f "$CLASH_SRC/$f" ] || die "managed file missing from repo: clash/$f"
done

# ---------------------------------------------------------------- syntax gates
log "running syntax gates"
for f in "${MANAGED[@]}"; do
  case "$f" in
    *.py) python3 -m py_compile "$CLASH_SRC/$f" || die "py_compile failed: $f" ;;
    *.sh) bash -n "$CLASH_SRC/$f" || die "bash -n failed: $f" ;;
  esac
done

# ------------------------------------------------------------------- compare
# NB: macOS ships bash 3.2, where `set -u` + `${#arr[@]}` on an empty array is an
# "unbound variable" error, so counts are tracked explicitly.
DIFF=(); SAME=(); MISSING=()
n_diff=0; n_same=0; n_missing=0
for f in "${MANAGED[@]}"; do
  l=$(local_hash "$CLASH_SRC/$f")
  r=$(remote_hash "$f")
  if [ -z "$r" ]; then MISSING+=("$f"); n_missing=$((n_missing + 1))
  elif [ "$l" = "$r" ]; then SAME+=("$f"); n_same=$((n_same + 1))
  else DIFF+=("$f"); n_diff=$((n_diff + 1)); fi
done

log "managed files: ${#MANAGED[@]}  same: $n_same  diff: $n_diff  missing-on-prod: $n_missing"
if [ "$n_same" -gt 0 ]; then for f in "${SAME[@]}"; do log "  SAME     $f"; done; fi
if [ "$n_diff" -gt 0 ]; then for f in "${DIFF[@]}"; do log "  DIFF     $f"; done; fi
if [ "$n_missing" -gt 0 ]; then for f in "${MISSING[@]}"; do log "  MISSING  $f"; done; fi

if [ "$MODE" = check ]; then
  if [ "$n_diff" -eq 0 ] && [ "$n_missing" -eq 0 ]; then
    log "no drift"
    exit 0
  fi
  warn "drift detected (repo <-> $HOST:$REMOTE_DIR)"
  exit 1
fi

if [ "$n_diff" -eq 0 ] && [ "$n_missing" -eq 0 ]; then
  log "nothing to deploy"
  exit 0
fi

# --------------------------------------------------------------------- stage
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/clash-deploy.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
TS=$(date +%Y%m%d-%H%M%S)
STAGE_REMOTE="$REMOTE_DIR/.deploy-$TS"
mkdir -p "$STAGE/clash"

TO_INSTALL=()
if [ "$n_diff" -gt 0 ]; then TO_INSTALL=("${DIFF[@]}"); fi
if [ "$n_missing" -gt 0 ]; then TO_INSTALL=("${TO_INSTALL[@]}" "${MISSING[@]}"); fi
for f in ${TO_INSTALL[@]+"${TO_INSTALL[@]}"}; do
  cp "$CLASH_SRC/$f" "$STAGE/clash/$f"
  log "will install $f"
done
( cd "$STAGE" && find . -type f ! -name 'MANIFEST.sha256' -print0 | sort -z | xargs -0 shasum -a 256 > MANIFEST.sha256 )

log "uploading to $HOST:$STAGE_REMOTE"
ssh -o BatchMode=yes "$HOST" "mkdir -p '$STAGE_REMOTE'" || die "cannot create staging dir"
( cd "$STAGE" && COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf - . ) \
  | ssh -o BatchMode=yes "$HOST" "tar -xzf - -C '$STAGE_REMOTE'" \
  || die "upload failed"

if [ "$MODE" = dry-run ]; then
  ssh -o BatchMode=yes "$HOST" "cd '$STAGE_REMOTE' && sha256sum -c MANIFEST.sha256 --quiet" \
    || die "staged payload failed verification"
  log "dry-run: payload verified; nothing installed"
  ssh -o BatchMode=yes "$HOST" "rm -rf '$STAGE_REMOTE'"
  exit 0
fi

# ---------------------------------------------------------- verify + install
log "installing on $HOST"
ssh -o BatchMode=yes "$HOST" bash -s -- "$STAGE_REMOTE" "$REMOTE_DIR" "$TS" <<'REMOTE'
set -euo pipefail
STAGE=$1
DIR=$2
TS=$3

( cd "$STAGE" && sha256sum -c MANIFEST.sha256 --quiet ) \
  || { echo "[clash] ERROR: staged payload corrupt on arrival" >&2; exit 1; }

for rel in $(cd "$STAGE" && find ./clash -type f | sed 's|^\./clash/||'); do
  src="$STAGE/clash/$rel"
  dst="$DIR/$rel"
  if [ -f "$dst" ]; then
    # keep the pre-image; never lose the version that was live
    cp -p "$dst" "$dst.pre-deploy-$TS"
  fi
  # same-filesystem rename → atomic, never a half-written writer on disk
  cp "$src" "$DIR/.$rel.new.$TS"
  chmod --reference="$dst" "$DIR/.$rel.new.$TS" 2>/dev/null || chmod 755 "$DIR/.$rel.new.$TS"
  mv -f "$DIR/.$rel.new.$TS" "$dst"
  # verify the installed bytes
  [ "$(sha256sum "$dst" | cut -d' ' -f1)" = "$(sha256sum "$src" | cut -d' ' -f1)" ] \
    || { echo "[clash] ERROR: $rel failed post-install verification" >&2; exit 1; }
  echo "[clash]   installed $rel (backup .pre-deploy-$TS)"
done
REMOTE

ssh -o BatchMode=yes "$HOST" "rm -rf '$STAGE_REMOTE'" || warn "could not remove staging dir"

log "done — installed ${#DIFF[@]} changed + ${#MISSING[@]} missing file(s)"
cat <<EOF

[clash] Next:
  keeper (apply-local-import/rules-reconciler/hutao-bridge-guard) picks up new
  code on its next cycle. The gateway imports subscription-manager + clash_lock
  at load time, so restart it for the lock change to take effect:

    ssh $HOST supervisorctl restart zashboard-gateway
    ssh root@10.144.144.31 'supervisorctl -s unix:///personal/pxed/supervisor.sock restart zashboard-gateway'

  Roll back any file with:  mv <file>.pre-deploy-$TS <file>
EOF
