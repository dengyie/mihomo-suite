#!/usr/bin/env bash
#
# Repeatable, verified deployment of the zashboard gateway + static bundle.
#
# Why this exists
# ---------------
# Deployment used to be hand-run `scp`/`tar`. On 2026-09-02 an interrupted copy
# left /personal/zashboard/dist/assets/earth-surface-*.webp truncated at 91 KB
# while its WebP header still declared 400 KB — the globe texture 404/decoded to
# nothing for two months because nothing verified the bytes after the copy. The
# same hand-run tar out of macOS also dropped 43 AppleDouble `._*` files into
# dist and later a set of `*.bak-*` backups became publicly servable.
#
# This script makes the payload self-verifying and the install atomic:
#
#   1. local gates       — asset container check + UI syntax
#   2. stage remotely    — payload tar'd with COPYFILE_DISABLE, junk excluded
#   3. verify staged     — sha256 of every file checked ON THE SERVER
#   4. install per file  — same-filesystem `mv` (atomic rename, never a partial)
#   5. clean mirror      — files absent from the payload are removed from dist
#   6. verify live       — re-check sha256 against the manifest after install
#   7. restart           — only when gateway.py actually changed
#
# The gateway serves /personal/zashboard/dist, which is the shared NFS mount, so
# one install reaches both Beam hosts. Only the process restart is per-host.
#
# Usage
#   scripts/deploy-zashboard.sh                 # deploy to tebi, restart if needed
#   scripts/deploy-zashboard.sh --dry-run       # gates + stage + verify, no install
#   scripts/deploy-zashboard.sh --no-restart    # install files only
#
# Env
#   DEPLOY_HOST   ssh target that owns the shared mount (default: tebi)
#   REMOTE_ROOT   remote zashboard root                 (default: /personal/zashboard)
#   PXED_SSH      ssh target for the pxed supervisor    (default: root@10.144.144.31)
#   RESTART_CMD   override the supervisorctl restart command entirely
#
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST_DIR="$REPO_ROOT/zashboard/dist"
GATEWAY="$REPO_ROOT/zashboard/gateway.py"

HOST=${DEPLOY_HOST:-tebi}
REMOTE_ROOT=${REMOTE_ROOT:-/personal/zashboard}
PXED_SSH=${PXED_SSH:-root@10.144.144.31}
RESTART=1
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=1 ;;
    --no-restart) RESTART=0 ;;
    -h|--help)    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[deploy] %s\n' "$*"; }
warn() { printf '[deploy] WARN: %s\n' "$*" >&2; }
die()  { printf '[deploy] ERROR: %s\n' "$*" >&2; exit 1; }

[ -d "$DIST_DIR" ] || die "missing $DIST_DIR"
[ -f "$GATEWAY" ]  || die "missing $GATEWAY"

# ---------------------------------------------------------------- 0. metadata
REV=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)
TS=$(date +%Y%m%d-%H%M%S)
if [ -n "$(git -C "$REPO_ROOT" status --porcelain -- zashboard scripts 2>/dev/null)" ]; then
  REV="$REV-dirty"
  warn "working tree has uncommitted changes under zashboard/ or scripts/"
fi
log "deploying $REV at $TS to $HOST:$REMOTE_ROOT"

# Repo hygiene: these are precisely the artefacts that must never be shipped.
junk=$(find "$DIST_DIR" \( -name '._*' -o -name '.DS_Store' -o -name '*.bak' -o -name '*.bak-*' \) -print 2>/dev/null || true)
if [ -n "$junk" ]; then
  warn "repo dist contains files that will NOT be shipped:"
  printf '  %s\n' $junk >&2
fi

# ------------------------------------------------------------- 1. local gates
log "running local gates"
node "$REPO_ROOT/scripts/check-dist-assets.mjs" >/dev/null \
  || die "check-dist-assets failed — refusing to ship a truncated/corrupt asset"
node --check "$REPO_ROOT/zashboard/src/user-rules-ui.js" \
  || die "src user-rules-ui.js has a syntax error"
node --check "$DIST_DIR/assets/user-rules-ui.js" \
  || die "dist user-rules-ui.js has a syntax error"

# ------------------------------------------------------------- 2. stage local
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/zashboard-deploy.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/dist"

# COPYFILE_DISABLE stops bsdtar writing AppleDouble `._*` members for xattrs.
( cd "$DIST_DIR" && COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -cf - \
    --exclude='._*' --exclude='.DS_Store' --exclude='*.bak' --exclude='*.bak-*' . ) \
  | ( cd "$STAGE/dist" && tar -xf - )
cp "$GATEWAY" "$STAGE/gateway.py"

# Manifest uses paths relative to the stage root so it can be re-verified
# against the live tree after install. Two spaces → `sha256sum -c` compatible.
( cd "$STAGE" && find . -type f ! -name 'MANIFEST.sha256' -print0 | sort -z \
    | xargs -0 shasum -a 256 > MANIFEST.sha256 )
files=$(wc -l < "$STAGE/MANIFEST.sha256" | tr -d ' ')
log "staged $files files ($(du -sh "$STAGE" | cut -f1))"

# ------------------------------------------------------------ 3. stage remote
STAGE_REMOTE="$REMOTE_ROOT/.deploy-$REV-$TS"
log "uploading to $HOST:$STAGE_REMOTE"
ssh -o BatchMode=yes "$HOST" "mkdir -p '$STAGE_REMOTE'" \
  || die "cannot create staging dir on $HOST (ssh/mount problem)"
( cd "$STAGE" && COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf - . ) \
  | ssh -o BatchMode=yes "$HOST" "tar -xzf - -C '$STAGE_REMOTE'" \
  || die "payload upload failed"

# --------------------------------------------- 4-6. verify, install, re-verify
if [ "$DRY_RUN" = 1 ]; then
  ssh -o BatchMode=yes "$HOST" "cd '$STAGE_REMOTE' && sha256sum -c MANIFEST.sha256 --quiet" \
    || die "staged payload failed checksum verification"
  log "dry-run: payload verified on the server; nothing installed"
  ssh -o BatchMode=yes "$HOST" "rm -rf '$STAGE_REMOTE'"
  exit 0
fi

remote_gw_before=$(ssh -o BatchMode=yes "$HOST" "sha256sum '$REMOTE_ROOT/gateway.py' 2>/dev/null | cut -d' ' -f1" || echo missing)

log "verifying + installing on $HOST"
ssh -o BatchMode=yes "$HOST" bash -s -- "$STAGE_REMOTE" "$REMOTE_ROOT" <<'REMOTE'
set -euo pipefail
STAGE=$1
ROOT=$2

# (a) the staged bytes must match what we hashed locally
( cd "$STAGE" && sha256sum -c MANIFEST.sha256 --quiet ) \
  || { echo "[deploy] ERROR: staged payload is corrupt on arrival" >&2; exit 1; }

GW_CHANGED=0
cmp -s "$STAGE/gateway.py" "$ROOT/gateway.py" || GW_CHANGED=1

# (b) payload file list, captured before anything is moved
( cd "$STAGE/dist" && find . -type f | sed 's|^\./||' | sort ) > "$STAGE/payload.lst"

# (c) install each file by same-filesystem rename: a reader sees the old
#     complete file or the new complete file, never a partial one.
while IFS= read -r rel; do
  dst="$ROOT/dist/$rel"
  mkdir -p "$(dirname "$dst")"
  mv -f "$STAGE/dist/$rel" "$dst"
done < "$STAGE/payload.lst"

# (d) clean mirror: drop files that are not part of this payload
( cd "$ROOT/dist" && find . -type f | sed 's|^\./||' ) | while IFS= read -r rel; do
  grep -qxF "$rel" "$STAGE/payload.lst" || { echo "[deploy]   prune dist/$rel"; rm -f "$ROOT/dist/$rel"; }
done
find "$ROOT/dist" -mindepth 1 -type d -empty -delete

# (e) gateway.py: atomic rename from the staging dir (same filesystem)
if [ "$GW_CHANGED" = 1 ]; then
  chmod 755 "$STAGE/gateway.py"
  mv -f "$STAGE/gateway.py" "$ROOT/gateway.py"
  echo "[deploy]   gateway.py installed (changed)"
else
  echo "[deploy]   gateway.py unchanged"
fi

# (f) re-verify the live tree against the same manifest
( cd "$ROOT" && sha256sum -c "$STAGE/MANIFEST.sha256" --quiet ) \
  || { echo "[deploy] ERROR: live tree does not match the manifest" >&2; exit 1; }
echo "[deploy]   live tree verified against $(wc -l < "$STAGE/MANIFEST.sha256" | tr -d ' ') hashes"

echo "GW_CHANGED=$GW_CHANGED"
REMOTE

# The manifest has been re-verified against the live tree, so the staging copy is
# spent. Remove it and keep only the most recent DEPLOY_KEEP staging dirs so a
# crash mid-deploy still leaves the evidence behind.
DEPLOY_KEEP=${DEPLOY_KEEP:-3}
ssh -o BatchMode=yes "$HOST" "
  rm -rf '$STAGE_REMOTE'
  ls -1dt '$REMOTE_ROOT'/.deploy-* 2>/dev/null | tail -n +$((DEPLOY_KEEP + 1)) | xargs -r rm -rf
" || warn "could not clean staging dirs on $HOST"

# --------------------------------------------------------------- 7. restart
restart_host() {
  local target=$1 label=$2
  if [ -n "${RESTART_CMD:-}" ]; then
    log "restart ($label): $RESTART_CMD"
    sh -c "$RESTART_CMD" || warn "$label restart failed"
    return
  fi
  log "restarting zashboard-gateway on $label"
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$target" \
      "supervisorctl ${SUPERVISOR_ARGS:-} restart zashboard-gateway" \
    || warn "could not restart $label (check supervisorctl manually)"
}

if [ "$RESTART" = 1 ]; then
  # Dist-only deploys need no restart (static files are read per request);
  # a gateway.py change does. Compare before/after the install, not after only.
  remote_gw_after=$(ssh -o BatchMode=yes "$HOST" "sha256sum '$REMOTE_ROOT/gateway.py' 2>/dev/null | cut -d' ' -f1" || echo missing)
  if [ "$remote_gw_before" = "$remote_gw_after" ]; then
    log "gateway.py unchanged — no restart needed (static bundle only)"
  else
    restart_host "$HOST" "$HOST"
    if ssh -o BatchMode=yes -o ConnectTimeout=8 "$PXED_SSH" true 2>/dev/null; then
      restart_host "$PXED_SSH" "pxed"
    else
      warn "pxed unreachable at $PXED_SSH — restart it manually: supervisorctl restart zashboard-gateway"
    fi
  fi
fi

# ------------------------------------------------------------- 8. health gate
if [ "${SKIP_HEALTH:-0}" != 1 ]; then
  base=${PUBLIC_URL:-https://3x-ui.mangoqwq.com}
  log "health: $base"
  ok=1
  code=$(curl -s -m 20 -o /dev/null -w '%{http_code}' "$base/" || true)
  [ "$code" = 200 ] || { warn "index returned $code"; ok=0; }
  ctype=$(curl -s -m 20 -o /dev/null -w '%{content_type}' "$base/assets/earth-surface-DQPefyI6.webp" || true)
  [ "$ctype" = "image/webp" ] || { warn "webp content-type is '$ctype'"; ok=0; }
  if [ "$ok" = 1 ]; then log "health OK"; else warn "health checks failed"; fi
fi

log "done ($REV)"
