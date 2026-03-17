#!/usr/bin/env bash
# =============================================================================
# RTAI DevSecOps Hook Installer
# =============================================================================
# Installs the pre-push security gate into the local git repository.
#
# Usage: bash scripts/install_hooks.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"
SRC="$SCRIPT_DIR/pre_push_check.sh"
DEST="$HOOKS_DIR/pre-push"

GRN='\033[0;32m'; RED='\033[0;31m'; BLD='\033[1m'; RST='\033[0m'

echo ""
echo -e "${BLD}RTAI Hook Installer${RST}"
echo "────────────────────────────────────"

# Verify git repo
if [[ ! -d "$HOOKS_DIR" ]]; then
    echo -e "${RED}[!] .git/hooks not found — are you inside a git repository?${RST}" >&2
    exit 1
fi

# Verify source script exists
if [[ ! -f "$SRC" ]]; then
    echo -e "${RED}[!] Source not found: $SRC${RST}" >&2
    exit 1
fi

# Backup any existing hook
if [[ -f "$DEST" ]]; then
    BACKUP="$DEST.bak.$(date +%s)"
    cp "$DEST" "$BACKUP"
    echo "  ⚠  Existing pre-push hook backed up → $BACKUP"
fi

cp "$SRC" "$DEST"
chmod +x "$DEST"

echo -e "${GRN}  ✔  pre-push hook installed → $DEST${RST}"
echo -e "${GRN}  ✔  Executable bit set${RST}"
echo ""
echo "  The hook will run automatically on every 'git push'."
echo "  Emergency bypass (avoid unless critical): git push --no-verify"
echo ""
