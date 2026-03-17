#!/usr/bin/env bash
# =============================================================================
# RTAI DevSecOps Pre-Push Gate
# =============================================================================
# Runs three security and hygiene checks before every git push:
#   1. Secrets scanner   — blocks pushes containing API keys / tokens
#   2. Forbidden files   — blocks .db / .lic / __pycache__ / large binaries
#   3. Python linting    — runs flake8 on modified .py files
#
# Install: bash scripts/install_hooks.sh
# Bypass (emergencies only): git push --no-verify
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'; BLD='\033[1m'; RST='\033[0m'

_pass() { printf "${GRN}  ✔ %s${RST}\n" "$*"; }
_fail() { printf "${RED}  ✘ %s${RST}\n" "$*" >&2; }
_warn() { printf "${YEL}  ⚠ %s${RST}\n" "$*"; }
_head() { printf "\n${BLD}── %s ──${RST}\n" "$*"; }

ERRORS=0

# Collect all files staged for this push (across all commits being pushed).
# git push passes  <local_ref> <local_sha> <remote_ref> <remote_sha>  on stdin.
PUSHED_FILES=()
while IFS=' ' read -r local_ref local_sha remote_ref remote_sha; do
    if [[ "$local_sha" == "0000000000000000000000000000000000000000" ]]; then
        continue  # branch deletion — skip
    fi
    BASE="${remote_sha:-$(git rev-list --max-parents=0 "$local_sha" | head -1)}"
    if [[ "$remote_sha" == "0000000000000000000000000000000000000000" ]]; then
        BASE="$(git rev-list --max-parents=0 "$local_sha" | head -1)"
    fi
    while IFS= read -r f; do
        [[ -n "$f" ]] && PUSHED_FILES+=("$f")
    done < <(git diff --name-only "${BASE}..${local_sha}" 2>/dev/null || true)
done

# Deduplicate
IFS=$'\n' UNIQUE_FILES=($(printf '%s\n' "${PUSHED_FILES[@]}" | sort -u))
unset IFS

if [[ ${#UNIQUE_FILES[@]} -eq 0 ]]; then
    _warn "No changed files detected — skipping checks."
    exit 0
fi

printf "\n${BLD}╔══════════════════════════════════════════════════╗${RST}\n"
printf "${BLD}║   RTAI Pre-Push Security & Hygiene Gate          ║${RST}\n"
printf "${BLD}╚══════════════════════════════════════════════════╝${RST}\n"
printf "  Checking %d changed file(s)...\n" "${#UNIQUE_FILES[@]}"


# =============================================================================
# CHECK 1 — Secrets Scanner
# =============================================================================
_head "CHECK 1: Secrets Scanner"

SECRET_PATTERNS=(
    # OpenAI API keys
    'sk-[A-Za-z0-9]{40,}'
    # Anthropic / Claude keys
    'sk-ant-[A-Za-z0-9\-_]{30,}'
    # GitHub Personal Access Tokens (classic + fine-grained)
    'ghp_[A-Za-z0-9]{36}'
    'github_pat_[A-Za-z0-9_]{80,}'
    # Jira / Atlassian API tokens (base64-ish, 24+ chars after known prefix)
    'ATATT[A-Za-z0-9+/=]{80,}'
    # AWS keys
    'AKIA[0-9A-Z]{16}'
    # Telegram bot tokens
    '[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}'
    # Generic high-entropy assignments  (password=, secret=, token=, api_key= followed by long value)
    '(?i)(password|passwd|secret|token|api_key|apikey)\s*=\s*["\x27][A-Za-z0-9+/\-_]{24,}["\x27]'
)

SECRETS_FOUND=0
for file in "${UNIQUE_FILES[@]}"; do
    [[ ! -f "$file" ]] && continue
    # Skip binary files
    if file "$file" 2>/dev/null | grep -q "binary"; then continue; fi

    for pattern in "${SECRET_PATTERNS[@]}"; do
        matches=$(grep -Pn "$pattern" "$file" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            _fail "Potential secret in $file:"
            while IFS= read -r line; do
                printf "         %s\n" "$line" >&2
            done <<< "$matches"
            SECRETS_FOUND=1
            ERRORS=1
        fi
    done
done

# Also scan git diff content directly (catches staged but uncommitted changes)
DIFF_CONTENT=$(git diff HEAD 2>/dev/null || true)
if [[ -n "$DIFF_CONTENT" ]]; then
    for pattern in "${SECRET_PATTERNS[@]}"; do
        diff_hits=$(echo "$DIFF_CONTENT" | grep -P "^\+" | grep -P "$pattern" 2>/dev/null || true)
        if [[ -n "$diff_hits" ]]; then
            _fail "Potential secret in diff (unstaged changes):"
            echo "$diff_hits" | head -5 >&2
            SECRETS_FOUND=1
            ERRORS=1
        fi
    done
fi

if [[ $SECRETS_FOUND -eq 0 ]]; then
    _pass "No secrets or API keys detected"
fi


# =============================================================================
# CHECK 2 — Forbidden / Sensitive File Types
# =============================================================================
_head "CHECK 2: Forbidden Files"

FORBIDDEN_EXTENSIONS=("*.db" "*.sqlite" "*.sqlite3" "*.lic" "*.log" "*.pem" "*.key" "*.p12" "*.pfx")
FORBIDDEN_PATTERNS=("__pycache__" ".env" "*.pyc" "*.pyo" "id_rsa" "id_ed25519" "id_ecdsa")

FORBIDDEN_FOUND=0
for file in "${UNIQUE_FILES[@]}"; do
    fname="${file##*/}"

    # Extension check
    for pattern in "${FORBIDDEN_EXTENSIONS[@]}"; do
        if [[ "$fname" == $pattern ]]; then
            _fail "Forbidden file type staged: $file  (matches $pattern)"
            FORBIDDEN_FOUND=1
            ERRORS=1
        fi
    done

    # Name / path pattern check
    for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
        if [[ "$fname" == $pattern ]] || [[ "/$file/" == *"/${pattern}/"* ]]; then
            _fail "Forbidden file/path staged: $file  (matches $pattern)"
            FORBIDDEN_FOUND=1
            ERRORS=1
        fi
    done

    # Size check — warn on files > 1 MB
    if [[ -f "$file" ]]; then
        size_bytes=$(wc -c < "$file" 2>/dev/null || echo 0)
        if (( size_bytes > 1048576 )); then
            size_kb=$(( size_bytes / 1024 ))
            _fail "Large file staged: $file  (${size_kb} KB > 1 MB limit)"
            FORBIDDEN_FOUND=1
            ERRORS=1
        fi
    fi
done

if [[ $FORBIDDEN_FOUND -eq 0 ]]; then
    _pass "No forbidden or oversized files detected"
fi


# =============================================================================
# CHECK 3 — Python Linting (flake8)
# =============================================================================
_head "CHECK 3: Python Linting (flake8)"

PY_FILES=()
for file in "${UNIQUE_FILES[@]}"; do
    if [[ "$file" == *.py && -f "$file" ]]; then
        PY_FILES+=("$file")
    fi
done

if [[ ${#PY_FILES[@]} -eq 0 ]]; then
    _warn "No Python files in changeset — skipping lint"
else
    # Prefer venv flake8 if available
    FLAKE8_CMD="flake8"
    for candidate in .venv/bin/flake8 venv/bin/flake8; do
        if [[ -x "$candidate" ]]; then
            FLAKE8_CMD="$candidate"
            break
        fi
    done

    if ! command -v "$FLAKE8_CMD" &>/dev/null && [[ "$FLAKE8_CMD" == "flake8" ]]; then
        _warn "flake8 not found — skipping lint (install with: pip install flake8)"
    else
        LINT_OUTPUT=$("$FLAKE8_CMD" \
            --max-line-length=120 \
            --extend-ignore=E501,W503,E302,E303 \
            "${PY_FILES[@]}" 2>&1 || true)

        if [[ -n "$LINT_OUTPUT" ]]; then
            # Treat errors (E/F codes) as blocking; warnings (W codes) as advisory
            BLOCKING=$(echo "$LINT_OUTPUT" | grep -v "^$" | grep -v " W[0-9]" || true)
            ADVISORY=$(echo "$LINT_OUTPUT" | grep " W[0-9]" || true)

            if [[ -n "$BLOCKING" ]]; then
                _fail "Lint errors found (blocking):"
                echo "$BLOCKING" | head -20 >&2
                ERRORS=1
            fi
            if [[ -n "$ADVISORY" ]]; then
                _warn "Lint warnings (advisory — push not blocked):"
                echo "$ADVISORY" | head -10
            fi
            if [[ -z "$BLOCKING" ]]; then
                _pass "${#PY_FILES[@]} Python file(s) linted — no blocking errors"
            fi
        else
            _pass "${#PY_FILES[@]} Python file(s) linted — clean"
        fi
    fi
fi


# =============================================================================
# Result
# =============================================================================
printf "\n"
if [[ $ERRORS -ne 0 ]]; then
    printf "${RED}${BLD}╔══════════════════════════════════════════════════╗${RST}\n"
    printf "${RED}${BLD}║  PRE-PUSH GATE: BLOCKED                          ║${RST}\n"
    printf "${RED}${BLD}╚══════════════════════════════════════════════════╝${RST}\n"
    printf "  Fix the issues above, then retry.\n"
    printf "  Emergency bypass: git push --no-verify\n\n"
    exit 1
else
    printf "${GRN}${BLD}╔══════════════════════════════════════════════════╗${RST}\n"
    printf "${GRN}${BLD}║  PRE-PUSH GATE: PASSED ✔                         ║${RST}\n"
    printf "${GRN}${BLD}╚══════════════════════════════════════════════════╝${RST}\n\n"
    exit 0
fi
