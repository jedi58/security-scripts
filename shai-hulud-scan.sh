#!/usr/bin/env bash
################################################################################
# Shai-Hulud 2.0 - NPM Supply-Chain Malware Scanner
#
# DESCRIPTION:
#   Scans Node.js projects for compromised npm packages and malicious IOCs
#   (Indicators of Compromise) associated with the Shai-Hulud 2.0 supply-chain
#   attack. Performs multiple detection methods:
#   - Checks installed packages against known compromised versions
#   - Scans for malicious file patterns (setup_bun.js, bun_environment.js)
#   - Performs SHA-256 hash verification on JS/TS files
#   - Searches for suspicious references to malware infrastructure
#
# REQUIREMENTS:
#   - bash 4.0+
#   - curl (for downloading IOC list)
#   - grep, find, xargs, sed, awk (standard Unix utilities)
#
# USAGE:
#   ./test.sh
#   SKIP_HASH_SCAN=true ./test.sh  # Skip time-consuming hash scan
#
# EXIT CODES:
#   0 - Success: No malicious indicators detected
#   1 - Failure: Malicious packages or IOCs found
#
################################################################################

set -euo pipefail  # Exit on error, undefined vars, and pipe failures

# Display banner
echo $'\e[1;97;44m

 Shai-Hulud 2.0 / NPM Supply-Chain Scanner 
\e[0m'

# ============================================================================
# CONFIGURATION
# ============================================================================

# URL to upstream IOC list maintained by Wiz Research
CSV_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"

# Cache directory: Use XDG_CACHE_HOME if set, otherwise ~/.cache
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/wiz-ioc"
mkdir -p "$CACHE_DIR"

# Local path to cached IOC list
CSV_FILE="$CACHE_DIR/ioc-list.csv"

# ============================================================================
# IOC LIST DOWNLOAD & CACHING
# ============================================================================
# Download the latest IOC list if not cached or cache is stale (>60 minutes)
if [ ! -f "$CSV_FILE" ] || find "$CSV_FILE" -mmin +60 | grep -q .; then
    echo "→ Downloading latest Wiz IOC package list…"
    # Use timeout to prevent hanging on network issues
    timeout 30s curl -sSL "$CSV_URL" -o "$CSV_FILE" || {
        # Fallback to cached version if download fails
        if [ -f "$CSV_FILE" ]; then
            echo "⚠️  IOC list download timed out, using cached version"
        else
            echo "❌ Failed to download IOC list and no cache available"
            exit 1
        fi
    }
else
    echo "→ Using cached Wiz IOC package list…"
fi

# ============================================================================
# LOCK FILE VALIDATION
# ============================================================================
# Ensure we have a lock file (required for dependency extraction)
# Supports: npm (package-lock.json), yarn (yarn.lock), pnpm (pnpm-lock.yaml), bun (bun.lockb)
if [ ! -f pnpm-lock.yaml ] && [ ! -f package-lock.json ] && [ ! -f yarn.lock ] && [ ! -f bun.lockb ]; then
    echo "❌ No lock file found (pnpm-lock.yaml, package-lock.json, yarn.lock, or bun.lockb)"
    echo "   Please run: pnpm install, npm install, yarn install, or bun install"
    exit 1
fi

# ============================================================================
# DEPENDENCY EXTRACTION
# ============================================================================
echo "→ Extracting installed dependencies from lock file…"
if [ -f package-lock.json ]; then
    # npm lock file: Extract packages using grep and sed
    # Matches lines like: "package-name": { "version": "1.0.0"
    grep -o '"[^"]*": *{' package-lock.json | grep -v '^ *{' | \
        sed 's/"//g' | sed 's/: *{//' | sed 's/^ *//' | \
        while read pkg; do
            # Extract version for this package (next "version" line)
            version=$(grep -A 20 "\"$pkg\": *{" package-lock.json | grep '"version": *"' | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
            [ -n "$version" ] && echo "$pkg@$version"
        done | sort -u > installed.txt
elif [ -f pnpm-lock.yaml ]; then
    # pnpm lock file: Extract packages from dependencies section
    # Format: "package-name": version (indented with 2-4 spaces)
    grep -E '^\s+[a-zA-Z0-9@][a-zA-Z0-9._/-]*:' pnpm-lock.yaml | \
        sed 's/^ *//; s/:.*//; s/ *$//' | sort -u > installed.txt
elif [ -f yarn.lock ]; then
    # yarn lock file: Extract from lines like: package-name@version:
    # Handles both scoped (@scope/name) and regular packages
    grep -E '^(@?[a-zA-Z0-9][a-zA-Z0-9._/-]*@[0-9])' yarn.lock | \
        sed 's/ *:.*//' | sort -u > installed.txt
elif [ -f bun.lockb ]; then
    # bun.lockb is binary, attempt text extraction of package names
    # This is a best-effort extraction using strings command
    if command -v strings &> /dev/null; then
        strings bun.lockb | grep -E '^[a-zA-Z0-9@][a-zA-Z0-9._/-]*@[0-9]' | sort -u > installed.txt
    else
        echo "⚠️  bun.lockb is binary and cannot be parsed without additional tools"
        echo "   Consider using npm, yarn, or pnpm instead"
        # Create empty file to allow script to continue
        touch installed.txt
    fi
else
    echo "❌ Unable to locate supported lock file"
    echo "   This should not happen if lock file validation passed"
    exit 1
fi

# ============================================================================
# IOC CHECK A: COMPROMISED PACKAGE VERSIONS
# ============================================================================
echo "→ Checking for compromised package versions…"
# Compare extracted dependencies against the known-bad IOC list
# Use -F (fixed strings) and -x (whole line match) for precision
BAD_MATCHES=$(grep -Fx -f installed.txt "$CSV_FILE" || true)

# Initialize variables for tracking findings across all checks
FOUND=0
if [ -n "$BAD_MATCHES" ]; then
    echo "❌ Found compromised npm packages:"
    echo "$BAD_MATCHES"
    FOUND=1
else
    echo "✓ No compromised npm packages found in dependency tree."
fi

# Clean up temporary dependency list file
rm -f installed.txt

echo
echo "→ Checking for additional IOCs…"

# Initialize flag for detecting any IOCs
FOUND_IOC=0

# ============================================================================
# IOC CHECK B: MALICIOUS FILE PATTERNS
# ============================================================================
# Known malicious files associated with Shai-Hulud 2.0 supply-chain attack
MALWARE_FILES=(
  "setup_bun.js"
  "bun_environment.js"
)

echo "  • Searching for malicious bun files…"
for f in "${MALWARE_FILES[@]}"; do
    # Search project for known malware file names (include node_modules for supply-chain detection)
    FOUND_FILES=$(find . -type f -name "$f" 2>/dev/null)
    if [ -n "$FOUND_FILES" ]; then
        echo "    ❌ Found malware file: $f"
        echo "$FOUND_FILES" | while read filepath; do
            echo "       → $filepath"
        done
        FOUND_IOC=1
    fi
done
if [ $FOUND_IOC -eq 0 ]; then
    echo "    ✓ No malicious bun files found"
fi

# ============================================================================
# IOC CHECK C: SHA-256 FILE HASH VERIFICATION
# ============================================================================
# Known malicious file hashes from the Shai-Hulud 2.0 attack
declare -a MALICIOUS_HASHES=(
  "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
  "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
  "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"
  "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
  "f1df4896244500671eb4aa63ebb48ea11cee196fafaa0e9874e17b24ac053c02"
  "9d59fd0bcc14b671079824c704575f201b74276238dc07a9c12a93a84195648a"
  "e0250076c1d2ac38777ea8f542431daf61fcbaab0ca9c196614b28065ef5b918"
)

# Allow skipping hash scan for faster pre-commit performance (expensive operation)
if [ "${SKIP_HASH_SCAN:-false}" = "true" ]; then
    echo "  • Skipping hash scan (set SKIP_HASH_SCAN=false to enable)"
    echo "    Hash scanning disabled for faster pre-commit performance"
else
    echo "  • Hash scanning for known malicious payloads (SHA-256)…"

    # Create temporary file for hash patterns (cleaned up on exit)
    TEMP_HASHES=$(mktemp)
    trap "rm -f $TEMP_HASHES" EXIT

    # Write malicious hashes to temporary file for grep pattern matching
    printf '%s\n' "${MALICIOUS_HASHES[@]}" > "$TEMP_HASHES"

    # Scan all JavaScript/TypeScript files with parallelization for performance:
    # - find: Locate all JS/TS source files (include node_modules for supply-chain detection)
    # - xargs: Process in batches (-n 50) with 8 parallel workers (-P 8) for speed
    # - sha256sum: Calculate file hashes
    # - grep: Match against known malicious hashes
    MATCH=$(find . -type f \( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" \) \
      -not -path "*/.husky/pre-commit-security-scan" -print0 2>/dev/null | \
      xargs -0 -n 50 -P 8 sha256sum | \
      grep -F -f "$TEMP_HASHES" || true)

    if [ -n "$MATCH" ]; then
        # Report each malicious file found
        echo "$MATCH" | while read hash file; do
            echo "    ❌ Malicious file hash detected: $file"
        done
        FOUND_IOC=1
    else
        echo "    ✓ No known malicious file hashes found"
    fi
fi

# ============================================================================
# IOC CHECK D: MALWARE INFRASTRUCTURE REFERENCES
# ============================================================================
# Search for references to bun.sh domain used in malware loader chains
# Exclude .d.ts files (TypeScript definitions are not executable)
echo "  • Searching for references to bun.sh domain…"
BUN_SH_REFS=$(grep -R "bun.sh" . --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" 2>/dev/null | grep -v "\.d\.ts:")
if [ -n "$BUN_SH_REFS" ]; then
    echo "    ❌ bun.sh domain reference found (possibly malware loader)"
    echo "$BUN_SH_REFS" | cut -d: -f1 | sort -u | while read filepath; do
        echo "       → $filepath"
    done
    FOUND_IOC=1
else
    echo "    ✓ No suspicious bun.sh references found"
fi

# ============================================================================
# IOC CHECK E: EXFILTRATION REPOSITORY PATTERNS
# ============================================================================
# Search for 18-character random GitHub repository names (common exfiltration infrastructure pattern)
# Exclude .d.ts files (TypeScript definitions are not executable)
echo "  • Searching for suspicious GitHub repo names (18-char random)…"
GITHUB_REFS=$(grep -R "github\.com/[0-9a-z]\{18\}" . --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" 2>/dev/null | \
    grep -v "\.d\.ts:" | grep -v "author" | grep -v "Definitions by")
if [ -n "$GITHUB_REFS" ]; then
    echo "    ❌ Exfiltration repository pattern detected"
    echo "$GITHUB_REFS" | cut -d: -f1 | sort -u | while read filepath; do
        echo "       → $filepath"
    done
    FOUND_IOC=1
else
    echo "    ✓ No exfiltration GitHub repo patterns found"
fi

# ============================================================================
# IOC CHECK F: SUSPICIOUS ENVIRONMENT FILE CONTENTS
# ============================================================================
# Check .env files for suspicious URLs, domains, or exfiltration patterns
echo "  • Scanning environment files for suspicious content…"
SUSPICIOUS_PATTERNS=(
    "bun\.sh"
    "github\.com/[0-9a-z]\{18\}"
)

ENV_FOUND=0
for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    # Search .env* files for suspicious patterns (include all directories for supply-chain detection)
    ENV_FILES=$(find . -type f \( -name ".env*" -o -name "*.env" \) 2>/dev/null | \
        xargs grep -l -E "$pattern" 2>/dev/null)
    if [ -n "$ENV_FILES" ]; then
        echo "    ❌ Suspicious content found in .env files"
        echo "$ENV_FILES" | while read filepath; do
            echo "       → $filepath"
        done
        ENV_FOUND=1
        FOUND_IOC=1
        break
    fi
done

if [ $ENV_FOUND -eq 0 ]; then
    echo "    ✓ No suspicious content in environment files"
fi

# ============================================================================
# FINAL VERDICT
# ============================================================================
echo
if [ "${FOUND_IOC:-0}" -eq 1 ] || [ "${FOUND:-0}" -eq 1 ]; then
    echo "⚠️  Suspicious indicators detected. Please investigate this project immediately."
    exit 1
else
    echo "✅ No Shai-Hulud 2.0 indicators detected."
fi
