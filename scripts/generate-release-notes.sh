#!/usr/bin/env bash
# scripts/generate-release-notes.sh
# Generates version-specific release notes from git log since the previous tag.
# Only commits starting with feat:, fix:, bug:, or docs: are included.
# Usage: ./scripts/generate-release-notes.sh [PROJECT_NAME] [VERSION]
# Arguments are optional: falls back to auto-detection from Makefile / NSE file.

set -e

# Locate the Makefile — check current dir first, then parent (when run from scripts/)
if [ -f "Makefile" ]; then
    MAKEFILE_DIR="."
elif [ -f "../Makefile" ]; then
    MAKEFILE_DIR=".."
else
    echo "Error: Makefile not found in current or parent directory" >&2
    exit 1
fi

# Auto-detect PROJECT_NAME from Makefile (supports PROJECT_NAME= and BINARY_NAME=)
BINARY_NAME="${1:-$(grep '^PROJECT_NAME=' "${MAKEFILE_DIR}/Makefile" 2>/dev/null | cut -d= -f2 | tr -d ' ')}"
if [ -z "$BINARY_NAME" ]; then
    BINARY_NAME="$(grep '^BINARY_NAME=' "${MAKEFILE_DIR}/Makefile" 2>/dev/null | cut -d= -f2 | tr -d ' ')"
fi

# Auto-detect VERSION: prefer argument, then NSE file, then Makefile literal
if [ -n "$2" ]; then
    VERSION="$2"
elif [ -f "${MAKEFILE_DIR}/cvescannerv3.nse" ]; then
    VERSION="$(grep '^version = ' "${MAKEFILE_DIR}/cvescannerv3.nse" | sed 's/version = "\(.*\)"/\1/' | tr -d ' ')"
else
    VERSION="$(grep '^VERSION ?=' "${MAKEFILE_DIR}/Makefile" 2>/dev/null | cut -d= -f2 | tr -d ' ')"
fi

if [ -z "$BINARY_NAME" ]; then
    echo "Error: PROJECT_NAME could not be determined. Pass it as the first argument or ensure Makefile contains PROJECT_NAME=" >&2
    exit 1
fi
if [ -z "$VERSION" ]; then
    echo "Error: VERSION could not be determined. Pass it as the second argument or ensure cvescannerv3.nse contains version = \"...\"" >&2
    exit 1
fi

TAG="v${VERSION}"

# Detect GitHub repo path from remote URL (supports both HTTPS and SSH)
REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")
REPO_PATH=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/]||' | sed 's|\.git$||')
COMMIT_BASE_URL="https://github.com/${REPO_PATH}/commit"

# Find the previous tag (tag before HEAD, skipping the current one if already created)
PREV_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "")

if [ -z "$PREV_TAG" ]; then
    LOG_RANGE=""
    SINCE_MSG="initial commit"
else
    LOG_RANGE="${PREV_TAG}..HEAD"
    SINCE_MSG="since ${PREV_TAG}"
fi

# format_commits: reads "HASH SUBJECT" lines from stdin and emits markdown list items with links
format_commits() {
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        HASH=$(echo "$line" | cut -d' ' -f1)
        MSG=$(echo "$line" | cut -d' ' -f2-)
        SHORT=$(echo "$HASH" | cut -c1-7)
        echo "- [\`${SHORT}\`](${COMMIT_BASE_URL}/${HASH}) ${MSG}"
    done
}

# Collect all non-merge commits as "HASH SUBJECT"
ALL_COMMITS=$(git log $LOG_RANGE --pretty=format:"%H %s" --no-merges 2>/dev/null || true)

# Only include commits starting with feat:, fix:, bug:, or docs: prefixes
FEATURES=$(echo "$ALL_COMMITS" | grep -E "^[a-f0-9]+ (feat|feature)(\(.+\))?[!:]" || true)
FIXES=$(echo    "$ALL_COMMITS" | grep -E "^[a-f0-9]+ (fix|bug)(\(.+\))?[!:]"      || true)
DOCS=$(echo     "$ALL_COMMITS" | grep -E "^[a-f0-9]+ docs?(\(.+\))?[!:]"          || true)

{
    echo "## ${BINARY_NAME} ${TAG}"
    echo ""
    echo "> Changes ${SINCE_MSG}"
    echo ""

    if [ -n "$FEATURES" ]; then
        echo "### Features"
        echo "$FEATURES" | format_commits
        echo ""
    fi

    if [ -n "$FIXES" ]; then
        echo "### Bug Fixes"
        echo "$FIXES" | format_commits
        echo ""
    fi

    if [ -n "$DOCS" ]; then
        echo "### Documentation"
        echo "$DOCS" | format_commits
        echo ""
    fi

    if [ -z "$FEATURES" ] && [ -z "$FIXES" ] && [ -z "$DOCS" ]; then
        echo "_No changes recorded._"
        echo ""
    fi

    echo "---"
    if [ -n "$PREV_TAG" ]; then
        echo "**Full Changelog**: https://github.com/${REPO_PATH}/compare/${PREV_TAG}...${TAG}"
    else
        echo "**Full Changelog**: https://github.com/${REPO_PATH}/commits/${TAG}"
    fi
}
