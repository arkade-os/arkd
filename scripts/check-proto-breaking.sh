#!/bin/bash
set -e

# Default values
TARGET_BRANCH="${1:-master}"
SUBDIR="${2:-api-spec/protobuf}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Ensure we're in the git repository root
GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Not in a git repository${NC}"
    exit 1
fi

cd "$GIT_ROOT"

# Use npx buf
BUF_CMD="npx -y @bufbuild/buf"

BUF_VERSION=$($BUF_CMD --version)
echo -e "${CYAN}Using buf version: $BUF_VERSION${NC}"
echo -e "${CYAN}Checking for breaking changes against branch: $TARGET_BRANCH${NC}"
echo ""

# Run buf breaking check
AGAINST_REF="$GIT_ROOT/.git#branch=$TARGET_BRANCH,subdir=$SUBDIR"

echo -e "${YELLOW}Running: buf breaking --against $AGAINST_REF${NC}"
echo ""

cd "$SUBDIR"

if $BUF_CMD breaking --against "$AGAINST_REF"; then
    echo ""
    echo -e "${GREEN}✓ No breaking changes detected!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}✗ Breaking changes detected!${NC}"
    echo ""
    echo -e "${YELLOW}To fix breaking changes, you can:${NC}"
    echo -e "${YELLOW}  1. Revert the breaking changes${NC}"
    echo -e "${YELLOW}  2. Use field reservations for deleted fields${NC}"
    echo -e "${YELLOW}  3. Add new fields instead of modifying existing ones${NC}"
    echo -e "${YELLOW}  4. If intentional, document the breaking change in your PR${NC}"
    exit 1
fi
