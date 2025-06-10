#!/bin/bash

# Setup Homebrew Tap for CLI Snitch
# This script helps you create your own Homebrew tap for distributing CLI Snitch

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GITHUB_USERNAME=${1:-"yourusername"}
REPO_NAME="cli-snitch"
TAP_REPO_NAME="homebrew-tap"

echo -e "${BLUE}🍺 CLI Snitch Homebrew Tap Setup${NC}"
echo "=================================="

if [ "$GITHUB_USERNAME" = "yourusername" ]; then
    echo -e "${YELLOW}⚠️  Please provide your GitHub username:${NC}"
    echo "Usage: $0 <github-username>"
    echo "Example: $0 johnsmith"
    exit 1
fi

echo -e "${GREEN}Setting up Homebrew tap for GitHub user: $GITHUB_USERNAME${NC}"

# Step 1: Check if tap repository exists
echo -e "\n${BLUE}Step 1: Checking if tap repository exists...${NC}"
if curl -s -f "https://api.github.com/repos/$GITHUB_USERNAME/$TAP_REPO_NAME" > /dev/null; then
    echo -e "${GREEN}✅ Tap repository exists: https://github.com/$GITHUB_USERNAME/$TAP_REPO_NAME${NC}"
else
    echo -e "${YELLOW}⚠️  Tap repository not found. You need to create:${NC}"
    echo "   https://github.com/$GITHUB_USERNAME/$TAP_REPO_NAME"
    echo ""
    echo -e "${BLUE}Instructions:${NC}"
    echo "1. Go to https://github.com/new"
    echo "2. Create repository: $TAP_REPO_NAME"
    echo "3. Make it public"
    echo "4. Initialize with README"
    echo "5. Run this script again"
    exit 1
fi

# Step 2: Create local tap directory
echo -e "\n${BLUE}Step 2: Setting up local tap directory...${NC}"
TAP_DIR="/tmp/$TAP_REPO_NAME"
if [ -d "$TAP_DIR" ]; then
    rm -rf "$TAP_DIR"
fi

git clone "https://github.com/$GITHUB_USERNAME/$TAP_REPO_NAME.git" "$TAP_DIR"
cd "$TAP_DIR"

# Step 3: Create Formula directory and copy formula
echo -e "\n${BLUE}Step 3: Creating Homebrew formula...${NC}"
mkdir -p Formula

# Update the formula with correct URLs
FORMULA_FILE="Formula/cli-snitch.rb"
cat > "$FORMULA_FILE" << EOF
class CliSnitch < Formula
  desc "Terminal-based network connection monitor and firewall manager for macOS"
  homepage "https://github.com/$GITHUB_USERNAME/$REPO_NAME"
  url "https://github.com/$GITHUB_USERNAME/$REPO_NAME/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"
  head "https://github.com/$GITHUB_USERNAME/$REPO_NAME.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/cli-snitch"
  end

  def caveats
    <<~EOS
      CLI Snitch requires root privileges to monitor network connections and manage firewall rules.
      
      To start monitoring:
        sudo cli-snitch watch
      
      For system status:
        cli-snitch system-status
      
      Note: This tool requires macOS and uses pfctl for firewall integration.
    EOS
  end

  test do
    assert_match "CLI Snitch", shell_output("#{bin}/cli-snitch --help")
    assert_match "watch", shell_output("#{bin}/cli-snitch --help")
  end
end
EOF

# Step 4: Create README for tap
echo -e "\n${BLUE}Step 4: Creating tap README...${NC}"
cat > README.md << EOF
# $GITHUB_USERNAME Homebrew Tap

This is the official Homebrew tap for CLI Snitch and other tools by $GITHUB_USERNAME.

## Installation

\`\`\`bash
# Add the tap
brew tap $GITHUB_USERNAME/tap

# Install CLI Snitch
brew install cli-snitch
\`\`\`

## Available Formulae

- **cli-snitch**: Terminal-based network connection monitor and firewall manager for macOS

## Support

For issues with the software itself, please visit the [CLI Snitch repository](https://github.com/$GITHUB_USERNAME/$REPO_NAME).

For issues with the Homebrew formula, please open an issue in this repository.
EOF

# Step 5: Commit and push
echo -e "\n${BLUE}Step 5: Committing and pushing to GitHub...${NC}"
git add .
git commit -m "Add CLI Snitch formula"
git push origin main

echo -e "\n${GREEN}🎉 Homebrew tap setup complete!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Create a release of your CLI Snitch repository on GitHub"
echo "2. Get the SHA256 of the release tarball:"
echo "   curl -sL https://github.com/$GITHUB_USERNAME/$REPO_NAME/archive/refs/tags/v1.0.0.tar.gz | shasum -a 256"
echo "3. Update the SHA256 in the formula: $TAP_REPO_NAME/Formula/cli-snitch.rb"
echo "4. Test the formula:"
echo "   brew install --build-from-source $GITHUB_USERNAME/tap/cli-snitch"
echo ""
echo -e "${GREEN}Users can now install with:${NC}"
echo "   brew tap $GITHUB_USERNAME/tap"
echo "   brew install cli-snitch"

# Cleanup
rm -rf "$TAP_DIR"
EOF 