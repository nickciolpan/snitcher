# Homebrew Distribution Guide for CLI Snitch

This guide explains how to distribute CLI Snitch via Homebrew, making it easy for users to install with a simple `brew install` command.

## Overview

Homebrew distribution involves:
1. Creating a Homebrew formula (Ruby file describing how to build/install)
2. Setting up a Homebrew tap (custom repository for your formulae)
3. Creating GitHub releases with source code
4. Automating the process with GitHub Actions

## Quick Setup

### Option 1: Automated Setup (Recommended)

Use the provided script to set up your Homebrew tap automatically:

```bash
# Run the setup script with your GitHub username
./scripts/setup-homebrew-tap.sh your-github-username
```

This script will:
- Check if your `homebrew-tap` repository exists
- Create the Homebrew formula with correct URLs
- Set up the tap repository structure
- Provide next steps

### Option 2: Manual Setup

1. **Create a homebrew-tap repository**:
   - Go to https://github.com/new
   - Create repository: `homebrew-tap`
   - Make it public
   - Initialize with README

2. **Clone and set up the tap**:
   ```bash
   git clone https://github.com/yourusername/homebrew-tap.git
   cd homebrew-tap
   mkdir Formula
   ```

3. **Copy the formula**:
   ```bash
   cp ../cli-snitch/Formula/cli-snitch.rb Formula/
   ```

4. **Update URLs in the formula**:
   Edit `Formula/cli-snitch.rb` and replace:
   - `yourusername` with your GitHub username
   - `REPLACE_WITH_ACTUAL_SHA256` with the actual SHA256 (see below)

## Creating Releases

### Automated Releases (GitHub Actions)

The repository includes a GitHub Actions workflow that automatically:
- Builds binaries for Intel and Apple Silicon Macs
- Creates release packages
- Uploads release assets
- Generates checksums

To trigger a release:
```bash
git tag -a v1.0.1 -m "Release v1.0.1"
git push origin v1.0.1
```

### Manual Releases

1. **Build release packages**:
   ```bash
   make package
   ```

2. **Generate SHA256**:
   ```bash
   make sha256
   ```

3. **Update formula with SHA256**:
   - Copy the generated SHA256
   - Update your `homebrew-tap/Formula/cli-snitch.rb`
   - Replace `REPLACE_WITH_ACTUAL_SHA256` with the actual value

4. **Create GitHub release**:
   - Go to your repository's releases page
   - Create a new release with tag `v1.0.1`
   - Upload the generated packages from `build/packages/`

## Testing Your Formula

### Local Testing

Test the formula locally before publishing:

```bash
# Test building from source
brew install --build-from-source ./Formula/cli-snitch.rb

# Test the installed binary
cli-snitch --help

# Uninstall for clean testing
brew uninstall cli-snitch
```

### Test with Tap

Test the complete user experience:

```bash
# Add your tap
brew tap yourusername/tap

# Install from tap
brew install cli-snitch

# Test functionality
cli-snitch system-status
```

## Publishing Process

### Complete Checklist

- [ ] Repository is public on GitHub
- [ ] Created `homebrew-tap` repository
- [ ] Updated formula with correct GitHub username
- [ ] Created and pushed a git tag (e.g., `v1.0.0`)
- [ ] GitHub Actions created release (or manual release created)
- [ ] Updated formula with correct SHA256
- [ ] Tested formula locally
- [ ] Tested complete tap installation

### User Installation Commands

Once everything is set up, users can install with:

```bash
# Add your tap
brew tap yourusername/tap

# Install CLI Snitch
brew install cli-snitch

# Use CLI Snitch
sudo cli-snitch watch
```

## Updating the Formula

When you release a new version:

1. **Create new release**:
   ```bash
   git tag -a v1.0.2 -m "Release v1.0.2"
   git push origin v1.0.2
   ```

2. **Update formula**:
   ```bash
   # Get new SHA256
   curl -sL https://github.com/yourusername/cli-snitch/archive/refs/tags/v1.0.2.tar.gz | shasum -a 256
   
   # Update Formula/cli-snitch.rb with:
   # - New version number in URL
   # - New SHA256
   ```

3. **Test and commit**:
   ```bash
   brew install --build-from-source ./Formula/cli-snitch.rb
   git add Formula/cli-snitch.rb
   git commit -m "Update cli-snitch to v1.0.2"
   git push origin main
   ```

## Advanced Features

### Version Pinning

Users can install specific versions:
```bash
brew install yourusername/tap/cli-snitch@1.0.0
```

### Development Builds

Users can install the latest development version:
```bash
brew install --HEAD yourusername/tap/cli-snitch
```

### Formula Variants

You can create variants for different build options by modifying the formula:

```ruby
class CliSnitch < Formula
  desc "Terminal-based network connection monitor"
  # ... existing content ...
  
  option "with-debug", "Build with debug symbols"
  
  def install
    ldflags = "-s -w"
    ldflags = "" if build.with? "debug"
    
    system "go", "build", "-ldflags", ldflags, "-o", bin/"cli-snitch", "./cmd/cli-snitch"
  end
end
```

## Troubleshooting

### Common Issues

1. **Formula fails to build**:
   - Check Go version requirements
   - Verify all dependencies are available
   - Test build locally first

2. **SHA256 mismatch**:
   - Ensure you're using the tarball SHA256, not the git commit
   - Download and verify: `curl -sL <url> | shasum -a 256`

3. **Permission errors**:
   - Ensure repository is public
   - Check GitHub token permissions for actions

### Getting Help

- Test locally before publishing
- Use `brew --debug install` for detailed error messages
- Check Homebrew documentation: https://docs.brew.sh/Formula-Cookbook

## Example Commands Summary

```bash
# Setup (one-time)
./scripts/setup-homebrew-tap.sh yourusername

# Release new version
git tag -a v1.0.1 -m "Release v1.0.1"
git push origin v1.0.1

# Update formula
curl -sL https://github.com/yourusername/cli-snitch/archive/refs/tags/v1.0.1.tar.gz | shasum -a 256
# Update Formula/cli-snitch.rb with new SHA256

# Test
brew install --build-from-source ./Formula/cli-snitch.rb

# User installation
brew tap yourusername/tap
brew install cli-snitch
```

This setup provides a professional distribution method that makes CLI Snitch easily accessible to macOS users. 