#!/bin/bash
#
# NTREE Quick Deploy for Raspberry Pi 5
# One-liner installation script
#
# Usage: curl -fsSL https://raw.githubusercontent.com/wargaintibumi/ntree/main/quick_deploy.sh | bash
# Or: wget -qO- https://raw.githubusercontent.com/wargaintibumi/ntree/main/quick_deploy.sh | bash
#

set -e

VERSION="2.0.0"
PACKAGE_URL="https://github.com/wargaintibumi/ntree/releases/download/v${VERSION}/ntree-${VERSION}-rpi5-latest.tar.gz"
CHECKSUM_URL="https://github.com/wargaintibumi/ntree/releases/download/v${VERSION}/ntree-${VERSION}-rpi5-latest.tar.gz.sha256"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         NTREE Quick Deploy for Raspberry Pi 5                 ║"
echo "║         Version: $VERSION                                      ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    log_error "This script is designed for Linux (Raspberry Pi OS)"
    exit 1
fi

# Check if running on ARM64
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" ]]; then
    log_error "This script requires ARM64 architecture (detected: $ARCH)"
    exit 1
fi

# Confirm installation
log_info "This will download and install NTREE on your Raspberry Pi"
log_info "Estimated time: 30-60 minutes"
log_info "Required disk space: ~10GB"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Installation cancelled"
    exit 0
fi

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

log_info "Downloading NTREE deployment package..."
log_info "URL: $PACKAGE_URL"

# Download package
if command -v wget &> /dev/null; then
    wget -q --show-progress "$PACKAGE_URL" -O ntree-package.tar.gz
elif command -v curl &> /dev/null; then
    curl -L --progress-bar "$PACKAGE_URL" -o ntree-package.tar.gz
else
    log_error "Neither wget nor curl found. Please install one of them."
    exit 1
fi

log_success "Package downloaded"

# Download and verify checksum
log_info "Verifying checksum..."
if command -v wget &> /dev/null; then
    wget -q "$CHECKSUM_URL" -O ntree-package.tar.gz.sha256
elif command -v curl &> /dev/null; then
    curl -sL "$CHECKSUM_URL" -o ntree-package.tar.gz.sha256
fi

if sha256sum -c ntree-package.tar.gz.sha256 &>/dev/null; then
    log_success "Checksum verified"
else
    log_error "Checksum verification failed!"
    log_error "Package may be corrupted or tampered with"
    exit 1
fi

# Extract package
log_info "Extracting package..."
tar -xzf ntree-package.tar.gz
cd ntree-*/

log_success "Package extracted"

# Run installation
log_info "Starting NTREE installation..."
echo ""

bash install_ntree_complete.sh

# Cleanup
log_info "Cleaning up temporary files..."
cd ~
rm -rf "$TEMP_DIR"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║              NTREE Quick Deploy Complete!                     ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

log_success "NTREE installed successfully!"
echo ""
log_info "Next steps:"
echo "  1. Run: ${GREEN}~/ntree/quick_start.sh${NC}"
echo "  2. Configure: ${GREEN}nano ~/ntree/config.json${NC}"
echo "  3. Test: ${GREEN}~/ntree/run_pentest.sh ~/ntree/templates/scope_example.txt${NC}"
echo ""
log_info "Documentation: ${GREEN}~/ntree/docs/${NC}"
log_info "Templates: ${GREEN}~/ntree/templates/${NC}"
echo ""

log_success "Happy hacking! 🎯"
echo ""
