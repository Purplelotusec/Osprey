#!/usr/bin/env bash
# Osprey (cra) CLI Installer
# Usage: curl -fsSL https://purplelotus.space/install-osprey.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/purplelotus/osprey.git"
INSTALL_DIR="$HOME/.osprey"
BIN_DIR="$HOME/.local/bin"

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command_exists node; then
        log_error "Node.js is not installed. Please install Node.js 18+ first."
        log_info "Visit: https://nodejs.org/"
        exit 1
    fi

    local node_version=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$node_version" -lt 18 ]; then
        log_error "Node.js version 18 or higher is required. You have: $(node -v)"
        exit 1
    fi

    if ! command_exists npm; then
        log_error "npm is not installed. Please install npm first."
        exit 1
    fi

    if ! command_exists git; then
        log_error "git is not installed. Please install git first."
        exit 1
    fi

    log_info "All prerequisites met!"
}

# Clone or update repository
setup_repository() {
    log_info "Setting up Osprey repository..."

    if [ -d "$INSTALL_DIR" ]; then
        log_warn "Osprey is already installed at $INSTALL_DIR"
        read -p "Do you want to update it? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Updating Osprey..."
            cd "$INSTALL_DIR"
            git pull origin main
        else
            log_info "Skipping update."
            return
        fi
    else
        log_info "Cloning Osprey repository..."
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
}

# Install dependencies and build
build_project() {
    log_info "Installing dependencies..."
    cd "$INSTALL_DIR"
    npm install --production

    log_info "Building Osprey..."
    npm run build
}

# Create symlinks
create_symlinks() {
    log_info "Creating command-line symlinks..."

    mkdir -p "$BIN_DIR"

    # Create cra symlink
    ln -sf "$INSTALL_DIR/dist/cli/audit.js" "$BIN_DIR/cra"
    chmod +x "$INSTALL_DIR/dist/cli/audit.js"

    # Create osprey symlink (alias)
    ln -sf "$INSTALL_DIR/dist/cli/audit.js" "$BIN_DIR/osprey"

    log_info "Symlinks created:"
    log_info "  cra -> $INSTALL_DIR/dist/cli/audit.js"
    log_info "  osprey -> $INSTALL_DIR/dist/cli/audit.js"
}

# Update PATH if needed
update_path() {
    local shell_rc=""

    if [ -n "$BASH_VERSION" ]; then
        shell_rc="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        shell_rc="$HOME/.zshrc"
    else
        shell_rc="$HOME/.profile"
    fi

    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        log_warn "$BIN_DIR is not in your PATH"
        log_info "Adding to $shell_rc"

        echo "" >> "$shell_rc"
        echo "# Added by Osprey installer" >> "$shell_rc"
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$shell_rc"

        log_info "Please run: source $shell_rc"
        log_info "Or restart your terminal"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    if [ -f "$BIN_DIR/cra" ]; then
        log_info "Installation successful!"
        echo ""
        log_info "Osprey CLI is now available as 'cra' and 'osprey'"
        log_info "Installation directory: $INSTALL_DIR"
        log_info "Binary directory: $BIN_DIR"
        echo ""
        log_info "Try running: cra --help"
    else
        log_error "Installation failed. Symlink not created."
        exit 1
    fi
}

# Uninstall function
uninstall() {
    log_info "Uninstalling Osprey..."

    rm -f "$BIN_DIR/cra"
    rm -f "$BIN_DIR/osprey"
    rm -rf "$INSTALL_DIR"

    log_info "Osprey has been uninstalled."
    log_info "You may want to remove the PATH entry from your shell configuration."
}

# Main installation flow
main() {
    echo ""
    echo "╔═══════════════════════════════════════════╗"
    echo "║   Osprey (cra) CLI Installer              ║"
    echo "║   SBOM Security & KEV Vulnerability       ║"
    echo "╚═══════════════════════════════════════════╝"
    echo ""

    # Check if uninstall flag is passed
    if [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
        uninstall
        exit 0
    fi

    check_prerequisites
    setup_repository
    build_project
    create_symlinks
    update_path
    verify_installation

    echo ""
    log_info "Installation complete! 🎉"
    echo ""
    echo "Quick start:"
    echo "  cra --path .              # Audit current project"
    echo "  cra --url owner/repo      # Audit GitHub repository"
    echo "  cra --help                # Show all options"
    echo ""
    echo "Supported ecosystems:"
    echo "  - JavaScript/TypeScript (npm)"
    echo "  - Python (PyPI)"
    echo "  - Java (Maven)"
    echo "  - Rust (Crates.io)"
    echo "  - .NET (NuGet)"
    echo "  - Ruby (RubyGems)"
    echo ""
}

# Handle script interruption
trap 'log_error "Installation interrupted"; exit 130' INT

# Run main function
main "$@"
