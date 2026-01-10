#!/bin/bash
#
# NTREE Installation Script for Raspberry Pi 5
# This script automates the installation of NTREE and all required security tools
#
# Usage: bash install_ntree.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Raspberry Pi
check_platform() {
    log_info "Checking platform..."

    if [[ ! -f /proc/device-tree/model ]]; then
        log_warning "Not running on Raspberry Pi. Continuing anyway..."
        return
    fi

    MODEL=$(cat /proc/device-tree/model)
    if [[ $MODEL == *"Raspberry Pi 5"* ]]; then
        log_success "Detected: $MODEL"
    else
        log_warning "Expected Raspberry Pi 5, detected: $MODEL"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Update system
update_system() {
    log_info "Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
    log_success "System updated"
}

# Install base dependencies
install_base_deps() {
    log_info "Installing base dependencies..."

    sudo apt install -y \
        build-essential \
        git \
        curl \
        wget \
        python3-pip \
        python3-venv \
        libssl-dev \
        libffi-dev \
        python3-dev \
        cargo \
        jq \
        unzip

    log_success "Base dependencies installed"
}

# Install Claude Code
install_claude_code() {
    log_info "Installing Claude Code..."

    if command -v claude &> /dev/null; then
        log_warning "Claude Code already installed"
        claude --version
        return
    fi

    # Download and install Claude Code
    curl -fsSL https://claude.ai/install-cli.sh | bash

    # Verify installation
    if command -v claude &> /dev/null; then
        log_success "Claude Code installed successfully"
        claude --version
    else
        log_error "Claude Code installation failed"
        exit 1
    fi

    log_warning "Please run 'claude auth login' to authenticate"
}

# Install security tools
install_security_tools() {
    log_info "Installing security tools (this may take 15-30 minutes)..."

    # Network scanning tools
    log_info "Installing network scanning tools..."
    sudo apt install -y nmap masscan

    # DNS tools
    log_info "Installing DNS enumeration tools..."
    sudo apt install -y dnsenum dnsutils

    # SMB/Windows tools
    log_info "Installing SMB/Windows tools..."
    sudo apt install -y enum4linux smbclient cifs-utils

    # Web tools
    log_info "Installing web security tools..."
    sudo apt install -y nikto dirb gobuster

    # Other tools
    log_info "Installing additional tools..."
    sudo apt install -y hydra john hashcat crackmapexec theharvester

    log_success "Core security tools installed"
}

# Install nuclei
install_nuclei() {
    log_info "Installing nuclei vulnerability scanner..."

    if command -v nuclei &> /dev/null; then
        log_warning "Nuclei already installed"
        return
    fi

    # Detect architecture
    ARCH=$(uname -m)
    if [[ $ARCH == "aarch64" ]]; then
        NUCLEI_ARCH="arm64"
    else
        log_error "Unsupported architecture: $ARCH"
        return
    fi

    # Get latest version
    NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name | sed 's/v//')

    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" -O /tmp/nuclei.zip

    unzip -q /tmp/nuclei.zip -d /tmp/
    sudo mv /tmp/nuclei /usr/local/bin/
    sudo chmod +x /usr/local/bin/nuclei
    rm /tmp/nuclei.zip

    # Update templates
    nuclei -update-templates

    log_success "Nuclei installed"
}

# Install testssl.sh
install_testssl() {
    log_info "Installing testssl.sh..."

    mkdir -p ~/tools

    if [[ -d ~/tools/testssl ]]; then
        log_warning "testssl.sh already installed"
        cd ~/tools/testssl && git pull
        cd -
        return
    fi

    git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl
    chmod +x ~/tools/testssl/testssl.sh

    # Add to PATH
    if ! grep -q "tools/testssl" ~/.bashrc; then
        echo 'export PATH="$HOME/tools/testssl:$PATH"' >> ~/.bashrc
    fi

    log_success "testssl.sh installed"
}

# Install Python security tools
install_python_tools() {
    log_info "Installing Python security tools..."

    # Create virtual environment
    if [[ ! -d ~/venvs/sectools ]]; then
        python3 -m venv ~/venvs/sectools
    fi

    source ~/venvs/sectools/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    # Install tools
    log_info "Installing impacket..."
    pip install impacket

    log_info "Installing other Python tools..."
    pip install ldap3 pycryptodome requests beautifulsoup4 xmltodict aiofiles

    deactivate

    # Add alias
    if ! grep -q "ntree-env" ~/.bashrc; then
        echo 'alias ntree-env="source ~/venvs/sectools/bin/activate"' >> ~/.bashrc
    fi

    log_success "Python security tools installed"
}

# Install wordlists
install_wordlists() {
    log_info "Installing wordlists (SecLists and RockYou)..."

    mkdir -p ~/wordlists

    # Install SecLists - Required for NTREE wordlist functionality
    if [[ -d ~/wordlists/SecLists ]]; then
        log_warning "SecLists already installed, updating..."
        cd ~/wordlists/SecLists && git pull
        cd -
    else
        log_info "Cloning SecLists from danielmiessler (this may take 5-10 minutes)..."
        log_info "Repository: https://github.com/danielmiessler/SecLists.git"
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists

        if [[ $? -eq 0 ]]; then
            log_success "SecLists cloned successfully"
            log_info "SecLists location: ~/wordlists/SecLists"
        else
            log_error "Failed to clone SecLists. NTREE wordlist features will not work."
            log_info "You can manually install later: git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists"
        fi
    fi

    # Download rockyou if not exists
    if [[ ! -f ~/wordlists/rockyou.txt ]]; then
        log_info "Downloading rockyou wordlist..."
        wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O ~/wordlists/rockyou.txt

        if [[ $? -eq 0 ]]; then
            log_success "RockYou wordlist downloaded"
        else
            log_warning "Failed to download rockyou wordlist"
        fi
    fi

    # Add environment variable for wordlists path
    if ! grep -q "NTREE_WORDLISTS_PATH" ~/.bashrc; then
        echo 'export NTREE_WORDLISTS_PATH="$HOME/wordlists"' >> ~/.bashrc
        echo 'export SECLISTS_PATH="$HOME/wordlists/SecLists"' >> ~/.bashrc
    fi

    log_success "Wordlists installed"
    log_info "SecLists path: ~/wordlists/SecLists"
    log_info "Environment variables added to ~/.bashrc"
}

# Set up NTREE directory structure
setup_ntree_structure() {
    log_info "Setting up NTREE directory structure..."

    mkdir -p ~/ntree/{engagements,templates,tools,logs}

    # Create example scope file
    cat > ~/ntree/templates/scope_example.txt << 'EOF'
# Target Network Ranges (CIDR notation)
192.168.1.0/24

# Individual IPs
# 192.168.1.50

# Domains
# example.com
# *.internal.example.com

# Forbidden/Excluded
# Format: EXCLUDE <ip or range>
EXCLUDE 192.168.1.1
EOF

    # Create example ROE file
    cat > ~/ntree/templates/roe_example.txt << 'EOF'
# Rules of Engagement

ENGAGEMENT_TYPE: internal_pentest
STEALTH_LEVEL: normal
AUTHORIZATION: written_authorization_required.pdf

ALLOWED_ACTIONS:
  - network_scanning
  - service_enumeration
  - vulnerability_testing
  - safe_exploitation
  - credential_testing (max 3 attempts)

FORBIDDEN_ACTIONS:
  - denial_of_service
  - data_deletion
  - data_exfiltration
  - social_engineering

APPROVAL_REQUIRED:
  - credential_dumping
  - privilege_escalation
  - exploitation

RATE_LIMITS:
  - credential_attempts: 3 per account
  - scan_timing: -T3 (normal)

CONTACTS:
  - primary: security-team@example.com
EOF

    chmod 600 ~/ntree/templates/*.txt

    log_success "NTREE directory structure created"
}

# Configure sudo for security tools
configure_sudo() {
    log_info "Configuring sudo for security tools..."

    SUDOERS_FILE="/etc/sudoers.d/ntree"
    USERNAME=$(whoami)

    sudo bash -c "cat > $SUDOERS_FILE" << EOF
# NTREE security tools - NOPASSWD for specific commands
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/nmap
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/masscan
$USERNAME ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump
EOF

    sudo chmod 440 $SUDOERS_FILE

    log_success "Sudo configuration complete"
}

# Create helper scripts
create_helper_scripts() {
    log_info "Creating helper scripts..."

    # Create activation script
    cat > ~/ntree/activate.sh << 'EOF'
#!/bin/bash
# Activate NTREE environment

# Activate Python virtual environment
source ~/venvs/sectools/bin/activate

# Add tools to PATH
export PATH="$HOME/tools/testssl:$PATH"

# Set NTREE home
export NTREE_HOME="$HOME/ntree"

# Set wordlist paths
export NTREE_WORDLISTS_PATH="$HOME/wordlists"
export SECLISTS_PATH="$HOME/wordlists/SecLists"

echo "NTREE environment activated"
echo "Python venv: $(which python)"
echo "NTREE_HOME: $NTREE_HOME"
echo "SecLists: $SECLISTS_PATH"
EOF

    chmod +x ~/ntree/activate.sh

    # Create backup script
    cat > ~/ntree/backup_engagement.sh << 'EOF'
#!/bin/bash
# Backup NTREE engagement

if [ -z "$1" ]; then
    echo "Usage: $0 <engagement_id>"
    exit 1
fi

ENGAGEMENT_ID=$1
BACKUP_DIR="$HOME/ntree/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

if [ ! -d "$HOME/ntree/engagements/$ENGAGEMENT_ID" ]; then
    echo "Error: Engagement $ENGAGEMENT_ID not found"
    exit 1
fi

tar -czf "$BACKUP_DIR/${ENGAGEMENT_ID}_${DATE}.tar.gz" \
    -C "$HOME/ntree/engagements" "$ENGAGEMENT_ID"

echo "Backup created: $BACKUP_DIR/${ENGAGEMENT_ID}_${DATE}.tar.gz"
EOF

    chmod +x ~/ntree/backup_engagement.sh

    # Create cleanup script
    cat > ~/ntree/cleanup_temp.sh << 'EOF'
#!/bin/bash
# Clean up temporary NTREE files

echo "Cleaning up temporary files..."

# Remove old temp files
find /tmp -name "ntree_*" -mtime +1 -delete 2>/dev/null
find /tmp -name "nmap_*.xml" -mtime +1 -delete 2>/dev/null

# Clean up old logs
find ~/ntree/logs -name "*.log" -mtime +30 -delete 2>/dev/null

echo "Cleanup complete"
EOF

    chmod +x ~/ntree/cleanup_temp.sh

    log_success "Helper scripts created"
}

# Display next steps
show_next_steps() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║              NTREE Installation Complete!                     ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "Next Steps:"
    echo ""
    echo "1. Authenticate with Claude Code:"
    echo "   ${GREEN}claude auth login${NC}"
    echo ""
    echo "2. Install NTREE MCP Servers:"
    echo "   ${GREEN}cd ~/ntree${NC}"
    echo "   ${GREEN}git clone https://github.com/YOUR_USERNAME/ntree-mcp-servers.git${NC}"
    echo "   ${GREEN}cd ntree-mcp-servers${NC}"
    echo "   ${GREEN}python3 -m venv venv && source venv/bin/activate${NC}"
    echo "   ${GREEN}pip install -e .${NC}"
    echo ""
    echo "3. Configure Claude Code MCP servers:"
    echo "   ${GREEN}nano ~/.config/claude-code/mcp-servers.json${NC}"
    echo ""
    echo "4. Copy NTREE system prompt to Claude Code:"
    echo "   ${GREEN}mkdir -p ~/.config/claude-code/prompts${NC}"
    echo "   ${GREEN}cp NTREE_CLAUDE_CODE_PROMPT.txt ~/.config/claude-code/prompts/ntree.txt${NC}"
    echo ""
    echo "5. Activate NTREE environment:"
    echo "   ${GREEN}source ~/ntree/activate.sh${NC}"
    echo ""
    echo "6. Test installation:"
    echo "   ${GREEN}nmap --version${NC}"
    echo "   ${GREEN}nuclei -version${NC}"
    echo "   ${GREEN}crackmapexec --version${NC}"
    echo ""
    echo "7. Start Claude Code and activate NTREE:"
    echo "   ${GREEN}claude${NC}"
    echo "   Type: ${YELLOW}Start NTREE with scope: ~/ntree/templates/scope_example.txt${NC}"
    echo ""
    log_info "NTREE Directory: ${GREEN}~/ntree${NC}"
    log_info "Templates: ${GREEN}~/ntree/templates/${NC}"
    log_info "Engagements: ${GREEN}~/ntree/engagements/${NC}"
    log_info "Wordlists (SecLists): ${GREEN}~/wordlists/SecLists${NC}"
    echo ""
    log_info "Wordlist Capabilities:"
    echo "   - Search SecLists by keyword: ${YELLOW}search_wordlists${NC}"
    echo "   - Access passwords, usernames, subdomains, fuzzing lists"
    echo "   - ${GREEN}~/wordlists/SecLists${NC} contains 1000+ curated wordlists"
    echo ""
    log_warning "Reload your shell or run: ${GREEN}source ~/.bashrc${NC}"
    echo ""
}

# Main installation flow
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║      NTREE - Neural Tactical Red-Team Exploitation Engine     ║"
    echo "║           Raspberry Pi 5 Installation Script                  ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    log_warning "This script will install NTREE and security tools"
    log_warning "Estimated installation time: 30-60 minutes"
    echo ""
    read -p "Continue with installation? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi

    echo ""
    log_info "Starting installation..."
    echo ""

    check_platform
    update_system
    install_base_deps
    install_claude_code
    install_security_tools
    install_nuclei
    install_testssl
    install_python_tools
    install_wordlists
    setup_ntree_structure
    configure_sudo
    create_helper_scripts

    log_success "All components installed successfully!"

    show_next_steps
}

# Run main function
main
