#!/bin/bash
#
# NTREE Deployment Package Creator
# Creates a complete deployment package for Raspberry Pi 5
#
# Usage: bash create_deployment_package.sh
#

set -e

VERSION="2.0.0"
BUILD_DATE=$(date +%Y%m%d)
PACKAGE_NAME="ntree-${VERSION}-rpi5-${BUILD_DATE}"
BUILD_DIR="deployment_build"

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

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         NTREE Deployment Package Creator                      ║"
echo "║         Version: $VERSION                                      ║"
echo "║         Build Date: $BUILD_DATE                                ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Clean previous builds
if [[ -d "$BUILD_DIR" ]]; then
    log_info "Cleaning previous build..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory structure
log_info "Creating deployment package structure..."
mkdir -p "$BUILD_DIR/$PACKAGE_NAME"
cd "$BUILD_DIR/$PACKAGE_NAME"

# Create directory structure
mkdir -p {ntree-mcp-servers,ntree-autonomous,scripts,docs,templates,tools}

log_success "Directory structure created"

# Copy MCP servers
log_info "Copying NTREE MCP servers..."
cp -r ../../ntree-mcp-servers/* ntree-mcp-servers/ 2>/dev/null || true

# Copy autonomous mode
log_info "Copying autonomous mode files..."
cp -r ../../ntree-autonomous/* ntree-autonomous/ 2>/dev/null || true

# Copy installation scripts
log_info "Copying installation scripts..."
cp ../../scripts/*.sh scripts/ 2>/dev/null || true

# Copy documentation
log_info "Copying documentation..."
cp ../../*.md docs/ 2>/dev/null || true
cp ../../*.txt docs/ 2>/dev/null || true

# Copy templates
log_info "Creating template files..."
mkdir -p templates

# Create scope template
cat > templates/scope_example.txt << 'EOF'
# NTREE Scope File Template
# Define authorized penetration testing targets

# Network ranges (CIDR notation)
192.168.1.0/24
10.0.0.0/28

# Individual IP addresses
# 192.168.1.50
# 192.168.1.51

# Domain names
# example.com
# *.internal.example.com

# Exclusions (gateway, critical servers)
EXCLUDE 192.168.1.1
EXCLUDE 192.168.1.254

# Notes:
# - All targets must be explicitly authorized
# - Verify scope with client before testing
# - Document authorization in ROE file
EOF

# Create ROE template
cat > templates/roe_example.txt << 'EOF'
# NTREE Rules of Engagement Template

ENGAGEMENT_TYPE: internal_pentest
CLIENT: Example Corporation
AUTHORIZATION: written-authorization-2026.pdf
TESTER: NTREE Autonomous Agent
DATE: 2026-01-09

# Engagement Parameters
STEALTH_LEVEL: normal
SCAN_TIMING: -T3 (normal)
TESTING_WINDOW: 2026-01-10 to 2026-01-17

# Allowed Actions
ALLOWED_ACTIONS:
  - network_scanning
  - service_enumeration
  - vulnerability_validation
  - configuration_analysis
  - safe_mode_exploitation
  - credential_testing (limited)

# Forbidden Actions
FORBIDDEN_ACTIONS:
  - denial_of_service
  - data_destruction
  - data_exfiltration
  - social_engineering
  - physical_security_testing
  - destructive_exploitation

# Approval Required
APPROVAL_REQUIRED:
  - credential_dumping
  - active_exploitation
  - privilege_escalation
  - lateral_movement_execution

# Rate Limits
RATE_LIMITS:
  credential_attempts: 3 per account per 5 minutes
  scan_rate: normal (-T3)
  concurrent_scans: 5

# Contacts
CONTACTS:
  primary: security-team@example.com
  secondary: it-operations@example.com
  emergency: incident-response@example.com

# Notification Requirements
NOTIFICATIONS:
  - Notify before testing begins
  - Notify of critical findings immediately
  - Notify upon test completion
  - Provide preliminary findings within 24 hours

# Exclusions
CRITICAL_SYSTEMS:
  - 192.168.1.1 (gateway)
  - 192.168.1.254 (domain controller - production)
  - 192.168.1.100 (database server - production)

# Legal
This penetration test is authorized under the agreement dated
[DATE] between [TESTER] and [CLIENT]. All activities must remain
within the defined scope and rules of engagement.
EOF

# Create master installation script
log_info "Creating master installation script..."
cat > install_ntree_complete.sh << 'INSTALLEOF'
#!/bin/bash
#
# NTREE Complete Installation Script for Raspberry Pi 5
# Installs both MCP mode and Autonomous mode
#
# Usage: bash install_ntree_complete.sh [--mcp-only|--autonomous-only]
#

set -e

VERSION="2.0.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

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

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         NTREE Complete Installation                           ║"
echo "║         Neural Tactical Red-Team Exploitation Engine          ║"
echo "║         Version: $VERSION                                      ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Parse arguments
INSTALL_MODE="both"
if [[ "$1" == "--mcp-only" ]]; then
    INSTALL_MODE="mcp"
elif [[ "$1" == "--autonomous-only" ]]; then
    INSTALL_MODE="autonomous"
fi

log_info "Installation mode: $INSTALL_MODE"
echo ""

# Check if running on Raspberry Pi
check_platform() {
    log_info "Checking platform..."

    if [[ -f /proc/device-tree/model ]]; then
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
    else
        log_warning "Not running on Raspberry Pi. Continuing anyway..."
    fi
}

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
log_info "Installation directory: $SCRIPT_DIR"

# Confirm installation
echo ""
log_warning "This script will install:"
if [[ "$INSTALL_MODE" == "both" ]] || [[ "$INSTALL_MODE" == "mcp" ]]; then
    echo "  • NTREE MCP Mode (Claude Code integration)"
fi
if [[ "$INSTALL_MODE" == "both" ]] || [[ "$INSTALL_MODE" == "autonomous" ]]; then
    echo "  • NTREE Autonomous Mode (Claude SDK)"
fi
echo "  • Security tools (nmap, nikto, gobuster, etc.)"
echo "  • Python dependencies"
echo "  • Wordlists (~500MB)"
echo ""
echo "Estimated time: 30-60 minutes"
echo "Required disk space: ~10GB"
echo ""
read -p "Continue with installation? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Installation cancelled"
    exit 0
fi

check_platform

# Run base installation
if [[ "$INSTALL_MODE" == "both" ]] || [[ "$INSTALL_MODE" == "mcp" ]]; then
    log_info "Installing NTREE base system and security tools..."
    bash "$SCRIPT_DIR/scripts/install_ntree.sh"
fi

# Install MCP servers
if [[ "$INSTALL_MODE" == "both" ]] || [[ "$INSTALL_MODE" == "mcp" ]]; then
    log_info "Installing NTREE MCP servers..."

    # Copy MCP servers to ~/ntree
    mkdir -p ~/ntree
    cp -r "$SCRIPT_DIR/ntree-mcp-servers" ~/ntree/

    # Install
    cd ~/ntree/ntree-mcp-servers
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -e .
    deactivate

    log_success "MCP servers installed"
fi

# Install autonomous mode
if [[ "$INSTALL_MODE" == "both" ]] || [[ "$INSTALL_MODE" == "autonomous" ]]; then
    log_info "Installing NTREE Autonomous Mode..."

    # Copy autonomous files
    mkdir -p ~/ntree
    cp -r "$SCRIPT_DIR/ntree-autonomous" ~/ntree/

    # Deploy
    cd ~/ntree/ntree-autonomous
    bash deploy_autonomous.sh

    log_success "Autonomous mode installed"
fi

# Copy templates
log_info "Copying templates..."
mkdir -p ~/ntree/templates
cp "$SCRIPT_DIR/templates/"* ~/ntree/templates/ 2>/dev/null || true

# Create quick start script
cat > ~/ntree/quick_start.sh << 'QSEOF'
#!/bin/bash
# NTREE Quick Start Guide

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║                  NTREE Quick Start                            ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "Choose your mode:"
echo ""
echo "1) MCP Mode (Interactive with Claude Code)"
echo "   - Human in the loop"
echo "   - Great for learning and custom testing"
echo "   Start: claude"
echo ""
echo "2) Autonomous Mode (Fully automated with Claude SDK)"
echo "   - No human interaction required"
echo "   - Great for scheduled testing"
echo "   Start: ~/ntree/run_pentest.sh ~/ntree/templates/scope_example.txt"
echo ""
echo "Documentation:"
echo "  • MCP Mode: ~/ntree/docs/NTREE_CLAUDE_CODE_PROMPT.txt"
echo "  • Autonomous: ~/ntree/docs/AUTONOMOUS_MODE.md"
echo ""
echo "Templates:"
echo "  • Scope: ~/ntree/templates/scope_example.txt"
echo "  • ROE: ~/ntree/templates/roe_example.txt"
echo ""
echo "Logs:"
echo "  • MCP: ~/.claude/logs/"
echo "  • Autonomous: ~/ntree/logs/"
echo ""
QSEOF

chmod +x ~/ntree/quick_start.sh

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║              NTREE Installation Complete!                     ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

log_success "NTREE is installed in: ~/ntree"
echo ""

if [[ "$INSTALL_MODE" == "both" ]] || [[ "$INSTALL_MODE" == "mcp" ]]; then
    echo "═══════════════════════════════════════════════════════════════"
    echo "  MCP MODE (Claude Code Integration)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "1. Authenticate with Claude Code:"
    echo "   ${GREEN}claude auth login${NC}"
    echo ""
    echo "2. Configure MCP servers (if not done):"
    echo "   ${GREEN}cd ~/ntree/ntree-mcp-servers${NC}"
    echo "   ${GREEN}bash ../scripts/setup_mcp_servers.sh${NC}"
    echo ""
    echo "3. Start Claude Code:"
    echo "   ${GREEN}claude${NC}"
    echo ""
    echo "4. In Claude Code, say:"
    echo "   ${YELLOW}Start NTREE with scope: ~/ntree/templates/scope_example.txt${NC}"
    echo ""
fi

if [[ "$INSTALL_MODE" == "both" ]] || [[ "$INSTALL_MODE" == "autonomous" ]]; then
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AUTONOMOUS MODE (Claude SDK API)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "1. Get Anthropic API key:"
    echo "   ${BLUE}https://console.anthropic.com/${NC}"
    echo ""
    echo "2. Configure API key:"
    echo "   ${GREEN}nano ~/ntree/config.json${NC}"
    echo "   Set: \"api_key\": \"sk-ant-...\"${NC}"
    echo ""
    echo "3. Run autonomous pentest:"
    echo "   ${GREEN}~/ntree/run_pentest.sh ~/ntree/templates/scope_example.txt${NC}"
    echo ""
    echo "4. Enable automation (optional):"
    echo "   ${GREEN}nano ~/ntree/config.json${NC}"
    echo "   Set: automation.enabled = true"
    echo "   ${GREEN}sudo systemctl enable ntree-scheduler${NC}"
    echo "   ${GREEN}sudo systemctl start ntree-scheduler${NC}"
    echo ""
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  QUICK START"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Run: ${GREEN}~/ntree/quick_start.sh${NC}"
echo ""
echo "Documentation: ${GREEN}~/ntree/docs/${NC}"
echo ""

log_warning "Reload shell: ${GREEN}source ~/.bashrc${NC}"
echo ""
log_success "Happy hacking! 🎯"
echo ""
INSTALLEOF

chmod +x install_ntree_complete.sh

log_success "Master installation script created"

# Create verification script
log_info "Creating verification script..."
cat > verify_installation.sh << 'VERIFYEOF'
#!/bin/bash
#
# NTREE Installation Verification Script
# Checks that all components are installed correctly
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0

check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1: $(command -v $1)"
        ((PASS++))
    else
        echo -e "${RED}✗${NC} $1: Not found"
        ((FAIL++))
    fi
}

check_file() {
    if [[ -f "$1" ]]; then
        echo -e "${GREEN}✓${NC} $1"
        ((PASS++))
    else
        echo -e "${RED}✗${NC} $1: Not found"
        ((FAIL++))
    fi
}

check_directory() {
    if [[ -d "$1" ]]; then
        echo -e "${GREEN}✓${NC} $1"
        ((PASS++))
    else
        echo -e "${RED}✗${NC} $1: Not found"
        ((FAIL++))
    fi
}

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         NTREE Installation Verification                       ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "Checking security tools..."
check_command nmap
check_command nikto
check_command gobuster
check_command enum4linux
check_command crackmapexec
check_command nuclei
check_command python3

echo ""
echo "Checking Python packages..."
python3 -c "import anthropic" 2>/dev/null && echo -e "${GREEN}✓${NC} anthropic" || echo -e "${RED}✗${NC} anthropic"
python3 -c "import pydantic" 2>/dev/null && echo -e "${GREEN}✓${NC} pydantic" || echo -e "${RED}✗${NC} pydantic"
python3 -c "import nmap" 2>/dev/null && echo -e "${GREEN}✓${NC} python-nmap" || echo -e "${RED}✗${NC} python-nmap"

echo ""
echo "Checking NTREE files..."
check_directory ~/ntree
check_directory ~/ntree/engagements
check_directory ~/ntree/templates
check_directory ~/ntree/logs
check_file ~/ntree/quick_start.sh

echo ""
echo "Checking NTREE MCP servers..."
check_directory ~/ntree/ntree-mcp-servers
check_file ~/ntree/ntree-mcp-servers/ntree_mcp/scope.py
check_file ~/ntree/ntree-mcp-servers/ntree_mcp/scan.py
check_file ~/ntree/ntree-mcp-servers/ntree_mcp/enum.py
check_file ~/ntree/ntree-mcp-servers/ntree_mcp/vuln.py
check_file ~/ntree/ntree-mcp-servers/ntree_mcp/post.py
check_file ~/ntree/ntree-mcp-servers/ntree_mcp/report.py

echo ""
echo "Checking NTREE Autonomous Mode..."
check_directory ~/ntree/ntree-autonomous
check_file ~/ntree/ntree-autonomous/ntree_agent.py
check_file ~/ntree/ntree-autonomous/ntree_scheduler.py
check_file ~/ntree/config.json

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  VERIFICATION RESULTS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Passed: ${GREEN}$PASS${NC}"
echo "Failed: ${RED}$FAIL${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}✓ All checks passed! NTREE is ready to use.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run: ~/ntree/quick_start.sh"
    echo "  2. Read: ~/ntree/docs/README.md"
else
    echo -e "${YELLOW}⚠ Some checks failed. Review errors above.${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Re-run installation: bash install_ntree_complete.sh"
    echo "  2. Check logs: ~/ntree/logs/"
    echo "  3. Manual verification: ~/ntree/docs/"
fi
echo ""
VERIFYEOF

chmod +x verify_installation.sh

log_success "Verification script created"

# Create README for deployment package
log_info "Creating deployment README..."
cat > README.md << 'READMEEOF'
# NTREE Deployment Package for Raspberry Pi 5

**Version:** 2.0.0
**Platform:** Raspberry Pi 5 (ARM64)
**OS:** Raspbian/Raspberry Pi OS (64-bit)

## What's Included

This deployment package contains everything needed to run NTREE on your Raspberry Pi 5:

```
ntree-deployment/
├── install_ntree_complete.sh    # Master installation script
├── verify_installation.sh       # Verification script
│
├── ntree-mcp-servers/           # MCP Mode (Claude Code)
│   ├── ntree_mcp/               # 6 MCP servers (3,600 lines)
│   ├── setup.py                 # Package configuration
│   └── requirements.txt         # Python dependencies
│
├── ntree-autonomous/            # Autonomous Mode (Claude SDK)
│   ├── ntree_agent.py           # Main agent (850 lines)
│   ├── ntree_scheduler.py       # Scheduler (250 lines)
│   ├── deploy_autonomous.sh     # Deployment script
│   └── requirements.txt         # Python dependencies
│
├── scripts/                     # Installation scripts
│   ├── install_ntree.sh         # Base system installer
│   └── setup_mcp_servers.sh     # MCP configuration
│
├── templates/                   # Example files
│   ├── scope_example.txt        # Scope file template
│   └── roe_example.txt          # Rules of engagement template
│
└── docs/                        # Complete documentation
    ├── AUTONOMOUS_MODE.md       # Autonomous mode guide
    ├── NTREE_CLAUDE_CODE_PROMPT.txt
    └── *.md                     # All other docs
```

## Quick Start

### 1. Transfer to Raspberry Pi

```bash
# On your computer
scp ntree-*.tar.gz pi@raspberrypi:~/

# On Raspberry Pi
cd ~
tar -xzf ntree-*.tar.gz
cd ntree-*
```

### 2. Run Installation

```bash
# Install everything (MCP + Autonomous)
bash install_ntree_complete.sh

# Or install specific mode
bash install_ntree_complete.sh --mcp-only
bash install_ntree_complete.sh --autonomous-only
```

**Installation time:** 30-60 minutes
**Disk space required:** ~10GB

### 3. Verify Installation

```bash
bash verify_installation.sh
```

### 4. Get Started

```bash
~/ntree/quick_start.sh
```

## Two Modes Available

### MCP Mode (Claude Code Integration)

**Use for:** Interactive pentesting, learning, custom testing

```bash
# 1. Authenticate
claude auth login

# 2. Start Claude Code
claude

# 3. In Claude Code
"Start NTREE with scope: ~/ntree/templates/scope_example.txt"
```

### Autonomous Mode (Claude SDK API)

**Use for:** Automated testing, scheduled scans, continuous monitoring

```bash
# 1. Get API key from https://console.anthropic.com/

# 2. Configure
nano ~/ntree/config.json
# Set: "api_key": "sk-ant-..."

# 3. Run pentest
~/ntree/run_pentest.sh ~/ntree/templates/scope_example.txt
```

## System Requirements

- **Hardware:** Raspberry Pi 5 (4GB+ RAM recommended)
- **OS:** Raspbian/Raspberry Pi OS 64-bit (Bullseye or newer)
- **Network:** Internet connection for installation
- **Disk:** 10GB free space
- **Optional:** External storage for wordlists and engagement data

## Features

### Security Tools (30+)
- nmap, masscan - Network scanning
- nikto, gobuster - Web testing
- enum4linux, crackmapexec - Windows/SMB
- nuclei - Vulnerability scanning
- john, hashcat - Password cracking
- Many more...

### Penetration Testing Capabilities
- ✅ Network reconnaissance
- ✅ Service enumeration
- ✅ Vulnerability assessment
- ✅ Credential testing (rate-limited)
- ✅ Post-exploitation analysis
- ✅ Automated reporting

### Safety Features
- ✅ Scope validation
- ✅ Rate limiting
- ✅ Safe mode by default
- ✅ Approval requirements
- ✅ Complete audit logging
- ✅ Iteration limits

## Documentation

All documentation is in the `docs/` directory:

- **AUTONOMOUS_MODE.md** - Complete autonomous mode guide
- **INSTALLATION_SCRIPT_ANALYSIS.md** - Installation details
- **TEST_RESULTS.md** - Test results and verification
- **NTREE_CLAUDE_CODE_PROMPT.txt** - MCP mode system prompt
- **PI5_INSTALLATION_GUIDE.md** - Raspberry Pi specific guide

## Support

### Troubleshooting

```bash
# Check installation
bash verify_installation.sh

# View logs
tail -f ~/ntree/logs/ntree_agent.log

# Test tools
nmap --version
python3 -c "import anthropic; print('OK')"
```

### Common Issues

**Problem:** Package installation fails
**Solution:** Ensure internet connection, try `sudo apt update`

**Problem:** Python version too old
**Solution:** Install Python 3.10+ from deadsnakes PPA

**Problem:** Claude Code not found
**Solution:** Install manually: `curl -fsSL https://claude.ai/install-cli.sh | bash`

### Getting Help

- Check `~/ntree/logs/` for error messages
- Review documentation in `docs/`
- Verify all tools installed: `verify_installation.sh`

## Security & Legal

⚠️ **CRITICAL WARNINGS**:

- **Get Written Authorization** before testing any systems
- **Stay Within Scope** - Only test explicitly authorized targets
- **Secure API Keys** - Never commit to version control
- **Monitor Costs** - Check API usage regularly
- **Legal Compliance** - Follow all applicable laws and regulations

## What's Next?

After installation:

1. ✅ Run `~/ntree/quick_start.sh` for guided tour
2. ✅ Review `~/ntree/docs/` documentation
3. ✅ Customize `~/ntree/templates/` for your needs
4. ✅ Run test pentest on authorized targets
5. ✅ Enable automation if using autonomous mode

## Version Information

- **NTREE Version:** 2.0.0
- **MCP Servers:** 6 servers, 3,600+ lines of code
- **Autonomous Agent:** 1,100+ lines of code
- **Documentation:** 15,000+ words
- **Total Package Size:** ~50MB (compressed)
- **Installed Size:** ~10GB (with tools and wordlists)

## License

MIT License - See individual files for details

---

**Built for:** Raspberry Pi 5
**Tested on:** Raspbian 64-bit (Bullseye)
**Last Updated:** 2026-01-09
READMEEOF

log_success "Deployment README created"

# Create version file
cat > VERSION << EOF
NTREE Deployment Package
Version: $VERSION
Build Date: $BUILD_DATE
Platform: Raspberry Pi 5 (ARM64)
OS: Raspbian/Raspberry Pi OS 64-bit

Components:
- NTREE MCP Servers: 6 servers, 3,600+ lines
- NTREE Autonomous Agent: 1,100+ lines
- Security Tools: 30+ tools
- Documentation: 15,000+ words

Modes:
- MCP Mode (Claude Code integration)
- Autonomous Mode (Claude SDK API)

Installation:
bash install_ntree_complete.sh

Verification:
bash verify_installation.sh
EOF

log_success "Version file created"

# Create checksums
log_info "Generating checksums..."
find . -type f -exec sha256sum {} \; > CHECKSUMS.txt
log_success "Checksums generated"

# Go back to build directory
cd ..

# Create tarball
log_info "Creating deployment package..."
tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"

# Calculate package size
PACKAGE_SIZE=$(du -h "${PACKAGE_NAME}.tar.gz" | cut -f1)

log_success "Deployment package created: ${PACKAGE_NAME}.tar.gz"
log_info "Package size: $PACKAGE_SIZE"

# Create checksum for package
sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║         Deployment Package Created Successfully!              ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

log_success "Package: ${GREEN}${BUILD_DIR}/${PACKAGE_NAME}.tar.gz${NC}"
log_info "Size: ${PACKAGE_SIZE}"
log_info "SHA256: ${BUILD_DIR}/${PACKAGE_NAME}.tar.gz.sha256"
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo "  DEPLOYMENT INSTRUCTIONS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "1. Transfer to Raspberry Pi:"
echo "   ${GREEN}scp ${BUILD_DIR}/${PACKAGE_NAME}.tar.gz pi@raspberrypi:~/${NC}"
echo ""
echo "2. On Raspberry Pi, extract:"
echo "   ${GREEN}tar -xzf ${PACKAGE_NAME}.tar.gz${NC}"
echo "   ${GREEN}cd ${PACKAGE_NAME}${NC}"
echo ""
echo "3. Run installation:"
echo "   ${GREEN}bash install_ntree_complete.sh${NC}"
echo ""
echo "4. Verify installation:"
echo "   ${GREEN}bash verify_installation.sh${NC}"
echo ""
echo "5. Get started:"
echo "   ${GREEN}~/ntree/quick_start.sh${NC}"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

log_info "Contents:"
echo "  • NTREE MCP Servers (6 servers)"
echo "  • NTREE Autonomous Agent"
echo "  • Installation scripts"
echo "  • Complete documentation"
echo "  • Template files"
echo "  • Verification tools"
echo ""

log_success "Ready for deployment! 🚀"
echo ""
