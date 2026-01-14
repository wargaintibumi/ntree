#!/bin/bash
#
# NTREE Autonomous Mode Deployment Script
# Sets up NTREE to run fully autonomously using Claude SDK
#
# Usage: bash deploy_autonomous.sh
#

set -e

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
echo "║         NTREE Autonomous Mode Deployment                      ║"
echo "║         Powered by Claude SDK (Anthropic API)                 ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check if running from correct directory
if [[ ! -f "ntree_agent.py" ]]; then
    log_error "Must run from ntree-autonomous directory"
    log_info "cd ~/ntree/ntree-autonomous && bash deploy_autonomous.sh"
    exit 1
fi

# Check if MCP servers are installed
if [[ ! -d "../ntree-mcp-servers" ]]; then
    log_error "NTREE MCP servers not found"
    log_info "Please install MCP servers first:"
    log_info "  cd ~/ntree && git clone <ntree-mcp-servers-repo>"
    exit 1
fi

# Install Python dependencies
log_info "Installing autonomous agent dependencies..."
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Install MCP servers as library
log_info "Installing NTREE MCP servers library..."
cd ../ntree-mcp-servers
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -e .
cd ../ntree-autonomous

log_success "Dependencies installed"

# Create configuration file
log_info "Setting up configuration..."

if [[ ! -f ~/ntree/config.json ]]; then
    log_info "Creating configuration file from template..."
    cp config.example.json ~/ntree/config.json

    log_warning "Configuration created at ~/ntree/config.json"
    log_warning "IMPORTANT: You must add your Anthropic API key!"
    echo ""
    log_info "Edit the config file:"
    echo "  ${GREEN}nano ~/ntree/config.json${NC}"
    echo ""
    log_info "Set your API key in the 'anthropic.api_key' field"
    echo ""
else
    log_info "Configuration file already exists at ~/ntree/config.json"
fi

# Create systemd service for scheduler (optional)
log_info "Creating systemd service for automated scheduling..."

SERVICE_FILE="/tmp/ntree-scheduler.service"
cat > $SERVICE_FILE << EOF
[Unit]
Description=NTREE Autonomous Penetration Testing Scheduler
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$HOME/ntree/ntree-autonomous
Environment="PATH=$HOME/ntree/ntree-autonomous/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$HOME/ntree/ntree-autonomous/venv/bin/python ntree_scheduler.py --config $HOME/ntree/config.json
Restart=on-failure
RestartSec=60
StandardOutput=append:$HOME/ntree/logs/scheduler.log
StandardError=append:$HOME/ntree/logs/scheduler_error.log

[Install]
WantedBy=multi-user.target
EOF

# Ask if user wants to install service
echo ""
log_info "Systemd service file created: $SERVICE_FILE"
read -p "Install as systemd service for automatic startup? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo cp $SERVICE_FILE /etc/systemd/system/ntree-scheduler.service
    sudo systemctl daemon-reload

    log_success "Systemd service installed"
    log_info "To enable on boot: ${GREEN}sudo systemctl enable ntree-scheduler${NC}"
    log_info "To start now: ${GREEN}sudo systemctl start ntree-scheduler${NC}"
    log_info "To check status: ${GREEN}sudo systemctl status ntree-scheduler${NC}"
else
    log_info "Service not installed. You can manually copy it later:"
    log_info "  ${GREEN}sudo cp $SERVICE_FILE /etc/systemd/system/${NC}"
fi

# Create helper scripts
log_info "Creating helper scripts..."

# Run once script
cat > ~/ntree/run_pentest.sh << 'EOF'
#!/bin/bash
# Run NTREE pentest once

SCOPE_FILE="${1:-~/ntree/templates/scope_example.txt}"
ROE_FILE="${2:-}"

cd ~/ntree/ntree-autonomous
source venv/bin/activate

python ntree_agent.py \
    --scope "$SCOPE_FILE" \
    --roe "$ROE_FILE" \
    --max-iterations 50

echo ""
echo "Pentest complete! Check ~/ntree/engagements/ for results"
EOF

chmod +x ~/ntree/run_pentest.sh

# Start scheduler script
cat > ~/ntree/start_scheduler.sh << 'EOF'
#!/bin/bash
# Start NTREE scheduler

cd ~/ntree/ntree-autonomous
source venv/bin/activate

python ntree_scheduler.py --config ~/ntree/config.json
EOF

chmod +x ~/ntree/start_scheduler.sh

# Stop scheduler script
cat > ~/ntree/stop_scheduler.sh << 'EOF'
#!/bin/bash
# Stop NTREE scheduler

sudo systemctl stop ntree-scheduler
echo "NTREE scheduler stopped"
EOF

chmod +x ~/ntree/stop_scheduler.sh

log_success "Helper scripts created"

# Test API key
log_info "Testing Anthropic API key..."

python3 << 'PYEOF'
import json
import os
import sys

config_file = os.path.expanduser("~/ntree/config.json")
if os.path.exists(config_file):
    with open(config_file) as f:
        config = json.load(f)

    api_key = config.get("anthropic", {}).get("api_key", "")

    if "YOUR_ANTHROPIC_API_KEY_HERE" in api_key or not api_key:
        print("\033[1;33m[WARNING]\033[0m API key not configured yet")
        print("Please edit ~/ntree/config.json and add your Anthropic API key")
        sys.exit(0)

    # Test API key
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)

        # Simple test
        response = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}]
        )

        print("\033[0;32m[SUCCESS]\033[0m Anthropic API key is valid!")

    except Exception as e:
        print(f"\033[0;31m[ERROR]\033[0m API key test failed: {e}")
        print("Please check your API key in ~/ntree/config.json")
        sys.exit(1)
else:
    print("\033[1;33m[WARNING]\033[0m Config file not found")
PYEOF

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║        NTREE Autonomous Mode Deployment Complete!             ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

log_info "Next Steps:"
echo ""
echo "1. Configure your Anthropic API key:"
echo "   ${GREEN}nano ~/ntree/config.json${NC}"
echo "   Set the 'anthropic.api_key' field"
echo ""
echo "2. Create a scope file for your pentest:"
echo "   ${GREEN}nano ~/ntree/templates/my_scope.txt${NC}"
echo "   Example format:"
echo "   192.168.1.0/24"
echo "   10.0.0.0/24"
echo "   EXCLUDE 192.168.1.1"
echo ""
echo "3. Run a single penetration test:"
echo "   ${GREEN}~/ntree/run_pentest.sh ~/ntree/templates/my_scope.txt${NC}"
echo ""
echo "4. Enable automated scheduling (optional):"
echo "   ${GREEN}nano ~/ntree/config.json${NC}"
echo "   Set 'automation.enabled' to true"
echo "   Configure 'automation.schedule' (cron format)"
echo "   ${GREEN}sudo systemctl enable ntree-scheduler${NC}"
echo "   ${GREEN}sudo systemctl start ntree-scheduler${NC}"
echo ""
echo "5. Monitor logs:"
echo "   ${GREEN}tail -f ~/ntree/logs/ntree_agent.log${NC}"
echo ""

log_info "Autonomous Mode Features:"
echo "  ✓ Fully automated pentesting using Claude SDK"
echo "  ✓ No human interaction required"
echo "  ✓ Scheduled recurring tests (daily/weekly/monthly)"
echo "  ✓ Automatic report generation"
echo "  ✓ All safety controls still enforced"
echo ""

log_warning "Important Security Notes:"
echo "  • Keep your API key secure (never commit to git)"
echo "  • Review scope files carefully before running"
echo "  • Monitor API usage and costs"
echo "  • All pentesting still requires proper authorization"
echo ""

deactivate 2>/dev/null || true

log_success "Deployment complete!"
