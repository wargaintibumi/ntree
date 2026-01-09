#!/bin/bash
#
# NTREE MCP Servers Setup Script
# Sets up the MCP servers for Claude Code integration
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

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Clone or update MCP servers repository
setup_mcp_repo() {
    log_info "Setting up NTREE MCP servers repository..."

    cd ~/ntree

    if [[ -d ntree-mcp-servers ]]; then
        log_info "Repository exists, updating..."
        cd ntree-mcp-servers
        git pull
    else
        log_info "Cloning repository..."
        read -p "Enter GitHub repository URL: " REPO_URL
        if [[ -z "$REPO_URL" ]]; then
            log_error "Repository URL required"
            exit 1
        fi
        git clone "$REPO_URL" ntree-mcp-servers
        cd ntree-mcp-servers
    fi

    log_success "Repository ready"
}

# Create virtual environment and install dependencies
install_dependencies() {
    log_info "Installing MCP server dependencies..."

    if [[ ! -d venv ]]; then
        python3 -m venv venv
    fi

    source venv/bin/activate

    pip install --upgrade pip
    pip install -e .

    log_success "Dependencies installed"
}

# Configure Claude Code MCP servers
configure_claude_code() {
    log_info "Configuring Claude Code MCP servers..."

    mkdir -p ~/.config/claude-code

    MCP_CONFIG=~/.config/claude-code/mcp-servers.json
    NTREE_MCP_PATH="$HOME/ntree/ntree-mcp-servers"

    # Backup existing config
    if [[ -f "$MCP_CONFIG" ]]; then
        cp "$MCP_CONFIG" "${MCP_CONFIG}.backup"
        log_info "Backed up existing config to ${MCP_CONFIG}.backup"
    fi

    # Create new config
    cat > "$MCP_CONFIG" << EOF
{
  "mcpServers": {
    "ntree-scope": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.scope"],
      "env": {
        "NTREE_HOME": "$HOME/ntree",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-scan": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.scan"],
      "env": {
        "NTREE_HOME": "$HOME/ntree",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-enum": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.enum"],
      "env": {
        "NTREE_HOME": "$HOME/ntree",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-vuln": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.vuln"],
      "env": {
        "NTREE_HOME": "$HOME/ntree",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-post": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.post"],
      "env": {
        "NTREE_HOME": "$HOME/ntree",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-report": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.report"],
      "env": {
        "NTREE_HOME": "$HOME/ntree",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    }
  }
}
EOF

    log_success "Claude Code MCP configuration created: $MCP_CONFIG"
}

# Test MCP servers
test_mcp_servers() {
    log_info "Testing MCP servers..."

    source venv/bin/activate

    # Test each server
    SERVERS=("scope" "scan" "enum" "vuln" "post" "report")

    for server in "${SERVERS[@]}"; do
        log_info "Testing ntree-${server}..."
        if python -m "ntree_mcp.${server}" --version 2>/dev/null; then
            log_success "ntree-${server} OK"
        else
            log_error "ntree-${server} test failed"
        fi
    done

    deactivate
}

# Copy system prompt
copy_system_prompt() {
    log_info "Setting up NTREE system prompt..."

    mkdir -p ~/.config/claude-code/prompts

    PROMPT_SOURCE="$HOME/ntree/NTREE_CLAUDE_CODE_PROMPT.txt"
    PROMPT_DEST="$HOME/.config/claude-code/prompts/ntree.txt"

    if [[ -f "$PROMPT_SOURCE" ]]; then
        cp "$PROMPT_SOURCE" "$PROMPT_DEST"
        log_success "System prompt copied to $PROMPT_DEST"
    else
        log_error "System prompt not found at $PROMPT_SOURCE"
        log_info "Please copy NTREE_CLAUDE_CODE_PROMPT.txt to $PROMPT_DEST manually"
    fi
}

# Main
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║         NTREE MCP Servers Setup for Claude Code               ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    setup_mcp_repo
    install_dependencies
    configure_claude_code
    test_mcp_servers
    copy_system_prompt

    echo ""
    log_success "MCP servers setup complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Restart Claude Code if running"
    echo "  2. Test MCP servers: ${GREEN}claude${NC}"
    echo "  3. In Claude Code, type: ${YELLOW}Start NTREE mode${NC}"
    echo ""
}

main
