# NTREE MCP Servers

Python Model Context Protocol servers for NTREE penetration testing on Raspberry Pi 5.

## Overview

This package provides 6 specialized MCP servers that integrate security tools with Claude Code for automated penetration testing:

- **ntree-scope**: Scope validation and engagement initialization
- **ntree-scan**: Network discovery and port scanning
- **ntree-enum**: Service enumeration (SMB, web, etc.)
- **ntree-vuln**: Vulnerability testing and validation
- **ntree-post**: Post-exploitation and lateral movement analysis
- **ntree-report**: Risk scoring and report generation

## Installation

### Prerequisites

- Python 3.11 or later
- Raspberry Pi OS (64-bit) or compatible Linux
- Security tools installed (nmap, enum4linux, nikto, etc.)

### Install from Source

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/ntree-mcp-servers.git
cd ntree-mcp-servers

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package
pip install -e .
```

### Install Dependencies Only

```bash
pip install -r requirements.txt
```

## Configuration

### Claude Code Integration

Add to `~/.config/claude-code/mcp-servers.json`:

```json
{
  "mcpServers": {
    "ntree-scope": {
      "command": "/path/to/ntree-mcp-servers/venv/bin/python",
      "args": ["-m", "ntree_mcp.scope"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    },
    "ntree-scan": {
      "command": "/path/to/ntree-mcp-servers/venv/bin/python",
      "args": ["-m", "ntree_mcp.scan"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    }
  }
}
```

Add entries for all 6 servers (scope, scan, enum, vuln, post, report).

## Usage

### 1. Initialize Engagement

```python
# Via MCP (from Claude Code)
ntree-scope.init_engagement(
    scope_file="/path/to/scope.txt",
    roe_file="/path/to/roe.txt"
)
```

### 2. Verify Scope

```python
ntree-scope.verify_scope(target="192.168.1.10")
# Returns: {in_scope: true, reason: "..."}
```

### 3. Scan Network

```python
ntree-scan.scan_network(
    targets="192.168.1.0/24",
    scan_type="tcp_syn",
    intensity="normal"
)
```

### 4. Enumerate Services

```python
ntree-enum.enumerate_services(
    host="192.168.1.10",
    ports="default"
)
```

## Development

### Project Structure

```
ntree-mcp-servers/
├── ntree_mcp/
│   ├── __init__.py
│   ├── scope.py           # Scope validation server
│   ├── scan.py            # Network scanning server
│   ├── enum.py            # Service enumeration server
│   ├── vuln.py            # Vulnerability testing server
│   ├── post.py            # Post-exploitation server
│   ├── report.py          # Reporting server
│   └── utils/
│       ├── __init__.py
│       ├── logger.py      # Logging utilities
│       ├── command_runner.py  # Safe command execution
│       ├── scope_parser.py    # Scope file parsing
│       └── nmap_parser.py     # Nmap XML parsing
├── tests/
│   ├── test_scope.py
│   ├── test_scan.py
│   └── ...
├── setup.py
├── requirements.txt
└── README.md
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=ntree_mcp --cov-report=html
```

### Code Quality

```bash
# Format code
black ntree_mcp/

# Lint
ruff check ntree_mcp/

# Type checking
mypy ntree_mcp/
```

## MCP Server API Reference

### ntree-scope

**init_engagement**(scope_file, roe_file)
- Initialize engagement with scope validation
- Creates engagement directory structure
- Returns engagement_id and validated scope

**verify_scope**(target)
- Check if target is in authorized scope
- Returns boolean with explanation

### ntree-scan

**scan_network**(targets, scan_type, intensity, ports)
- Perform nmap network scan
- Returns discovered hosts and services

**passive_recon**(domain)
- DNS enumeration, subdomain discovery, WHOIS
- No direct contact with target

### ntree-enum

**enumerate_services**(host, ports)
- Detailed service version detection
- Returns service list with versions

**enumerate_web**(url, depth)
- Web application enumeration
- Technology detection, endpoint discovery

**enumerate_smb**(host)
- SMB/Windows enumeration
- Shares, users, domain information

### ntree-vuln

**test_vuln**(host, service, vuln_id, safe_mode)
- Test for specific vulnerability
- Returns exploitability status

**check_creds**(host, service, username, password, hash)
- Validate credentials
- Returns access level

**search_exploits**(service, version)
- Search exploit databases
- Returns available exploits

### ntree-post

**analyze_trust**(host, session_info)
- Map lateral movement paths
- Identify trust relationships

**extract_secrets**(host, session_info, types)
- Extract credentials/hashes
- **Requires explicit approval**

**map_privileges**(host, session_info)
- Privilege escalation opportunities
- Current user permissions

### ntree-report

**score_risk**(engagement_id)
- Calculate risk scores
- Business impact assessment

**generate_report**(engagement_id, format)
- Generate comprehensive report
- Executive + technical findings

## Security Considerations

### Scope Validation

Every action MUST be validated against scope:

```python
# Always check before targeting
is_valid, reason = verify_scope(target)
if not is_valid:
    raise ScopeViolationError(reason)
```

### Audit Logging

All actions are logged to:
- `~/ntree/logs/` - General logs
- `~/ntree/engagements/{id}/audit.log` - Engagement-specific audit trail

### Rate Limiting

Built-in protections:
- Max 3 credential attempts per account
- Adaptive scan timing
- Circuit breakers for unresponsive targets

## Troubleshooting

### MCP Server Not Starting

```bash
# Test server directly
python -m ntree_mcp.scope --version

# Check logs
tail -f ~/ntree/logs/ntree-scope_*.log
```

### Permission Errors

```bash
# Ensure sudo configured for security tools
sudo visudo /etc/sudoers.d/ntree

# Add:
pi ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

### Tool Not Found

```bash
# Verify tools installed
which nmap enum4linux nikto

# Install missing tools
sudo apt install nmap enum4linux nikto
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure code passes `black` and `ruff` checks
5. Submit pull request

## License

MIT License - See LICENSE file

## Support

- **Issues**: https://github.com/YOUR_USERNAME/ntree-mcp-servers/issues
- **Discussions**: https://github.com/YOUR_USERNAME/ntree-mcp-servers/discussions
- **Email**: ntree@example.com

## Acknowledgments

- Anthropic for Claude and MCP protocol
- Security tool authors (nmap, metasploit, impacket, etc.)
- NTREE project contributors

---

**Version**: 2.0.0
**Status**: Beta
**Python**: 3.11+
**Platform**: Raspberry Pi 5 / ARM64 Linux
