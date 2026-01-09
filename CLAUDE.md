# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NTREE (Neural Tactical Red-Team Exploitation Engine) v2.0 is a fully autonomous penetration testing platform for Raspberry Pi 5. It integrates Claude Code, Anthropic API, and MCP servers with security tools (nmap, metasploit, impacket, etc.).

## Build and Development Commands

### MCP Servers Setup
```bash
cd ntree-mcp-servers
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Autonomous Agents Setup
```bash
cd ntree-autonomous
pip install -r requirements.txt
```

### Testing
```bash
# MCP server tests
python test_servers.py

# Specific test file
pytest tests/test_scope.py -v

# With coverage
pytest tests/ --cov=ntree_mcp --cov-report=html
```

### Code Quality
```bash
black ntree_mcp/              # Format
ruff check ntree_mcp/         # Lint
mypy ntree_mcp/               # Type check
```

### Running NTREE
```bash
# Interactive mode (Claude Code + MCP)
claude
# Then: "Start NTREE with scope: ~/ntree/templates/my_scope.txt"

# Autonomous API mode
python ntree-autonomous/ntree_agent.py --scope ~/scope.txt

# Autonomous SDK mode
python ntree-autonomous/ntree_agent_sdk.py --scope ~/scope.txt
```

## Architecture

### Three Operational Modes

1. **Interactive (Claude Code + MCP)**: User controls Claude Code, which communicates with 6 MCP servers that execute security tools
2. **Autonomous API**: NTREEAgent uses Anthropic API function calling to drive security functions
3. **Autonomous SDK**: NTREEAgentSDK uses Claude Code SDK with MCP integration

### MCP Server Structure (`ntree-mcp-servers/ntree_mcp/`)

| Server | Purpose |
|--------|---------|
| `scope.py` | Scope validation, engagement initialization |
| `scan.py` | Network discovery, nmap, passive recon |
| `enum.py` | Service enumeration (web, SMB, LDAP, etc.) |
| `vuln.py` | CVE testing, credential checking, exploit research |
| `post.py` | Post-exploitation, lateral movement |
| `report.py` | Risk scoring, report generation |

Utilities in `utils/`: `scope_parser.py`, `command_runner.py`, `nmap_parser.py`, `logger.py`

### Autonomous Agents (`ntree-autonomous/`)

- `ntree_agent.py` - Direct Anthropic API mode
- `ntree_agent_sdk.py` - Claude Code SDK mode
- `ntree_scheduler.py` - Cron-based automation

## Key Patterns

### MCP Tool Pattern (all servers follow this)
```python
from mcp.server import Server
from pydantic import BaseModel, Field

app = Server("ntree-{module}")

class ToolArgs(BaseModel):
    param: str = Field(description="...")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(name="...", inputSchema=ToolArgs.model_json_schema())]

@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    args = ToolArgs(**arguments)
    result = await handler(...)
    return [TextContent(type="text", text=json.dumps(result, indent=2))]
```

### Scope Validation (defense in depth)
All MCP servers validate targets against scope before execution:
```python
if not await verify_scope(target):
    return {"status": "error", "error": "Target out of scope"}
```

### Standard Response Pattern
```python
try:
    result = await operation()
    return {"status": "success", "data": result}
except Exception as e:
    logger.error(f"Operation failed: {e}", exc_info=True)
    return {"status": "error", "error": str(e)}
```

## Safety Controls

- **Scope validation**: Every action checked against authorized targets
- **Rate limiting**: Max 3 credential attempts per account per 5 minutes
- **Safe mode**: Validation without exploitation by default
- **Approval workflow**: High-risk operations require explicit approval
- **Circuit breakers**: Unresponsive targets automatically skipped
- **Audit logging**: Complete action history with timestamps

## 7-Phase Testing Workflow

0. **Initialization** - Scope validation, engagement setup
1. **Reconnaissance** - Network discovery, OS fingerprinting
2. **Enumeration** - Service detection, versioning
3. **Attack Surface Mapping** - CVE correlation, exploit research
4. **Exploit Validation** - Safe vulnerability testing
5. **Post-Exploitation** - Credential extraction, lateral movement
6. **Reporting** - Risk scoring, documentation

## Engagement Directory Structure

```
engagements/eng_YYYYMMDD_HHMMSS/
├── scope.txt           # Authorized targets
├── roe.txt             # Rules of engagement
├── state.json          # Engagement state
├── findings/           # Discovered vulnerabilities
├── scans/              # Tool outputs (nmap XML, etc.)
└── reports/            # Generated reports (HTML, JSON)
```

## Key Configuration Files

- `ntree-mcp-servers/setup.py` - MCP package setup (Python 3.10+)
- `ntree-mcp-servers/requirements.txt` - MCP dependencies
- `ntree-autonomous/requirements.txt` - Autonomous agent dependencies
- `ntree-autonomous/config.example.json` - Configuration template
- `~/.config/claude-code/mcp-servers.json` - MCP server configuration for Claude Code

## Tech Stack

- Python 3.10+ with asyncio
- MCP Protocol for AI tool integration
- Pydantic v2.0+ for data validation
- Anthropic SDK for autonomous mode
- Security tools: nmap, metasploit, impacket, hydra, crackmapexec, etc.
