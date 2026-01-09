# NTREE Autonomous Modes - API vs SDK

**Version:** 2.0.0 | **Date:** 2026-01-09

---

## Overview

NTREE Autonomous Agent offers two implementation modes, each optimized for different use cases:

1. **API Mode** (`ntree_agent.py`) - Direct Anthropic API with function calling
2. **SDK Mode** (`ntree_agent_sdk.py`) - Claude Code SDK with full MCP integration

---

## Quick Comparison

| Feature | API Mode | SDK Mode |
|---------|----------|----------|
| **Implementation** | Direct Anthropic API | claude-code-sdk library |
| **Tool Integration** | Manual function definitions | MCP servers via mcp__ prefix |
| **Architecture** | Function calling | Session-based with working dirs |
| **Setup Complexity** | Simple | Moderate |
| **MCP Integration** | Calls functions directly | Full MCP protocol support |
| **Session Management** | Conversation history | Working directory + context |
| **File Operations** | Through tool functions | Read/Write/Edit tools available |
| **Best For** | Standard pentesting | Advanced workflows, better MCP integration |
| **Dependencies** | anthropic | anthropic + claude-code-sdk |

---

## API Mode (ntree_agent.py)

### Architecture

```
┌─────────────────────────────────┐
│     ntree_agent.py              │
│                                 │
│  Anthropic API (messages.create)│
│          ↓                      │
│  Function Calling               │
│          ↓                      │
│  18 Tool Definitions            │
│          ↓                      │
│  Direct Python function calls   │
│          ↓                      │
│  Security tools from MCP servers│
└─────────────────────────────────┘
```

### How It Works

```python
from anthropic import Anthropic

client = Anthropic(api_key="...")

response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=4096,
    system=system_prompt,
    messages=conversation_history,
    tools=tool_definitions  # 18 security tools defined
)

# Process tool calls
for block in response.content:
    if block.type == "tool_use":
        result = await execute_tool(block.name, block.input)
        conversation_history.append(result)
```

### Tool Definition Example

```python
{
    "name": "scan_network",
    "description": "Scan network for active hosts using nmap",
    "input_schema": {
        "type": "object",
        "properties": {
            "targets": {"type": "string"},
            "scan_type": {"type": "string"}
        },
        "required": ["targets"]
    }
}
```

### Advantages

✅ **Simpler Setup** - Just install `anthropic` package
✅ **Lighter Weight** - Fewer dependencies
✅ **Direct Control** - Explicit tool definitions
✅ **Easier Debugging** - Clear function call flow
✅ **Lower Overhead** - No MCP protocol overhead
✅ **Faster Iteration** - Quick to modify tool definitions

### Disadvantages

❌ **Manual Tool Definitions** - Must define all 18 tools manually
❌ **No File Tools** - Can't use Read/Write/Edit tools directly
❌ **Less Claude Code-like** - Different behavior than interactive mode
❌ **Duplication** - Tool logic exists in both MCP servers and agent

### Best Use Cases

- Standard autonomous pentesting
- Production deployments where simplicity is key
- Environments with limited dependencies
- When you want explicit control over tool behavior
- Cost-sensitive deployments (slightly less API usage)

---

## SDK Mode (ntree_agent_sdk.py)

### Architecture

```
┌────────────────────────────────────────┐
│     ntree_agent_sdk.py                 │
│                                        │
│  ClaudeSDKClient (claude-code-sdk)     │
│          ↓                             │
│  ClaudeCodeOptions                     │
│    - MCP servers config                │
│    - Working directory                 │
│    - Allowed tools                     │
│          ↓                             │
│  MCP Protocol                          │
│          ↓                             │
│  6 NTREE MCP Servers                   │
│    + Standard tools (Bash, Read, etc.) │
└────────────────────────────────────────┘
```

### How It Works

```python
from claude_code_sdk import ClaudeSDKClient, ClaudeCodeOptions

options = ClaudeCodeOptions(
    cwd=str(session_dir),
    allowed_tools=[
        "Bash", "Glob", "Grep", "Read", "Write", "Edit",
        "mcp__ntree-scope__init_engagement",
        "mcp__ntree-scope__verify_scope",
        "mcp__ntree-scan__scan_network",
        # ... all MCP tools
    ],
    mcp_servers={
        "ntree-scope": {
            "command": "python",
            "args": ["-m", "ntree_mcp.scope"],
            "env": {"NTREE_HOME": "~/ntree"}
        },
        # ... all 6 servers
    }
)

async with ClaudeSDKClient(options=options) as client:
    await client.query(initial_prompt)
    async for message in client.receive_response():
        # Handle responses
```

### MCP Configuration Example

```python
mcp_servers = {
    "ntree-scope": {
        "command": python_path,
        "args": ["-m", "ntree_mcp.scope"],
        "env": {
            "NTREE_HOME": str(Path.home() / "ntree"),
            "PYTHONPATH": str(mcp_servers_dir)
        }
    },
    "ntree-scan": { ... },
    "ntree-enum": { ... },
    "ntree-vuln": { ... },
    "ntree-post": { ... },
    "ntree-report": { ... }
}
```

### Advantages

✅ **Full MCP Integration** - Native MCP protocol support
✅ **No Tool Duplication** - Uses MCP servers directly
✅ **Session Management** - Working directories for better context
✅ **More Claude Code-like** - Behavior matches interactive mode
✅ **File Tools Available** - Can use Read/Write/Edit tools
✅ **Better State Management** - Session-based persistence
✅ **Advanced Workflows** - Support for complex multi-step operations

### Disadvantages

❌ **More Complex Setup** - Additional dependencies
❌ **Heavier Weight** - claude-code-sdk + MCP overhead
❌ **More Dependencies** - Requires MCP server processes
❌ **Slightly Higher Latency** - MCP protocol overhead
❌ **More Moving Parts** - 6 MCP server processes

### Best Use Cases

- Advanced pentesting workflows
- When you want Claude Code-like behavior
- Complex multi-step engagements
- Development and experimentation
- When you need file manipulation tools
- Better integration with existing MCP ecosystem

---

## Technical Differences

### 1. Tool Execution

**API Mode:**
```python
# Tool defined in agent code
tools = [
    {
        "name": "scan_network",
        "description": "...",
        "input_schema": {...}
    }
]

# Executed directly
from ntree_mcp.scan import scan_network
result = await scan_network(targets="192.168.1.0/24")
```

**SDK Mode:**
```python
# Tool accessed via MCP
allowed_tools = [
    "mcp__ntree-scan__scan_network"
]

# Executed through MCP protocol
# Claude calls: mcp__ntree-scan__scan_network
# SDK routes to: ntree-scan server -> scan_network()
```

### 2. State Management

**API Mode:**
```python
# State in conversation history
conversation_history = [
    {"role": "user", "content": "Start pentest"},
    {"role": "assistant", "content": [...]},
    {"role": "user", "content": "Tool results: ..."}
]

# Engagement state tracked in memory/files
self.engagement_id = "..."
self.findings = [...]
```

**SDK Mode:**
```python
# State in working directory + conversation
session_dir = work_dir / "pentest_20260109_120000"
options = ClaudeCodeOptions(cwd=str(session_dir))

# Files created in session_dir:
# - engagement_*.json
# - findings/*.json
# - reports/*
# - state.json
```

### 3. Configuration

**API Mode:**
```python
# Simple API key config
self.client = Anthropic(api_key=config["anthropic"]["api_key"])
```

**SDK Mode:**
```python
# Full MCP configuration
options = ClaudeCodeOptions(
    cwd=str(session_dir),
    allowed_tools=[...],  # 25+ tools
    permission_mode="acceptEdits",
    mcp_servers={...}  # 6 server configs
)
```

---

## Performance Comparison

### API Mode

**Startup Time:** ~1-2 seconds
- Load agent
- Initialize Anthropic client
- Ready to go

**Per-Tool Latency:** ~2-5 seconds
- API call to Claude
- Function execution
- Response back to Claude

**Memory Usage:** ~100-200 MB
- Python process
- Anthropic client
- Conversation history

### SDK Mode

**Startup Time:** ~5-10 seconds
- Load agent
- Initialize SDK client
- Start 6 MCP server processes
- Configure session

**Per-Tool Latency:** ~3-7 seconds
- API call to Claude
- MCP protocol routing
- Server execution
- Response back through MCP

**Memory Usage:** ~500-800 MB
- Python process
- SDK client
- 6 MCP server processes
- Session state

---

## Cost Comparison

Both modes use the same Claude model, so API costs are similar:

**API Mode:** Slightly lower
- Simpler system prompts
- Less protocol overhead
- More concise tool descriptions

**SDK Mode:** Slightly higher
- More verbose MCP protocol
- Additional context from session
- Richer tool metadata

**Difference:** ~5-10% more tokens in SDK mode

---

## Migration Between Modes

### API → SDK

Replace:
```bash
python ntree_agent.py --scope scope.txt
```

With:
```bash
python ntree_agent_sdk.py --scope scope.txt
```

No configuration changes needed. Same API key, same behavior.

### SDK → API

Same as above, just reverse the filenames.

---

## Choosing the Right Mode

### Choose API Mode If:

✅ You want the simplest setup
✅ You're deploying to production
✅ You need maximum performance
✅ You want explicit control over tools
✅ You're cost-sensitive
✅ You don't need file manipulation tools
✅ Your workflows are standard pentesting

### Choose SDK Mode If:

✅ You want Claude Code-like behavior
✅ You're experimenting with advanced workflows
✅ You need file manipulation (Read/Write/Edit)
✅ You want better MCP integration
✅ You're building on top of NTREE
✅ You need session-based state management
✅ You want to leverage the full MCP ecosystem

---

## Recommendation

### For Most Users: **API Mode**
- Simpler, faster, proven
- Best for standard autonomous pentesting
- Lower resource usage
- Easier to understand and debug

### For Advanced Users: **SDK Mode**
- More powerful and flexible
- Better for complex workflows
- Closer to interactive Claude Code
- More extensible for future features

---

## Installation

### API Mode

```bash
cd ~/ntree/ntree-autonomous
source venv/bin/activate
pip install -r requirements.txt  # Includes anthropic
```

### SDK Mode

```bash
cd ~/ntree/ntree-autonomous
source venv/bin/activate
pip install -r requirements.txt  # Includes anthropic + claude-code-sdk
```

Same requirements file, both dependencies included!

---

## Testing Both Modes

```bash
# Test API mode
python ntree_agent.py --scope ~/ntree/templates/scope_example.txt

# Test SDK mode
python ntree_agent_sdk.py --scope ~/ntree/templates/scope_example.txt

# Compare results
diff ~/ntree/engagements/eng_*/reports/executive_report.md
```

Results should be similar, but SDK mode may:
- Use slightly different approaches
- Leverage file tools more
- Have richer session state

---

## Support and Documentation

- **API Mode Docs:** See `AUTONOMOUS_MODE.md`
- **SDK Mode Docs:** See `ntree_agent_sdk.py` comments
- **MCP Servers:** See `ntree-mcp-servers/README.md`
- **Troubleshooting:** Check `~/ntree/logs/ntree_agent.log`

---

## Summary

Both modes are production-ready and fully functional. The choice depends on your specific needs:

**API Mode** = Simple, fast, proven
**SDK Mode** = Powerful, flexible, Claude Code-like

Try both and see which fits your workflow better!

---

**Last Updated:** 2026-01-09
**NTREE Version:** 2.0.0
