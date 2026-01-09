# NTREE Autonomous Mode

**Fully Automated Penetration Testing Using Claude SDK**

## Overview

NTREE can now run in **fully autonomous mode** using the Claude SDK (Anthropic API), eliminating the need for human interaction during penetration tests. The system can operate independently on your Raspberry Pi 5, making intelligent decisions about testing strategy while maintaining all safety controls.

## Architecture

### Mode Comparison

| Feature | MCP Mode (Claude Code) | **Autonomous Mode (Claude SDK)** |
|---------|----------------------|----------------------------------|
| **Interaction** | Human in the loop | Fully autonomous |
| **Platform** | Claude Code CLI | Standalone Python |
| **Decision Making** | User approves actions | Claude decides autonomously |
| **Scheduling** | Manual execution | Cron/systemd scheduling |
| **API** | Model Context Protocol | Anthropic REST API |
| **Use Case** | Interactive pentesting | Automated continuous testing |
| **Cost** | Claude Code Pro subscription | Pay-per-token API usage |

### Autonomous Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NTREE Autonomous Agent                   │
│                  (ntree_agent.py)                           │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Claude SDK (Anthropic API)                │   │
│  │  - Model: claude-sonnet-4-5-20250929               │   │
│  │  - Function calling / Tool use                      │   │
│  │  - Autonomous decision-making                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ├─── Tool Execution               │
│                           │                                 │
│  ┌────────────────────────▼────────────────────────────┐   │
│  │          Security Tool Functions                    │   │
│  │  (Imported from ntree-mcp-servers)                  │   │
│  │                                                      │   │
│  │  • Scope validation    • Enumeration                │   │
│  │  • Network scanning    • Vulnerability testing      │   │
│  │  • Post-exploitation   • Report generation          │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ├─── Results                      │
│                           │                                 │
│  ┌────────────────────────▼────────────────────────────┐   │
│  │         Findings & Evidence Collection              │   │
│  │         Engagement State Management                 │   │
│  │         Automated Report Generation                 │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │
         ├─── Logs: ~/ntree/logs/ntree_agent.log
         ├─── Engagements: ~/ntree/engagements/eng_*
         └─── Reports: ~/ntree/engagements/eng_*/reports/
```

## Installation

### Prerequisites

1. **Anthropic API Key** - Sign up at https://console.anthropic.com/
2. **NTREE Base Installation** - Run `install_ntree.sh` first
3. **NTREE MCP Servers** - Install Python security tool functions

### Quick Start

```bash
# 1. Clone autonomous mode code
cd ~/ntree
git clone <your-repo>/ntree-autonomous.git

# 2. Run deployment script
cd ntree-autonomous
bash deploy_autonomous.sh

# 3. Configure API key
nano ~/ntree/config.json
# Set: "api_key": "sk-ant-..."

# 4. Run your first autonomous pentest
~/ntree/run_pentest.sh ~/ntree/templates/scope_example.txt
```

## Configuration

### Main Config File: `~/ntree/config.json`

```json
{
  "anthropic": {
    "api_key": "sk-ant-...",               # Your API key
    "model": "claude-sonnet-4-5-20250929", # Claude model to use
    "max_tokens": 4096,                    # Max response length
    "temperature": 0.7                     # Creativity (0-1)
  },
  "pentest": {
    "max_iterations": 50,                  # Safety limit on test length
    "default_scan_intensity": "normal",    # stealth/normal/aggressive
    "credential_attempt_limit": 3,         # Rate limiting
    "enable_safe_mode": true               # Validation-only by default
  },
  "automation": {
    "enabled": false,                      # Enable scheduled tests
    "schedule": "0 2 * * 0",              # Cron format (Sun 2am)
    "scope_file": "~/ntree/templates/scope_weekly.txt",
    "notification_webhook": ""             # Slack/Discord webhook
  },
  "safety": {
    "scope_validation_required": true,     # Always validate targets
    "rate_limiting_enabled": true,         # Prevent lockouts
    "require_explicit_approval": true      # High-risk actions need approval
  }
}
```

### Scope File Format

Same as MCP mode:

```
# Authorized targets
192.168.1.0/24
10.0.0.0/28
example.com
*.internal.company.com

# Exclusions
EXCLUDE 192.168.1.1
EXCLUDE 192.168.1.254
```

## Usage

### Manual Execution

#### Run Single Penetration Test

```bash
# Basic usage
~/ntree/run_pentest.sh ~/ntree/templates/my_scope.txt

# With ROE file
cd ~/ntree/ntree-autonomous
source venv/bin/activate
python ntree_agent.py \
    --scope ~/ntree/templates/my_scope.txt \
    --roe ~/ntree/templates/my_roe.txt \
    --max-iterations 50
```

#### What Happens Autonomously

1. **Initialization Phase**
   - Claude reads scope file
   - Calls `init_engagement()` to set up pentest
   - Validates all targets are authorized

2. **Reconnaissance Phase**
   - Decides which hosts to scan first
   - Performs passive recon (DNS, WHOIS)
   - Network scanning to discover hosts/services
   - Analyzes results to prioritize targets

3. **Enumeration Phase**
   - Deep service enumeration on discovered hosts
   - Web application profiling
   - SMB/Windows enumeration
   - Active Directory reconnaissance
   - Makes tactical decisions based on findings

4. **Vulnerability Assessment**
   - Tests for known CVEs
   - Configuration analysis
   - Credential testing (rate-limited)
   - Exploit research
   - Prioritizes high-value vulnerabilities

5. **Exploitation Phase** (Safe Mode)
   - Validates exploitability without actual exploitation
   - Maps lateral movement opportunities
   - Identifies privilege escalation paths
   - **Note**: Actual exploitation requires approval=true

6. **Reporting Phase**
   - Risk scoring and aggregation
   - Generates executive summary
   - Technical findings report
   - Remediation recommendations

### Automated Scheduling

#### Enable Recurring Tests

```bash
# 1. Edit configuration
nano ~/ntree/config.json
```

Set:
```json
{
  "automation": {
    "enabled": true,
    "schedule": "0 2 * * 0",  // Every Sunday at 2 AM
    "scope_file": "~/ntree/templates/scope_weekly.txt",
    "roe_file": "~/ntree/templates/roe_automated.txt",
    "notification_webhook": "https://hooks.slack.com/..."
  }
}
```

```bash
# 2. Enable systemd service
sudo systemctl enable ntree-scheduler
sudo systemctl start ntree-scheduler

# 3. Check status
sudo systemctl status ntree-scheduler

# 4. View logs
tail -f ~/ntree/logs/scheduler.log
```

#### Schedule Formats

```
# Cron format: minute hour day_month month day_week

"0 2 * * 0"     # Every Sunday at 2:00 AM
"0 3 * * *"     # Every day at 3:00 AM
"0 1 * * 1"     # Every Monday at 1:00 AM
"0 22 * * 5"    # Every Friday at 10:00 PM
```

#### Stop Scheduler

```bash
sudo systemctl stop ntree-scheduler
# or
~/ntree/stop_scheduler.sh
```

## How Autonomous Decision-Making Works

### Claude's Role

Claude acts as the penetration tester's brain, making strategic and tactical decisions:

1. **Strategic Planning**
   - Determines testing approach based on discovered infrastructure
   - Prioritizes high-value targets
   - Decides when to move between pentest phases
   - Balances thoroughness vs. time constraints

2. **Tactical Execution**
   - Chooses appropriate tools for each task
   - Adjusts scan intensity based on results
   - Identifies interesting services to enumerate deeply
   - Correlates findings to identify attack paths

3. **Adaptive Behavior**
   - If port scan reveals web server → enumerate with nikto/gobuster
   - If SMB shares found → enumerate with enum4linux
   - If domain controller discovered → AD enumeration
   - If credentials obtained → test for lateral movement

### Example Decision Flow

```
Claude: "I'll start by initializing the engagement and validating scope"
Tool: init_engagement(scope_file="scope.txt")
Result: Engagement created, 2 networks in scope

Claude: "The scope includes 192.168.1.0/24 and 10.0.0.0/24. I'll start with
        passive reconnaissance on any domains, then perform network discovery"
Tool: passive_recon(domain="example.com")
Result: DNS records found, mail servers identified

Claude: "Now I'll scan the 192.168.1.0/24 network to discover live hosts"
Tool: scan_network(targets="192.168.1.0/24", scan_type="ping_sweep")
Result: 12 hosts discovered

Claude: "I found 12 hosts. Let me do detailed service scans on each"
Tool: scan_network(targets="192.168.1.5", scan_type="tcp_syn", ports="top1000")
Result: Ports 22, 80, 443, 445 open

Claude: "Host 192.168.1.5 has web services and SMB. I'll enumerate both"
Tool: enumerate_web(url="http://192.168.1.5")
Result: Apache 2.4.41, /admin directory found

Claude: "Found admin panel. I'll also check SMB shares"
Tool: enumerate_smb(host="192.168.1.5")
Result: Anonymous share access enabled

Claude: "Anonymous SMB access is a security issue. Let me test for other vulns"
... [continues autonomously] ...
```

### Safety Controls

Even in autonomous mode, all safety features remain active:

✅ **Scope Validation** - Every action verified against authorized targets
✅ **Rate Limiting** - Credential testing limited to 3 attempts per 5 minutes
✅ **Safe Mode** - Vulnerabilities validated without exploitation
✅ **Approval Required** - High-risk actions (secret extraction) need approval=true
✅ **Audit Logging** - Complete trail of all actions
✅ **Iteration Limits** - Maximum 50 iterations prevents infinite loops

## Monitoring

### Real-Time Monitoring

```bash
# Watch agent logs
tail -f ~/ntree/logs/ntree_agent.log

# Watch scheduler logs
tail -f ~/ntree/logs/scheduler.log

# Monitor system resources
htop
```

### Log Files

```
~/ntree/logs/
├── ntree_agent.log          # Main agent activity
├── scheduler.log            # Scheduled test execution
├── scope_violations.log     # Out-of-scope attempts
└── audit.log                # Security-critical actions
```

### Engagement Data

```
~/ntree/engagements/eng_20260109_120000/
├── state.json                # Engagement state
├── findings/
│   ├── finding_001.json
│   ├── finding_002.json
│   └── finding_003.json
├── evidence/
│   ├── nmap_scan_192.168.1.5.xml
│   └── screenshot_admin_panel.png
└── reports/
    ├── executive_report.html
    ├── technical_report.html
    └── comprehensive_report.pdf
```

## API Usage & Costs

### Estimated Costs

Based on Claude Sonnet 4.5 pricing (as of Jan 2025):
- Input: $3 per million tokens
- Output: $15 per million tokens

**Typical Penetration Test:**
- Small network (5 hosts): ~100K tokens → $1-2
- Medium network (20 hosts): ~500K tokens → $5-10
- Large network (100 hosts): ~2M tokens → $20-40

**Automated Weekly Tests:**
- ~$10-50/month depending on scope size

### Usage Monitoring

```bash
# View API usage in Anthropic Console
https://console.anthropic.com/settings/usage

# Check engagement logs for token counts
grep "tokens" ~/ntree/logs/ntree_agent.log
```

### Cost Optimization

1. **Use Haiku for Simple Tasks** - Switch to claude-haiku-4 for basic scans
2. **Limit Max Iterations** - Set lower `max_iterations` in config
3. **Target Scheduling** - Run tests during off-peak hours
4. **Scope Carefully** - Smaller scopes = lower costs

## Notifications

### Slack Integration

```json
{
  "automation": {
    "notification_webhook": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }
}
```

Notifications sent:
- ✅ Pentest completed successfully
- ❌ Pentest failed with error
- 📊 Summary with finding count
- 🔗 Link to reports

### Discord Integration

Similar to Slack - use Discord webhook URL

### Email Notifications

```json
{
  "automation": {
    "notification_email": "security-team@company.com"
  }
}
```

(Requires SMTP configuration - see documentation)

## Troubleshooting

### Agent Stops Prematurely

**Problem**: Agent completes after only a few iterations

**Solutions**:
- Check logs: `tail -f ~/ntree/logs/ntree_agent.log`
- Increase `max_iterations` in config
- Verify scope file is correct
- Check API key is valid

### API Rate Limiting

**Problem**: "Rate limit exceeded" errors

**Solutions**:
- Anthropic has generous rate limits for paid tier
- Add delays between iterations (edit config)
- Upgrade API tier if needed

### High API Costs

**Problem**: Unexpected API bills

**Solutions**:
- Set lower `max_iterations` (default: 50)
- Use more specific scope files (fewer targets)
- Review automation schedule frequency
- Switch to Haiku model for simple tasks

### No Progress After Init

**Problem**: Agent initializes but doesn't proceed

**Solutions**:
- Check scope file has valid targets
- Verify network connectivity
- Check security tools are installed (`nmap --version`)
- Review system prompt is loaded correctly

## Advanced Configuration

### Custom System Prompts

Edit `ntree_agent.py` to modify Claude's instructions:

```python
def _load_system_prompt(self) -> str:
    # Add your custom instructions
    return """You are NTREE...

    [Add custom methodology, priorities, constraints]
    """
```

### Custom Tool Functions

Add new security tools in `ntree-mcp-servers/ntree_mcp/`:

```python
# custom_tools.py
async def my_custom_scanner(target: str, options: str) -> dict:
    # Your custom tool logic
    return {"status": "success", "findings": [...]}
```

Then register in `ntree_agent.py` tool definitions.

### Multi-Engagement Support

Run multiple tests in parallel:

```bash
# Terminal 1
python ntree_agent.py --scope scope1.txt &

# Terminal 2
python ntree_agent.py --scope scope2.txt &
```

Each creates separate engagement directories.

## Security Considerations

### API Key Security

```bash
# NEVER commit API keys to git
echo "config.json" >> .gitignore

# Use environment variables
export ANTHROPIC_API_KEY="sk-ant-..."
# Remove from config.json, agent will use env var

# Restrict file permissions
chmod 600 ~/ntree/config.json
```

### Penetration Testing Authorization

⚠️ **CRITICAL**: Autonomous mode does NOT change legal requirements:
- ✅ Get written authorization before testing
- ✅ Define clear scope boundaries
- ✅ Have incident response plan
- ✅ Follow responsible disclosure
- ❌ NEVER test without permission
- ❌ NEVER exceed authorized scope

### Network Isolation

Recommended setup for production:
```
┌─────────────────────┐
│  Raspberry Pi 5     │
│  (NTREE Agent)      │
│  Management Network │
└──────┬──────────────┘
       │
       │ VPN/Isolated
       │
┌──────▼──────────────┐
│  Target Network     │
│  (Pentest Scope)    │
└─────────────────────┘
```

## Comparison: MCP vs Autonomous

### When to Use MCP Mode (Claude Code)

✅ Learning and training
✅ Complex custom testing
✅ High-risk environments requiring human oversight
✅ Ad-hoc investigations
✅ Manual verification of findings

### When to Use Autonomous Mode (SDK)

✅ Recurring compliance testing
✅ Continuous security monitoring
✅ Standard infrastructure pentesting
✅ Automated vulnerability validation
✅ Scheduled regression testing
✅ Large-scale network assessments

## Example: Complete Workflow

```bash
# 1. Create scope for production network
cat > ~/ntree/templates/prod_scope.txt << EOF
# Production web servers
192.168.100.0/24

# Database tier
192.168.101.0/28

# Exclusions
EXCLUDE 192.168.100.1  # Gateway
EXCLUDE 192.168.101.15 # Production DB
EOF

# 2. Create rules of engagement
cat > ~/ntree/templates/prod_roe.txt << EOF
ENGAGEMENT_TYPE: weekly_compliance_scan
STEALTH_LEVEL: normal
AUTHORIZATION: security-team-approval-2026.pdf

ALLOWED_ACTIONS:
  - network_scanning
  - service_enumeration
  - vulnerability_validation
  - safe_mode_testing

FORBIDDEN_ACTIONS:
  - exploitation
  - credential_dumping
  - production_disruption

RATE_LIMITS:
  - scan_timing: -T2 (polite)
  - credential_attempts: 0 (disabled)
EOF

# 3. Test manually first
~/ntree/run_pentest.sh ~/ntree/templates/prod_scope.txt

# 4. Review results
ls ~/ntree/engagements/eng_*/reports/

# 5. Enable weekly automation
nano ~/ntree/config.json
# Set automation.enabled = true
# Set automation.schedule = "0 2 * * 0"
# Set automation.scope_file = "~/ntree/templates/prod_scope.txt"

# 6. Start scheduler
sudo systemctl enable ntree-scheduler
sudo systemctl start ntree-scheduler

# 7. Monitor
tail -f ~/ntree/logs/scheduler.log

# 8. Review weekly reports
ls -lat ~/ntree/engagements/
```

## Conclusion

NTREE Autonomous Mode transforms your Raspberry Pi 5 into a fully automated penetration testing platform. Claude SDK provides intelligent decision-making while maintaining strict safety controls, enabling continuous security assessment without constant human oversight.

**Key Capabilities:**
- ✅ Fully autonomous penetration testing
- ✅ Intelligent, adaptive decision-making
- ✅ Scheduled recurring assessments
- ✅ Automatic report generation
- ✅ All safety controls enforced
- ✅ Cost-effective API usage
- ✅ Enterprise-ready scheduling

Get started today: `bash deploy_autonomous.sh`

---

**Documentation Version:** 1.0
**Last Updated:** 2026-01-09
**Compatible With:** NTREE v2.0+
