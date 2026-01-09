# NTREE Quick Start Guide

Get your NTREE penetration testing platform running on Raspberry Pi 5 in under an hour.

---

## Prerequisites

- **Raspberry Pi 5** (4GB or 8GB RAM)
- **Raspberry Pi OS** (64-bit) installed
- **Internet connection** (Ethernet recommended)
- **Claude Code Pro subscription**
- **Authorized penetration testing engagement**

---

## Installation (One-Time Setup)

### Step 1: Download NTREE

```bash
# Create workspace
mkdir -p ~/ntree
cd ~/ntree

# Download NTREE files
# Option A: Clone from GitHub
git clone https://github.com/YOUR_USERNAME/ntree.git .

# Option B: Manual download (if no repository yet)
# Download and extract NTREE files to ~/ntree/
```

### Step 2: Run Installation Script

```bash
# Make installation script executable
chmod +x scripts/install_ntree.sh

# Run installation (takes 30-60 minutes)
bash scripts/install_ntree.sh
```

**What gets installed:**
- Claude Code CLI
- Security tools (nmap, masscan, nikto, enum4linux, etc.)
- Python security libraries (impacket, crackmapexec)
- Wordlists (SecLists, rockyou)
- NTREE directory structure

**During installation:** Get coffee ☕ - the Pi needs time to compile and install everything.

### Step 3: Authenticate Claude Code

```bash
# Login to Claude Code
claude auth login
```

Follow the prompts to authenticate with your Claude Pro account.

### Step 4: Install MCP Servers

```bash
# Setup MCP servers
chmod +x scripts/setup_mcp_servers.sh
bash scripts/setup_mcp_servers.sh
```

When prompted for repository URL:
- If you have the MCP servers repo: provide the URL
- If not: Skip this for now and install manually later

### Step 5: Reload Shell

```bash
# Reload bash configuration
source ~/.bashrc

# Verify installation
nmap --version
nuclei -version
crackmapexec --version
```

---

## First Engagement

### Step 1: Create Scope File

```bash
# Edit the example scope file
nano ~/ntree/templates/scope_example.txt
```

Add your authorized targets:

```
# Your authorized target network
192.168.100.0/24

# Specific hosts
10.0.0.50
10.0.0.51

# Domains (if testing external)
# testdomain.com

# Excluded (off-limits)
EXCLUDE 192.168.100.1
EXCLUDE 192.168.100.100
```

**Save as:** `~/ntree/engagements/my_first_pentest/scope.txt`

### Step 2: Activate NTREE Environment

```bash
# Activate NTREE environment
source ~/ntree/activate.sh

# You should see:
# NTREE environment activated
# Python venv: /home/pi/venvs/sectools/bin/python
# NTREE_HOME: /home/pi/ntree
```

### Step 3: Start Claude Code

```bash
# Start Claude Code
claude
```

### Step 4: Activate NTREE Mode

In Claude Code, type:

```
Start NTREE with scope: /home/pi/ntree/engagements/my_first_pentest/scope.txt
```

Claude will:
1. Read the scope file
2. Initialize the engagement
3. Create engagement directory structure
4. Begin systematic reconnaissance

### Step 5: Follow NTREE Workflow

NTREE will guide you through phases:

**Phase 1: Reconnaissance**
- Discover live hosts
- Identify operating systems
- Map network topology

**Phase 2: Enumeration**
- Enumerate services on each host
- Identify versions
- Collect banners

**Phase 3: Attack Surface Mapping**
- Analyze vulnerabilities
- Research exploits
- Prioritize targets

**Phase 4: Exploit Validation**
- Test suspected vulnerabilities
- Validate default credentials (with approval)
- Confirm exploitability

**Phase 5: Post-Exploitation** (if access gained)
- Test credential reuse
- Map lateral movement paths
- Analyze privilege escalation

**Phase 6: Risk Quantification**
- Score findings by severity
- Calculate business impact
- Identify critical paths

**Phase 7: Report Generation**
- Generate comprehensive report
- Include executive summary
- Provide remediation guidance

### Step 6: Approve High-Risk Actions

When NTREE needs approval for sensitive operations:

```
⚠️  APPROVAL REQUIRED ⚠️
Action: Test credentials on 192.168.100.50:445
Justification: Enumerate SMB shares with discovered credentials
Risk: MEDIUM
Type 'APPROVE' to proceed or 'DENY' to skip
```

Type: `APPROVE` or `DENY`

### Step 7: Review Findings

During engagement:

```bash
# View current state
cat ~/ntree/engagements/eng_*/state.json | jq .

# List findings
ls ~/ntree/engagements/eng_*/findings/

# View specific finding
cat ~/ntree/engagements/eng_*/findings/finding_001.json | jq .
```

### Step 8: Generate Report

When NTREE completes all phases:

```bash
# Report is automatically generated at:
~/ntree/engagements/eng_YYYYMMDD_HHMMSS/reports/final_report.md

# View report
less ~/ntree/engagements/eng_*/reports/final_report.md

# Or open in browser (if GUI available)
chromium ~/ntree/engagements/eng_*/reports/final_report.html
```

---

## Daily Usage

### Starting a New Engagement

```bash
# 1. Activate environment
source ~/ntree/activate.sh

# 2. Create engagement directory
mkdir -p ~/ntree/engagements/client_name_date

# 3. Create scope file
nano ~/ntree/engagements/client_name_date/scope.txt

# 4. Start Claude Code
claude

# 5. In Claude Code:
Start NTREE with scope: /home/pi/ntree/engagements/client_name_date/scope.txt
```

### Resuming an Engagement

```bash
# 1. Start Claude Code
claude

# 2. Load engagement
Load engagement eng_20250108_103045

# NTREE will resume from where it left off
```

### Pausing an Engagement

In Claude Code:
```
Pause NTREE
```

State is automatically saved. Resume anytime.

### Backing Up an Engagement

```bash
# Backup engagement
~/ntree/backup_engagement.sh eng_20250108_103045

# Backup saved to:
# ~/ntree/backups/eng_20250108_103045_TIMESTAMP.tar.gz
```

---

## Common Operations

### Scanning a Specific Host

Instead of full engagement:

```bash
# In Claude Code (not NTREE mode)
Run nmap scan on 192.168.100.50 and analyze results
```

### Testing Specific Vulnerability

```bash
# In NTREE mode
Test CVE-2023-12345 on 192.168.100.50
```

### Generating Quick Report

```bash
# From any engagement directory
cd ~/ntree/engagements/eng_20250108_103045

# Generate report manually (if MCP server available)
python -m ntree_mcp.report generate eng_20250108_103045
```

---

## Troubleshooting

### MCP Servers Not Working

```bash
# Test MCP servers
cd ~/ntree/ntree-mcp-servers
source venv/bin/activate
python -m ntree_mcp.scope --version

# Restart Claude Code
pkill claude
claude
```

### Tools Require Password

```bash
# Check sudo configuration
sudo -l

# Should show NOPASSWD for nmap, masscan, tcpdump
# If not, re-run:
sudo visudo /etc/sudoers.d/ntree
```

### Out of Scope Errors

```bash
# Verify scope file
cat ~/ntree/engagements/eng_*/scope.txt

# Ensure target is in included ranges/IPs
# Ensure target is not in EXCLUDE lines
```

### Slow Scans

```bash
# Check network connection
ping -c 4 8.8.8.8

# Ensure Pi is on Ethernet (not WiFi)
# Reduce scan intensity (NTREE uses -T3 by default)
```

### Disk Space Full

```bash
# Check disk usage
df -h

# Clean up temporary files
~/ntree/cleanup_temp.sh

# Archive old engagements
tar -czf old_engagements.tar.gz ~/ntree/engagements/eng_2024*
rm -rf ~/ntree/engagements/eng_2024*
```

---

## Best Practices

### Pre-Engagement

1. **Verify Authorization**: Always have written permission
2. **Test Equipment**: Scan a test VM first (Metasploitable, DVWA)
3. **Backup Pi**: Create SD card backup before critical engagements
4. **Check Network**: Ensure Pi can reach targets
5. **Set Expectations**: Know what client expects in report

### During Engagement

1. **Monitor Progress**: Check state.json periodically
2. **Backup Frequently**: Run backup script after major phases
3. **Review Findings**: Manually verify NTREE's findings
4. **Document Changes**: Note any manual actions outside NTREE
5. **Stay in Scope**: Trust NTREE's scope validation

### Post-Engagement

1. **Review Report**: Read through before sending to client
2. **Validate Remediation**: Offer retest after fixes
3. **Archive Engagement**: Backup and encrypt engagement data
4. **Update Tools**: Keep NTREE and security tools updated
5. **Learn**: Review what worked well, what needs improvement

---

## Updating NTREE

### Update System and Tools

```bash
# Update Raspberry Pi OS
sudo apt update && sudo apt upgrade -y

# Update nuclei templates
nuclei -update-templates

# Update wordlists
cd ~/wordlists/SecLists && git pull

# Update Python tools
source ~/venvs/sectools/bin/activate
pip install --upgrade impacket crackmapexec
```

### Update NTREE MCP Servers

```bash
# Pull latest changes
cd ~/ntree/ntree-mcp-servers
git pull

# Reinstall
source venv/bin/activate
pip install --upgrade -e .

# Restart Claude Code
pkill claude
```

---

## Example Engagement Timeline

**Typical small network (10-20 hosts):**

| Phase | Duration | What NTREE Does |
|-------|----------|-----------------|
| Initialization | 1 min | Parse scope, create directories |
| Reconnaissance | 5-10 min | Ping sweep, OS detection |
| Enumeration | 15-30 min | Service scans on all hosts |
| Attack Surface Mapping | 5 min | Analyze results, prioritize targets |
| Exploit Validation | 10-30 min | Test vulnerabilities, credentials |
| Post-Exploitation | 10-20 min | If access gained, test reuse/lateral |
| Risk Quantification | 5 min | Score findings |
| Report Generation | 2 min | Create comprehensive report |
| **Total** | **~1-2 hours** | Automated pentest |

**Manual pentesting same network:** 4-8 hours

---

## Getting Help

### Documentation

- Full installation guide: `PI5_INSTALLATION_GUIDE.md`
- MCP server implementation: `MCP_SERVER_IMPLEMENTATION.md`
- System prompt details: `NTREE_CLAUDE_CODE_PROMPT.txt`

### Community

- GitHub Issues: Report bugs and request features
- Discussions: Ask questions, share findings
- Discord: Real-time community support (if available)

### Logs

```bash
# View NTREE logs
tail -f ~/ntree/logs/ntree.log

# View Claude Code logs
journalctl --user -u claude-code -f

# View MCP server logs
tail -f ~/.local/share/claude-code/mcp-servers.log
```

---

## Security Reminders

⚠️ **CRITICAL SAFETY RULES:**

1. **Never exceed authorized scope** - NTREE will block out-of-scope targets
2. **Always have written authorization** - Legal requirement for pentesting
3. **Test in lab first** - Use vulnerable VMs before real engagements
4. **Monitor for impact** - Stop if targets become unresponsive
5. **Secure engagement data** - Encrypt findings, credentials, reports
6. **Report responsibly** - Give client time to fix before disclosure
7. **Stay updated** - Keep tools current for accurate results

---

**You're ready to start penetration testing with NTREE! 🔒🔍**

Remember: With great power comes great responsibility. Always test ethically and legally.
