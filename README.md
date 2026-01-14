# NTREE v2.0 - Neural Tactical Red-Team Exploitation Engine

**Claude Code Edition for Raspberry Pi 5**

An autonomous penetration testing platform powered by Claude Code Pro, running on affordable Raspberry Pi hardware.

**Compatible with:** Raspberry Pi OS (64-bit) • Kali Linux ARM64

---

## 🎯 What is NTREE?

NTREE transforms Claude Code into a systematic red-team operator that conducts professional penetration tests following industry-standard methodologies. Unlike traditional automated scanners, NTREE uses Claude's reasoning engine to:

- **Think like a pentester** - Analyze results, correlate findings, prioritize targets
- **Adapt to findings** - Build progressive attack chains based on discoveries
- **Stay safe** - Multi-layer authorization prevents scope violations
- **Generate insights** - Explain vulnerabilities in business context

### Key Features

✅ **Three Operational Modes** - Interactive (MCP), Autonomous API, Autonomous SDK
✅ **Systematic Methodology** - Follows structured pentest lifecycle from recon to reporting
✅ **Safety-First Design** - Scope validation, approval workflows, rate limiting
✅ **Real Tool Execution** - Actually runs nmap, nikto, smbclient, rpcclient, crackmapexec, nuclei
✅ **State Persistence** - Resume engagements across sessions
✅ **Real Reports** - Generated from actual findings discovered during scans
✅ **Affordable Hardware** - Runs on Raspberry Pi 5 ($80)
✅ **Fully Autonomous** - Can run scheduled pentests without human intervention
✅ **Powered by Claude** - Advanced reasoning + security expertise

### How It Actually Works

NTREE executes **real security tools** via subprocess and generates **real reports** from actual findings:

```
./start_pentest.sh --scope targets.txt
        ↓
init_engagement()     → Creates engagement directory
        ↓
scan_network()        → Runs: sudo nmap -sS -sV -O <targets>
        ↓
enumerate_services()  → Runs: nmap -sC -sV, nikto, smbclient, rpcclient
        ↓
test_vuln()           → Runs: nmap --script vuln, nuclei
        ↓
save_finding()        → Saves vulnerability to findings/*.json
        ↓
generate_report()     → Reads findings, creates executive/technical report
```

**Required Security Tools (Auto-Installed):**
```bash
# Network scanning
nmap, masscan

# DNS/Domain enumeration
dnsenum, dnsutils, whois

# SMB/Windows testing
smbclient, rpcclient, cifs-utils, crackmapexec

# Web application testing
nikto, dirb, gobuster, whatweb, wapiti, sqlmap

# Credential testing
hydra, medusa, john, hashcat

# Vulnerability scanning
nuclei (with templates), testssl.sh

# Exploitation frameworks
metasploit-framework, impacket

# Python packages
mcp, pydantic, anthropic, claude-code-sdk, xmltodict, aiofiles
```

---

## 🏗️ Architecture

### Three Operational Modes

**1. Interactive Mode (Claude Code)** - Human-in-the-loop collaboration
**2. Autonomous API Mode** - Fully automated with direct Anthropic API
**3. Autonomous SDK Mode** - Fully automated with Claude Code SDK

```
┌─────────────────────────────────────────────────────────┐
│              Mode 1: Interactive (MCP)                  │
│                                                         │
│                    Claude Code Pro                      │
│              (Reasoning Engine + Planning)              │
└─────────────────────┬───────────────────────────────────┘
                      │ MCP Protocol
┌─────────────────────▼───────────────────────────────────┐
│                 NTREE MCP Servers                       │
│  ┌─────────┬─────────┬─────────┬─────────┬──────────┐  │
│  │  Scope  │  Scan   │  Enum   │  Vuln   │  Report  │  │
│  └─────────┴─────────┴─────────┴─────────┴──────────┘  │
└─────────────────────┬───────────────────────────────────┘
                      │ CLI Execution
┌─────────────────────▼───────────────────────────────────┐
│              Security Tools (Raspberry Pi)              │
│  nmap · masscan · smbclient · nikto · crackmapexec     │
│  impacket · hydra · john · nuclei · metasploit         │
└─────────────────────┬───────────────────────────────────┘
                      │ Network Traffic
┌─────────────────────▼───────────────────────────────────┐
│                  Target Network                         │
│           (Authorized Pentest Scope)                    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│     Mode 2: Autonomous API / Mode 3: Autonomous SDK    │
│                                                         │
│          NTREE Autonomous Agent (No Human)              │
│        • API Mode: Direct Anthropic API                │
│        • SDK Mode: claude-code-sdk with MCP            │
│                                                         │
│  ↓ Calls security tools directly or via MCP            │
│  ↓ Makes all tactical decisions autonomously           │
│  ↓ Can be scheduled for recurring tests                │
└─────────────────────┬───────────────────────────────────┘
                      │ Same Security Tools
┌─────────────────────▼───────────────────────────────────┐
│              Security Tools (Raspberry Pi)              │
│  nmap · masscan · smbclient · nikto · crackmapexec     │
└─────────────────────────────────────────────────────────┘
```

---

## 📋 Requirements

### Hardware
- **Raspberry Pi 5** (4GB or 8GB RAM recommended)
- **MicroSD Card** (64GB+ Class 10)
- **Power Supply** (Official 27W USB-C recommended)
- **Ethernet Connection** (strongly preferred over WiFi)
- **Active Cooling** (fan or heatsink for sustained operations)

### Software
- **Operating System**: One of the following:
  - Raspberry Pi OS (64-bit, Bookworm or later) - Recommended
  - Kali Linux ARM64 (2024.1 or later) - Fully supported
- **Claude Code Pro** subscription (for interactive/SDK modes)
- **Anthropic API Key** (for autonomous API mode)
- **Python 3.10+** (3.11+ strongly recommended)
- **Git**
- **Build tools** (gcc, make, cargo - auto-installed)

**Note for Kali Users:** Many security tools come pre-installed with Kali Linux. The setup script will detect existing tools and skip their installation.

### Authorization
- **Written permission** for penetration testing
- **Defined scope** (IP ranges, domains)
- **Rules of engagement** document

---

## 🚀 Quick Start

### Installation (One-Time Setup)

```bash
# Clone the repository
git clone https://github.com/wargaintibumi/ntree.git
cd ntree

# Run the unified setup script
bash setup.sh

# IMPORTANT: Authenticate with Claude Code (REQUIRED)
claude auth login
```

**Installation time:** 30-60 minutes
**Disk space required:** ~10GB

The setup script will automatically install:
- ✅ All security tools (nmap, metasploit, impacket, etc.)
- ✅ NTREE MCP servers (Claude Code integration)
- ✅ NTREE autonomous agents
- ✅ Python dependencies
- ✅ Wordlists (SecLists, RockYou)

### Kali Linux Installation Notes

If you're running NTREE on Kali Linux:

**Pre-installed Tools:** Kali comes with most security tools already installed (nmap, metasploit, hydra, john, sqlmap, nikto, etc.). The setup script will detect these and skip reinstallation.

**Installation differences:**
- Faster installation (~15-30 minutes instead of 30-60) due to pre-installed tools
- Swap management is skipped (Kali uses different swap configuration)
- Platform detection warning is normal (no device tree on non-Pi hardware)

**Recommended: Run in non-interactive mode to skip confirmations:**
```bash
bash setup.sh --yes
```

Everything else works identically to Raspberry Pi OS.

### Fastest Way to Start (Using Launcher Script)

The easiest way to run NTREE is using the `start_pentest.sh` launcher:

```bash
# Interactive scope definition (guided setup)
./start_pentest.sh

# Or use a template and edit it
cp templates/scope_single_target.txt my_targets.txt
nano my_targets.txt
./start_pentest.sh --scope my_targets.txt

# View all options and examples
./start_pentest.sh --help
```

### Mode 1: Interactive with Claude Code (Recommended for Learning)

```bash
# Authenticate first (one-time)
claude auth login

# Using launcher script
./start_pentest.sh --mode interactive

# Or manually start Claude Code:
claude
# Then in Claude Code: "Start NTREE with scope: ~/ntree/templates/my_scope.txt"
```

NTREE will interactively walk you through the pentest, asking for approval at key points.

### Mode 2: Autonomous API Mode (Recommended for Automation)

```bash
# Set your API key
export ANTHROPIC_API_KEY='sk-ant-...'

# Using launcher script
./start_pentest.sh --scope templates/scope_internal_network.txt --mode api

# Or run directly:
python ntree-autonomous/ntree_agent.py --scope ~/scope.txt
```

**Best for:** Weekly/monthly recurring tests, production environments

### Mode 3: Autonomous SDK Mode (No API Key Needed)

```bash
# Authenticate with Claude Code first (one-time)
claude auth login

# Using launcher script
./start_pentest.sh --scope templates/scope_ctf_lab.txt --mode sdk

# Or run directly:
python ~/ntree/ntree-autonomous/ntree_agent_sdk.py --scope ~/ntree/templates/scope_example.txt
```

**Best for:** Advanced workflows, better MCP integration, Claude Code-like behavior

### Authentication Requirements

| Mode | Authentication |
|------|----------------|
| `api` | `ANTHROPIC_API_KEY` environment variable |
| `sdk` | `claude auth login` (Claude Code auth) |
| `interactive` | `claude auth login` (Claude Code auth) |

### What NTREE Does Automatically

1. ✅ Discover live hosts
2. ✅ Enumerate services
3. ✅ Test vulnerabilities
4. ✅ Map attack paths
5. ✅ Generate reports

**See [QUICK_DEPLOY_REFERENCE.md](QUICK_DEPLOY_REFERENCE.md) for detailed walkthrough.**

---

## 📁 Scope Templates

NTREE includes ready-to-use scope templates in the `templates/` directory:

| Template | Use Case |
|----------|----------|
| `scope_example.txt` | Main template with full syntax reference |
| `scope_single_target.txt` | Quick single host/application test |
| `scope_internal_network.txt` | Corporate LAN assessment |
| `scope_external.txt` | Internet-facing assets |
| `scope_active_directory.txt` | Windows AD environment |
| `scope_webapp.txt` | Web application testing |
| `scope_ctf_lab.txt` | HackTheBox/TryHackMe/Lab |
| `roe_example.txt` | Rules of Engagement template |

### Scope File Syntax

```bash
# Comments start with #
192.168.1.100              # Single IP address
192.168.1.0/24             # CIDR range (network block)
example.com                # Domain name
*.example.com              # Wildcard (all subdomains)
EXCLUDE 192.168.1.1        # Exclude from testing
```

### Quick Examples

```bash
# Lab/CTF testing
./start_pentest.sh --scope templates/scope_ctf_lab.txt --mode sdk

# Corporate pentest with ROE
./start_pentest.sh --scope templates/scope_internal_network.txt \
                   --roe templates/roe_example.txt

# Automated overnight scan
./start_pentest.sh --scope my_targets.txt --iterations 200 --yes
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [QUICK_DEPLOY_REFERENCE.md](QUICK_DEPLOY_REFERENCE.md) | ⭐ Quick reference for deployment |
| [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Complete deployment instructions |
| [ntree-autonomous/MODE_COMPARISON.md](ntree-autonomous/MODE_COMPARISON.md) | API vs SDK mode comparison |
| [ntree-autonomous/AUTONOMOUS_MODE.md](docs/AUTONOMOUS_MODE.md) | Autonomous mode guide (8,000+ words) |
| [PI5_INSTALLATION_GUIDE.md](PI5_INSTALLATION_GUIDE.md) | Complete Raspberry Pi setup instructions |
| [MCP_SERVER_IMPLEMENTATION.md](MCP_SERVER_IMPLEMENTATION.md) | MCP server development guide |
| [NTREE_CLAUDE_CODE_PROMPT.txt](NTREE_CLAUDE_CODE_PROMPT.txt) | System prompt for Claude Code |
| [NTREE_system_prompt_v2.txt](NTREE_system_prompt_v2.txt) | Detailed methodology specification |

---

## 🔬 Testing Methodology

NTREE follows a systematic 7-phase methodology:

### Phase 0: Initialization
- Parse and validate scope
- Load rules of engagement
- Create engagement workspace

### Phase 1: Reconnaissance
- Network discovery (ping sweep)
- OS fingerprinting
- Passive intelligence gathering

### Phase 2: Enumeration
- Service detection and versioning
- Banner grabbing
- Protocol-specific enumeration (SMB, LDAP, HTTP)

### Phase 3: Attack Surface Mapping
- Correlate services with known vulnerabilities
- Search exploit databases
- Prioritize targets by exploitability and impact

### Phase 4: Exploit Validation
- Test vulnerabilities safely (safe_mode=true by default)
- Validate default credentials (with approval)
- Confirm configuration weaknesses

### Phase 5: Post-Exploitation
- Test credential reuse across hosts
- Map lateral movement paths
- Identify privilege escalation opportunities
- Analyze trust relationships

### Phase 6: Risk Quantification
- Calculate CVSS scores
- Assess business impact
- Identify critical attack paths
- Measure time-to-compromise

### Phase 7: Reporting
- Generate executive summary (business language)
- Document technical findings with evidence
- Provide remediation roadmap
- Include attack narrative

### Findings & Exploitation Status

NTREE automatically categorizes all findings by exploitation status to distinguish between confirmed vulnerabilities and those requiring manual verification:

| Status | Badge | Description |
|--------|-------|-------------|
| ✅ **Confirmed** | Exploit proof exists | Successfully exploited with proof of compromise |
| ⚠️ **Needs Verification** | Evidence exists | Vulnerability detected with evidence but not exploited |
| ❓ **Requires Check** | Manual testing needed | Vulnerability identified, manual verification required |

**Reports automatically include:**
- Exploitation status badges for each finding
- Visual indicators in HTML reports (color-coded badges)
- Separate sections for confirmed vs. unconfirmed findings
- Manual verification notices for non-exploited vulnerabilities

**Best Practice:** Findings marked "Needs Verification" or "Requires Check" should be manually tested to confirm exploitability before inclusion in final reports to clients.

---

## 🛡️ Safety Features

### Multi-Layer Authorization

**Layer 1: Scope Validation**
- Every action validated against authorized scope
- Automatic blocking of out-of-scope targets

**Layer 2: Human Approval**
- High-risk actions require explicit approval
- Credential testing, exploitation, post-exploitation

**Layer 3: Rate Limiting**
- Max 3 credential attempts per account
- Adaptive scan timing based on target response
- Circuit breaker for unresponsive targets

**Layer 4: Hard Limits**
- No DoS attacks
- No destructive actions
- No data exfiltration (beyond proof-of-concept)
- No unauthorized scope expansion

**Layer 5: Audit Trail**
- Complete logging of all actions
- Evidence chain for findings
- Engagement replay capability

---

## 🎯 Use Cases

### Internal Network Pentest
Test internal network security from employee perspective.

**Scope:** `10.0.0.0/8`
**Duration:** 4-8 hours
**Deliverable:** Report with lateral movement paths, privilege escalation, Active Directory issues

### External Attack Surface Assessment
Identify publicly exposed vulnerabilities.

**Scope:** `company.com`, `*.company.com`
**Duration:** 2-4 hours
**Deliverable:** Internet-facing vulnerabilities, misconfigurations, exposed services

### Compliance Testing
Validate security controls for PCI-DSS, HIPAA, ISO 27001.

**Scope:** Specific systems per compliance requirement
**Duration:** Variable
**Deliverable:** Compliance-focused report with control validation

### Red Team Assessment
Simulate advanced persistent threat (APT) attack.

**Scope:** Full environment with specific objectives
**Duration:** Days to weeks
**Deliverable:** Attack narrative demonstrating breach potential

---

## 💡 Example Session

```bash
user: Start NTREE with scope: ~/ntree/engagements/acme_corp/scope.txt

ntree: [NTREE MODE ACTIVE]

       ───────────────────────────────────────────────────────
       [NTREE] PHASE: INITIALIZATION
       ───────────────────────────────────────────────────────

       OBSERVATION:
       Scope file loaded successfully
       • Included: 192.168.100.0/24 (254 potential hosts)
       • Excluded: 192.168.100.1 (gateway)
       • Excluded: 192.168.100.100 (production database)

       ANALYSIS:
       Class C network, likely small business or department
       Need to discover live hosts before enumeration

       HYPOTHESIS:
       "Expect 10-30 live hosts based on typical utilization"

       ACTION:
       Tool: nmap
       Command: sudo nmap -sn 192.168.100.0/24 -oX scan_output.xml
       Risk Level: LOW (passive discovery)
       Approval: ✓ not required

       ───────────────────────────────────────────────────────

       [Running scan...]

       Discovered 12 live hosts:
       • 192.168.100.10 - Windows Server 2019
       • 192.168.100.15 - Windows 10 Pro
       • 192.168.100.20 - Linux 4.x
       ...

       Transitioning to ENUMERATION phase...

[NTREE continues systematically through all phases]
```

---

## 🔧 Customization

### Custom Tools

Add your own tools to NTREE:

```python
# ntree_mcp/custom.py

async def my_custom_tool(target: str) -> dict:
    """Your custom security tool."""
    result = run_command(f"my_tool {target}")
    return parse_result(result)
```

Register in MCP server config.

### Custom Workflows

Modify phase logic in system prompt or create custom agents.

### Reporting Templates

Customize report format:

```bash
# Edit report template
nano ~/ntree/ntree-mcp-servers/ntree_mcp/templates/report_template.md
```

---

## 📊 Performance

Tested on Raspberry Pi 5 (8GB):

| Network Size | Discovery | Full Scan | Total Time |
|--------------|-----------|-----------|------------|
| /24 (254 hosts) | 5 min | 30 min | ~45 min |
| /16 (65K hosts) | 45 min | N/A* | 3-6 hours |
| Single host | 1 min | 5 min | ~15 min |

*Use targeted scanning for large networks

**Comparison:**
- Manual pentest of /24 network: 6-10 hours
- NTREE automated: 45 minutes
- **Time savings: 85-90%**

---

## 🤝 Contributing

We welcome contributions!

### Areas for Contribution
- Additional MCP servers (cloud, containers, APIs)
- Tool integrations (Burp, ZAP, Cobalt Strike)
- Report templates (compliance-specific)
- Exploit modules
- Documentation improvements

### How to Contribute
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 🔒 Responsible Use

### Legal Requirements
- **Authorization**: Always have written permission
- **Scope**: Never exceed authorized boundaries
- **Disclosure**: Report findings responsibly
- **Data**: Protect discovered sensitive information

### Ethical Guidelines
- Test to improve security, not to harm
- Respect privacy and confidentiality
- Give reasonable time for remediation
- Consider impact on systems and users

**NTREE is a tool for authorized security testing only. Unauthorized use is illegal and unethical.**

---

## 📜 License

NTREE is released under the MIT License. See [LICENSE](LICENSE) for details.

### Third-Party Tools
NTREE integrates many open-source security tools. Each tool has its own license:
- nmap: GPL 2.0
- Metasploit: BSD 3-Clause
- Impacket: Apache 2.0
- See individual tool licenses for details

---

## 🙏 Acknowledgments

Built on the shoulders of giants:

- **Anthropic** - Claude AI and MCP protocol
- **Security Community** - Open-source security tools
- **Raspberry Pi Foundation** - Affordable hardware
- **Contributors** - Everyone who improves NTREE

Special thanks to:
- nmap project (Gordon Lyon)
- Metasploit team
- Impacket developers
- All open-source security tool authors

---

## 📞 Support

### Getting Help
- **Documentation**: Start with QUICKSTART.md
- **Issues**: GitHub Issues for bugs
- **Discussions**: GitHub Discussions for questions
- **Security**: security@example.com for security issues

### Status
- Version: 2.0.0
- Status: Beta
- Last Updated: 2025-01-08

---

## 🗺️ Roadmap

### v2.1 (Q1 2025)
- [ ] Web application testing enhancements
- [ ] Cloud infrastructure support (AWS, Azure, GCP)
- [ ] Container security testing
- [ ] GUI dashboard for monitoring

### v2.2 (Q2 2025)
- [ ] Active Directory attack path visualization
- [ ] Automated exploitation (with approval)
- [ ] CI/CD integration for DevSecOps
- [ ] Team collaboration features

### v3.0 (Q3 2025)
- [ ] AI-powered exploit development
- [ ] Adaptive evasion techniques
- [ ] Real-time threat intelligence integration
- [ ] Multi-Pi distributed scanning

---

## 🌟 Star History

If NTREE helps your security testing, please star the repository!

---

## 📸 Screenshots

### NTREE in Action
![NTREE Console](docs/images/ntree-console.png)

### Sample Report
![Sample Report](docs/images/ntree-report.png)

### Network Visualization
![Network Map](docs/images/network-map.png)

---

**Happy (Ethical) Hacking! 🔐🚀**

---

*NTREE - Making professional penetration testing accessible to everyone.*
