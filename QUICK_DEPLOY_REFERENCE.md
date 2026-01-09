# NTREE Raspberry Pi - Quick Deploy Reference

**Version:** 2.0.0 | **Platform:** Raspberry Pi 5 | **Status:** Production Ready

---

## 🚀 One-Liner Deploy

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/ntree/main/quick_deploy.sh | bash
```

---

## 📦 Manual Deploy

```bash
# 1. Transfer package
scp ntree-2.0.0-rpi5-*.tar.gz pi@raspberrypi:~/

# 2. Extract
ssh pi@raspberrypi
tar -xzf ntree-*.tar.gz && cd ntree-*

# 3. Install
bash install_ntree_complete.sh

# 4. Verify
bash verify_installation.sh
```

---

## ⚙️ Installation Options

```bash
# Both modes (recommended)
bash install_ntree_complete.sh

# MCP mode only
bash install_ntree_complete.sh --mcp-only

# Autonomous mode only
bash install_ntree_complete.sh --autonomous-only
```

---

## 🎯 Quick Start

### MCP Mode (Interactive)
```bash
claude auth login
claude
# Say: "Start NTREE with scope: ~/ntree/templates/scope_example.txt"
```

### Autonomous Mode
```bash
# 1. Get API key: https://console.anthropic.com/
# 2. Configure
nano ~/ntree/config.json  # Set api_key

# 3. Run pentest (two modes available)
# API Mode (simple, recommended):
python ~/ntree/ntree-autonomous/ntree_agent.py --scope ~/ntree/templates/scope_example.txt

# SDK Mode (advanced, Claude Code-like):
python ~/ntree/ntree-autonomous/ntree_agent_sdk.py --scope ~/ntree/templates/scope_example.txt

# Or use helper script (uses API mode):
~/ntree/run_pentest.sh ~/ntree/templates/scope_example.txt
```

---

## 📊 Common Commands

```bash
# Quick start guide
~/ntree/quick_start.sh

# Run pentest
~/ntree/run_pentest.sh <scope_file>

# Enable automation
nano ~/ntree/config.json  # Set automation.enabled=true
sudo systemctl enable ntree-scheduler
sudo systemctl start ntree-scheduler

# Check status
sudo systemctl status ntree-scheduler

# View logs
tail -f ~/ntree/logs/ntree_agent.log

# Verify installation
bash verify_installation.sh
```

---

## 📁 Important Files

```bash
~/ntree/config.json              # Main configuration
~/ntree/templates/scope_example.txt  # Scope template
~/ntree/templates/roe_example.txt    # ROE template
~/ntree/logs/ntree_agent.log     # Agent logs
~/ntree/engagements/             # Pentest results
~/ntree/docs/                    # Documentation
```

---

## 🛠️ Troubleshooting

```bash
# Verify installation
bash verify_installation.sh

# Check logs
tail -100 ~/ntree/logs/ntree_agent.log

# Test tools
nmap --version
python3 -c "import anthropic; print('OK')"

# Re-run installation
bash install_ntree_complete.sh
```

---

## 📚 Documentation

```bash
~/ntree/docs/AUTONOMOUS_MODE.md      # Autonomous guide
~/ntree/docs/DEPLOYMENT_GUIDE.md     # Full deployment guide
~/ntree/quick_start.sh              # Interactive guide
```

---

## 🔒 Security Checklist

- [ ] Change default password: `passwd`
- [ ] Secure SSH: key-based auth only
- [ ] Enable firewall: `sudo ufw enable`
- [ ] Secure config: `chmod 600 ~/ntree/config.json`
- [ ] Get written authorization before testing
- [ ] Never test outside authorized scope

---

## 📞 Support

**Logs:** `~/ntree/logs/`
**Docs:** `~/ntree/docs/`
**Verify:** `bash verify_installation.sh`

---

## 📋 Installation Time

| Item | Time |
|------|------|
| Download/Transfer | 2-5 min |
| Extraction | 1 min |
| Installation | 30-60 min |
| Configuration | 5-10 min |
| **Total** | **40-75 min** |

---

## 💾 Disk Space

| Component | Size |
|-----------|------|
| Package (compressed) | ~50MB |
| Base tools | ~2GB |
| Security tools | ~3GB |
| Wordlists | ~500MB |
| Python environments | ~1GB |
| Documentation | ~10MB |
| **Total** | **~7-10GB** |

---

## 🎛️ System Requirements

- **Hardware:** Raspberry Pi 5 (4GB+ RAM)
- **OS:** Raspbian 64-bit (Bullseye+)
- **Network:** Internet connection
- **Storage:** 10GB free space
- **Optional:** External SSD for engagements

---

## 🔄 Automation Schedule Examples

```json
{
  "automation": {
    "schedule": "0 2 * * 0"    // Every Sunday 2 AM
  }
}
```

**Common schedules:**
- `"0 2 * * 0"` - Every Sunday 2 AM
- `"0 3 * * *"` - Every day 3 AM
- `"0 1 * * 1"` - Every Monday 1 AM
- `"0 0 1 * *"` - First of month midnight

---

## 💰 API Costs (Autonomous Mode)

**Claude Sonnet 4.5:**
- Input: $3/million tokens
- Output: $15/million tokens

**Estimated costs:**
- Small pentest (5 hosts): $1-2
- Medium pentest (20 hosts): $5-10
- Large pentest (100 hosts): $20-40
- Weekly automation: $10-50/month

---

## ✅ Package Contents

- **MCP Servers:** 6 servers (scope, scan, enum, vuln, post, report)
- **Autonomous Agent:** Full SDK integration
- **Security Tools:** 30+ tools
- **Documentation:** 15,000+ words
- **Templates:** Scope & ROE examples
- **Helper Scripts:** Quick start, backups, monitoring

---

## 🎯 Quick Win

```bash
# 1. Deploy (one command)
curl -fsSL https://URL/quick_deploy.sh | bash

# 2. Configure (2 minutes)
nano ~/ntree/config.json

# 3. Test (5 minutes)
~/ntree/run_pentest.sh ~/ntree/templates/scope_example.txt

# 4. Review results
cat ~/ntree/engagements/eng_*/reports/executive_report.md
```

**Total time:** ~45 minutes to first pentest! 🚀

---

**Created:** 2026-01-09 | **Version:** 2.0.0 | **Platform:** Raspberry Pi 5
