# NTREE Raspberry Pi 5 Deployment Guide

**Complete Step-by-Step Instructions**

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Hardware Setup](#hardware-setup)
3. [Package Transfer](#package-transfer)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Verification](#verification)
7. [First Pentest](#first-pentest)
8. [Automation Setup](#automation-setup)
9. [Troubleshooting](#troubleshooting)
10. [Post-Deployment](#post-deployment)

---

## Pre-Deployment Checklist

### Required Hardware

- [ ] Raspberry Pi 5 (4GB RAM minimum, 8GB recommended)
- [ ] MicroSD card (64GB minimum, 128GB+ recommended)
- [ ] Power supply (official Raspberry Pi 5 USB-C power adapter)
- [ ] Ethernet cable or WiFi configured
- [ ] (Optional) External SSD for engagement data storage

### Required Software

- [ ] Raspbian/Raspberry Pi OS 64-bit (Bullseye or newer)
- [ ] Internet connection
- [ ] SSH enabled (for remote access)

### Required Credentials

- [ ] Anthropic API key (for autonomous mode) - Get from https://console.anthropic.com/
- [ ] Claude Code Pro subscription (for MCP mode) - Optional
- [ ] GitHub account (for deploying your MCP servers) - Optional

### Preparation

- [ ] Download NTREE deployment package
- [ ] Verify package checksum
- [ ] Have authorized pentest scope ready
- [ ] Obtain written authorization for testing

---

## Hardware Setup

### 1. Prepare Raspberry Pi

```bash
# On your computer
# 1. Download Raspberry Pi Imager
# https://www.raspberrypi.com/software/

# 2. Flash Raspbian 64-bit to SD card
# - OS: Raspberry Pi OS (64-bit)
# - Enable SSH in advanced settings
# - Configure WiFi if needed
# - Set hostname: ntree (optional)
# - Set username: pi (or your choice)

# 3. Insert SD card into Raspberry Pi
# 4. Connect power and ethernet
# 5. Wait for first boot (2-3 minutes)
```

### 2. Find Raspberry Pi IP Address

```bash
# Option 1: Check router admin panel
# Option 2: Use network scanner
nmap -sn 192.168.1.0/24

# Option 3: Connect monitor and keyboard
# Run: hostname -I
```

### 3. Initial Connection

```bash
# SSH to Raspberry Pi
ssh pi@<raspberry-pi-ip>
# Or
ssh pi@ntree.local  # if mDNS working

# Accept host key fingerprint
# Enter password (default: raspberry, or what you set)
```

### 4. Update System

```bash
# On Raspberry Pi
sudo apt update
sudo apt upgrade -y
sudo reboot
```

Wait 1-2 minutes, then reconnect.

---

## Package Transfer

### Option 1: Direct Download (Recommended)

```bash
# On Raspberry Pi
cd ~
wget https://github.com/YOUR_USERNAME/ntree/releases/download/v2.0.0/ntree-2.0.0-rpi5-*.tar.gz

# Verify checksum
wget https://github.com/YOUR_USERNAME/ntree/releases/download/v2.0.0/ntree-2.0.0-rpi5-*.tar.gz.sha256
sha256sum -c ntree-2.0.0-rpi5-*.tar.gz.sha256
```

### Option 2: SCP Transfer

```bash
# On your computer
scp ntree-2.0.0-rpi5-*.tar.gz pi@<raspberry-pi-ip>:~/
scp ntree-2.0.0-rpi5-*.tar.gz.sha256 pi@<raspberry-pi-ip>:~/

# On Raspberry Pi
cd ~
sha256sum -c ntree-2.0.0-rpi5-*.tar.gz.sha256
```

### Option 3: USB Transfer

```bash
# 1. Copy package to USB drive on your computer
# 2. Insert USB into Raspberry Pi
# 3. Mount and copy

sudo mkdir /mnt/usb
sudo mount /dev/sda1 /mnt/usb
cp /mnt/usb/ntree-*.tar.gz ~/
sudo umount /mnt/usb
```

---

## Installation

### 1. Extract Package

```bash
# On Raspberry Pi
cd ~
tar -xzf ntree-2.0.0-rpi5-*.tar.gz
cd ntree-2.0.0-rpi5-*
```

You should see:
```
├── install_ntree_complete.sh
├── verify_installation.sh
├── ntree-mcp-servers/
├── ntree-autonomous/
├── scripts/
├── templates/
├── docs/
└── README.md
```

### 2. Choose Installation Mode

**Option A: Complete Installation (Recommended)**
```bash
bash install_ntree_complete.sh
# Installs both MCP and Autonomous modes
# Time: 30-60 minutes
```

**Option B: MCP Mode Only**
```bash
bash install_ntree_complete.sh --mcp-only
# For Claude Code interactive testing only
# Time: 20-30 minutes
```

**Option C: Autonomous Mode Only**
```bash
bash install_ntree_complete.sh --autonomous-only
# For automated testing only
# Time: 25-40 minutes
```

### 3. Monitor Installation

The installer will:
1. ✅ Check platform (Raspberry Pi 5)
2. ✅ Update system packages
3. ✅ Install base dependencies (build tools, Python, etc.)
4. ✅ Install security tools (nmap, nikto, gobuster, etc.)
5. ✅ Install modern tools (nuclei, testssl.sh)
6. ✅ Install Python tools (impacket, etc.)
7. ✅ Download wordlists (~500MB)
8. ✅ Set up NTREE directories
9. ✅ Install MCP servers (if selected)
10. ✅ Install autonomous agent (if selected)
11. ✅ Create helper scripts

**Expected output:**
```
[INFO] Checking platform...
[SUCCESS] Detected: Raspberry Pi 5 Model B Rev 1.0
[INFO] Installing base dependencies...
[SUCCESS] Base dependencies installed
...
[SUCCESS] NTREE Installation Complete!
```

### 4. Reload Shell

```bash
source ~/.bashrc
```

---

## Configuration

### For MCP Mode

```bash
# 1. Authenticate with Claude Code
claude auth login
# Follow browser prompts to authenticate

# 2. Configure MCP servers (if needed)
cd ~/ntree/ntree-mcp-servers
# Edit ~/.config/claude-code/mcp-servers.json if needed

# 3. Test MCP servers
python -m ntree_mcp.scope --version
```

### For Autonomous Mode

```bash
# 1. Get Anthropic API key
# Visit: https://console.anthropic.com/
# Navigate to: Settings > API Keys
# Click: Create Key
# Copy your API key (sk-ant-...)

# 2. Configure NTREE
nano ~/ntree/config.json
```

Update:
```json
{
  "anthropic": {
    "api_key": "sk-ant-YOUR_API_KEY_HERE",
    "model": "claude-sonnet-4-5-20250929"
  }
}
```

Save and exit (Ctrl+X, Y, Enter)

```bash
# 3. Secure config file
chmod 600 ~/ntree/config.json

# 4. Test API key
python3 << 'EOF'
import json
from anthropic import Anthropic

with open('/home/pi/ntree/config.json') as f:
    config = json.load(f)

client = Anthropic(api_key=config['anthropic']['api_key'])
response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=10,
    messages=[{"role": "user", "content": "Hi"}]
)
print("API key is valid!")
EOF
```

---

## Verification

### Run Verification Script

```bash
cd ~/ntree-2.0.0-rpi5-*
bash verify_installation.sh
```

**Expected output:**
```
NTREE Installation Verification

Checking security tools...
✓ nmap: /usr/bin/nmap
✓ nikto: /usr/bin/nikto
✓ gobuster: /usr/bin/gobuster
...

Checking Python packages...
✓ anthropic
✓ pydantic
✓ python-nmap

Checking NTREE files...
✓ ~/ntree
✓ ~/ntree/engagements
✓ ~/ntree/templates
...

VERIFICATION RESULTS
Passed: 25
Failed: 0

✓ All checks passed! NTREE is ready to use.
```

### Manual Verification

```bash
# Check NTREE installation
ls -la ~/ntree

# Check tools
nmap --version
nuclei -version
crackmapexec --version

# Check Python environment
source ~/ntree/ntree-autonomous/venv/bin/activate
python --version
pip list | grep anthropic
deactivate
```

---

## First Pentest

### Prepare Scope File

```bash
# Create your scope file
nano ~/ntree/templates/my_first_pentest.txt
```

Add:
```
# My First Pentest - Lab Environment Only!
# IMPORTANT: Only test systems you own or have written permission to test

# Example lab network (adjust to your lab)
192.168.1.100
192.168.1.101

# Excluded (gateway, production systems)
EXCLUDE 192.168.1.1
```

Save and exit.

### Option A: Run with MCP Mode

```bash
# Start Claude Code
claude

# In Claude Code interface, type:
# "Start NTREE with scope: ~/ntree/templates/my_first_pentest.txt"

# Follow Claude's guided process
# Claude will walk you through each phase
# You approve actions interactively
```

### Option B: Run with Autonomous Mode

```bash
# Run autonomous pentest
~/ntree/run_pentest.sh ~/ntree/templates/my_first_pentest.txt

# Or use full command
cd ~/ntree/ntree-autonomous
source venv/bin/activate
python ntree_agent.py \
    --scope ~/ntree/templates/my_first_pentest.txt \
    --max-iterations 50
```

### Monitor Progress

```bash
# Watch logs in real-time (new terminal)
tail -f ~/ntree/logs/ntree_agent.log

# Check resource usage
htop
```

### Review Results

```bash
# List engagements
ls -lat ~/ntree/engagements/

# View latest engagement
cd ~/ntree/engagements/eng_*/

# Check findings
ls findings/
cat findings/finding_001.json

# View reports
ls reports/
# Open HTML report in browser or view markdown
cat reports/executive_report.md
```

---

## Automation Setup

### Enable Scheduled Pentests

```bash
# 1. Configure automation
nano ~/ntree/config.json
```

Update:
```json
{
  "automation": {
    "enabled": true,
    "schedule": "0 2 * * 0",  // Every Sunday at 2 AM
    "scope_file": "/home/pi/ntree/templates/weekly_scan.txt",
    "roe_file": "/home/pi/ntree/templates/weekly_roe.txt",
    "notification_webhook": ""  // Optional: Slack webhook
  }
}
```

```bash
# 2. Create weekly scope file
cp ~/ntree/templates/scope_example.txt ~/ntree/templates/weekly_scan.txt
nano ~/ntree/templates/weekly_scan.txt
# Adjust for your recurring test targets

# 3. Enable systemd service
sudo systemctl enable ntree-scheduler
sudo systemctl start ntree-scheduler

# 4. Check status
sudo systemctl status ntree-scheduler

# 5. View scheduler logs
tail -f ~/ntree/logs/scheduler.log
```

### Schedule Options

```
Cron Format: minute hour day_month month day_week

Examples:
"0 2 * * 0"    # Every Sunday at 2:00 AM
"0 3 * * *"    # Every day at 3:00 AM
"0 1 * * 1"    # Every Monday at 1:00 AM
"0 22 * * 5"   # Every Friday at 10:00 PM
"0 0 1 * *"    # First day of every month at midnight
```

---

## Troubleshooting

### Installation Issues

**Problem:** Package installation fails
```bash
# Solution: Update package lists
sudo apt update
sudo apt install -f  # Fix broken dependencies
```

**Problem:** Python version too old
```bash
# Check version
python3 --version

# If < 3.10, install newer version
sudo apt install python3.11 python3.11-venv python3.11-dev
```

**Problem:** Out of disk space
```bash
# Check space
df -h

# Clean up
sudo apt clean
sudo apt autoremove
```

### Network Issues

**Problem:** Cannot download packages
```bash
# Check internet connection
ping -c 4 8.8.8.8

# Check DNS
ping -c 4 google.com

# Try different mirror
sudo nano /etc/apt/sources.list
```

### Tool Issues

**Problem:** nmap not found
```bash
# Reinstall
sudo apt install --reinstall nmap
```

**Problem:** MCP servers won't start
```bash
# Check Python installation
cd ~/ntree/ntree-mcp-servers
source venv/bin/activate
python -c "import ntree_mcp.scope; print('OK')"
```

**Problem:** Autonomous agent fails
```bash
# Check API key
cat ~/ntree/config.json | grep api_key

# Test API
cd ~/ntree/ntree-autonomous
source venv/bin/activate
python -c "from anthropic import Anthropic; print('SDK OK')"
```

### Permission Issues

**Problem:** Permission denied errors
```bash
# Fix ownership
sudo chown -R pi:pi ~/ntree

# Fix permissions
chmod +x ~/ntree/*.sh
chmod 600 ~/ntree/config.json
```

### Getting More Help

```bash
# Check all logs
ls -la ~/ntree/logs/

# View specific log
tail -100 ~/ntree/logs/ntree_agent.log

# Run verification
bash ~/ntree-2.0.0-rpi5-*/verify_installation.sh

# Manual test
nmap --version
python3 --version
claude --version
```

---

## Post-Deployment

### Security Hardening

```bash
# 1. Change default password
passwd

# 2. Secure SSH
sudo nano /etc/ssh/sshd_config
# Disable password auth, enable key-only
# PasswordAuthentication no
# PubkeyAuthentication yes

# 3. Enable firewall
sudo apt install ufw
sudo ufw allow ssh
sudo ufw enable

# 4. Regular updates
sudo apt update && sudo apt upgrade -y

# 5. Secure API keys
chmod 600 ~/ntree/config.json
# Never commit config.json to git
```

### Backup Strategy

```bash
# 1. Backup engagement data
tar -czf ~/ntree-backup-$(date +%Y%m%d).tar.gz ~/ntree/engagements

# 2. Backup configuration
cp ~/ntree/config.json ~/ntree/config.json.backup

# 3. Automated backups (add to crontab)
crontab -e
# Add: 0 4 * * 0 tar -czf ~/backups/ntree-$(date +\%Y\%m\%d).tar.gz ~/ntree/engagements
```

### Monitoring

```bash
# 1. Set up monitoring script
cat > ~/monitor_ntree.sh << 'EOF'
#!/bin/bash
echo "NTREE Status Report - $(date)"
echo "================================"
echo ""
echo "Disk Usage:"
df -h | grep -E "Filesystem|/dev/root"
echo ""
echo "Running Processes:"
ps aux | grep -E "ntree|claude" | grep -v grep
echo ""
echo "Recent Engagements:"
ls -lat ~/ntree/engagements/ | head -5
echo ""
echo "Scheduler Status:"
systemctl status ntree-scheduler --no-pager | head -5
EOF

chmod +x ~/monitor_ntree.sh

# 2. Run monitoring
~/monitor_ntree.sh
```

### Optimization

```bash
# 1. Move wordlists to external storage (optional)
# If you have external SSD/USB
sudo mkdir /mnt/external
sudo mount /dev/sda1 /mnt/external
mv ~/wordlists /mnt/external/
ln -s /mnt/external/wordlists ~/wordlists

# 2. Move engagement data to external storage
mv ~/ntree/engagements /mnt/external/ntree-engagements
ln -s /mnt/external/ntree-engagements ~/ntree/engagements

# 3. Configure log rotation
sudo nano /etc/logrotate.d/ntree
```

Add:
```
/home/pi/ntree/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 pi pi
}
```

### Maintenance Schedule

**Weekly:**
- [ ] Review logs: `tail -100 ~/ntree/logs/ntree_agent.log`
- [ ] Check disk space: `df -h`
- [ ] Backup engagements: `~/ntree/backup_engagement.sh eng_*`

**Monthly:**
- [ ] Update system: `sudo apt update && sudo apt upgrade -y`
- [ ] Update tools: `nuclei -update-templates`
- [ ] Review API costs: https://console.anthropic.com/settings/usage
- [ ] Archive old engagements

**Quarterly:**
- [ ] Full system backup
- [ ] Review and update scope templates
- [ ] Update ROE templates
- [ ] Review security configurations

---

## Quick Reference

### Common Commands

```bash
# MCP Mode
claude                          # Start Claude Code
claude auth login               # Authenticate

# Autonomous Mode
~/ntree/run_pentest.sh <scope>  # Run single pentest
~/ntree/start_scheduler.sh      # Start automation
~/ntree/stop_scheduler.sh       # Stop automation

# Monitoring
tail -f ~/ntree/logs/ntree_agent.log        # Watch logs
sudo systemctl status ntree-scheduler       # Check scheduler
~/monitor_ntree.sh                          # Status report

# Utilities
bash verify_installation.sh     # Verify installation
~/ntree/quick_start.sh         # Quick start guide
~/ntree/backup_engagement.sh   # Backup data
```

### File Locations

```
~/ntree/
├── config.json                # Main configuration
├── engagements/               # Pentest data
├── templates/                 # Scope/ROE templates
├── logs/                      # Log files
├── ntree-mcp-servers/        # MCP servers
├── ntree-autonomous/         # Autonomous agent
└── tools/                     # Additional tools

~/.config/claude-code/         # Claude Code config
~/.claude/                     # Claude Code data
/etc/systemd/system/ntree-scheduler.service  # Systemd service
```

### Support Resources

- **Documentation:** `~/ntree/docs/`
- **Logs:** `~/ntree/logs/`
- **Templates:** `~/ntree/templates/`
- **Verification:** `bash verify_installation.sh`

---

## Deployment Checklist

### Pre-Installation
- [ ] Raspberry Pi 5 with Raspbian 64-bit
- [ ] Internet connection verified
- [ ] SSH access working
- [ ] Deployment package downloaded
- [ ] Checksum verified

### Installation
- [ ] Package extracted
- [ ] Installation script run
- [ ] All tools installed
- [ ] Shell reloaded
- [ ] Verification passed

### Configuration
- [ ] API key obtained (if using autonomous)
- [ ] config.json configured
- [ ] Scope files created
- [ ] ROE files created
- [ ] Permissions secured

### Testing
- [ ] First pentest completed
- [ ] Results reviewed
- [ ] Reports generated
- [ ] Logs verified

### Automation (Optional)
- [ ] Schedule configured
- [ ] Systemd service enabled
- [ ] Notifications set up
- [ ] First automated run tested

### Post-Deployment
- [ ] Backups configured
- [ ] Monitoring set up
- [ ] Security hardened
- [ ] Documentation reviewed

---

**Deployment Complete! 🎯**

Your Raspberry Pi 5 is now a fully functional autonomous penetration testing platform.

For questions or issues, check:
- Documentation: `~/ntree/docs/`
- Logs: `~/ntree/logs/`
- Verification: `bash verify_installation.sh`

Happy hacking! 🚀
