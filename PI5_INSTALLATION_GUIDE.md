# NTREE Raspberry Pi 5 Installation Guide

Complete setup guide for deploying NTREE on Raspberry Pi 5 with Claude Code Pro.

---

## Hardware Requirements

- **Raspberry Pi 5** (4GB or 8GB RAM recommended)
- **MicroSD Card** (64GB+ recommended)
- **Power Supply** (Official Pi 5 27W USB-C power supply)
- **Ethernet Connection** (preferred over WiFi for stability)
- **Cooling** (Active cooling recommended for sustained scanning)

---

## Software Prerequisites

- **Raspberry Pi OS** (64-bit, Bookworm or later)
- **Claude Code CLI** (installed and configured)
- **Python 3.11+** (for MCP servers)
- **Node.js 18+** (if using JavaScript MCP servers)

---

## Installation Steps

### 1. Prepare Raspberry Pi OS

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential build tools
sudo apt install -y build-essential git curl wget \
    python3-pip python3-venv libssl-dev libffi-dev \
    python3-dev cargo
```

### 2. Install Claude Code

```bash
# Download and install Claude Code
curl -fsSL https://claude.ai/install-cli.sh | bash

# Verify installation
claude --version

# Authenticate (requires Claude Pro subscription)
claude auth login
```

### 3. Install Security Tools

#### Core Tools
```bash
# Network scanning
sudo apt install -y nmap masscan

# DNS enumeration
sudo apt install -y dnsenum dnsutils

# SMB/Windows tools
sudo apt install -y enum4linux smbclient cifs-utils

# Web tools
sudo apt install -y nikto dirb gobuster

# SSL/TLS testing
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl
chmod +x ~/tools/testssl/testssl.sh
echo 'export PATH="$HOME/tools/testssl:$PATH"' >> ~/.bashrc

# Vulnerability scanner
wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.4_linux_arm64.zip
unzip nuclei_3.1.4_linux_arm64.zip
sudo mv nuclei /usr/local/bin/
rm nuclei_3.1.4_linux_arm64.zip

# OSINT tools
sudo apt install -y theharvester
```

#### Python Security Tools
```bash
# Create virtual environment for security tools
python3 -m venv ~/venvs/sectools
source ~/venvs/sectools/bin/activate

# Install impacket (Windows protocol tools)
pip install impacket

# Install crackmapexec
sudo apt install -y crackmapexec

# Or install from pip if apt version outdated:
pip install pipx
pipx ensurepath
pipx install crackmapexec

# Install other Python tools
pip install ldap3 pycryptodome requests beautifulsoup4

# Make venv activation automatic for ntree
echo 'alias ntree-env="source ~/venvs/sectools/bin/activate"' >> ~/.bashrc
```

#### Exploitation Tools (Optional - if safe testing environment)
```bash
# Metasploit Framework (large install, 30-60 min on Pi)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
sudo ./msfinstall

# Hydra (credential testing)
sudo apt install -y hydra

# John the Ripper (password cracking)
sudo apt install -y john

# Hashcat (advanced password cracking - CPU only on Pi)
sudo apt install -y hashcat
```

#### Wordlists
```bash
# Create wordlists directory
mkdir -p ~/wordlists

# Install SecLists (comprehensive wordlist collection)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists

# Download rockyou wordlist
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O ~/wordlists/rockyou.txt
```

### 4. Install NTREE MCP Servers

```bash
# Create NTREE directory
mkdir -p ~/ntree
cd ~/ntree

# Clone NTREE MCP server repository (you'll create this)
git clone https://github.com/YOUR_USERNAME/ntree-mcp-servers.git
cd ntree-mcp-servers

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install MCP servers
pip install -e .
```

### 5. Configure Claude Code for NTREE

Create Claude Code MCP configuration:

```bash
# Create config directory if not exists
mkdir -p ~/.config/claude-code

# Edit MCP server configuration
nano ~/.config/claude-code/mcp-servers.json
```

Add NTREE MCP servers:

```json
{
  "mcpServers": {
    "ntree-scope": {
      "command": "python",
      "args": ["-m", "ntree_mcp.scope"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    },
    "ntree-scan": {
      "command": "python",
      "args": ["-m", "ntree_mcp.scan"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    },
    "ntree-enum": {
      "command": "python",
      "args": ["-m", "ntree_mcp.enum"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    },
    "ntree-vuln": {
      "command": "python",
      "args": ["-m", "ntree_mcp.vuln"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    },
    "ntree-post": {
      "command": "python",
      "args": ["-m", "ntree_mcp.post"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    },
    "ntree-report": {
      "command": "python",
      "args": ["-m", "ntree_mcp.report"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree"
      }
    }
  }
}
```

### 6. Set Up NTREE Workspace

```bash
# Create engagement directory structure
mkdir -p ~/ntree/engagements
mkdir -p ~/ntree/templates
mkdir -p ~/ntree/tools

# Create example scope file
cat > ~/ntree/templates/scope_example.txt << 'EOF'
# Target Network Ranges (CIDR notation)
192.168.1.0/24
10.0.0.0/24

# Individual IPs
192.168.1.50
192.168.1.60

# Domains
example.com
*.internal.example.com

# Forbidden/Excluded
# Format: EXCLUDE <ip or range>
EXCLUDE 192.168.1.1
EXCLUDE 192.168.1.100
EOF

# Create example Rules of Engagement
cat > ~/ntree/templates/roe_example.txt << 'EOF'
# Rules of Engagement

ENGAGEMENT_TYPE: internal_pentest
STEALTH_LEVEL: normal
AUTHORIZATION: written_authorization_on_file.pdf

ALLOWED_ACTIONS:
  - network_scanning
  - service_enumeration
  - vulnerability_testing
  - safe_exploitation
  - credential_testing (max 3 attempts)
  - post_exploitation (with approval)

FORBIDDEN_ACTIONS:
  - denial_of_service
  - data_deletion
  - data_exfiltration (beyond proof-of-concept)
  - social_engineering
  - physical_access

APPROVAL_REQUIRED:
  - credential_dumping
  - privilege_escalation
  - domain_controller_access
  - production_system_exploitation

RATE_LIMITS:
  - credential_attempts: 3 per account
  - scan_timing: -T3 (normal)
  - web_requests: 50 per second max

CONTACTS:
  - primary: security-team@example.com
  - emergency: +1-555-0100
EOF

# Set proper permissions
chmod 600 ~/ntree/templates/scope_example.txt
chmod 600 ~/ntree/templates/roe_example.txt
```

### 7. Install NTREE System Prompt

```bash
# Copy NTREE system prompt to Claude Code custom prompts directory
mkdir -p ~/.config/claude-code/prompts

# Copy the NTREE prompt (you'll need to transfer the file to Pi)
cp NTREE_CLAUDE_CODE_PROMPT.txt ~/.config/claude-code/prompts/ntree.txt
```

### 8. Configure Sudo for Security Tools

Some tools require root privileges. Configure safe sudo access:

```bash
# Edit sudoers file
sudo visudo

# Add these lines (replace 'pi' with your username):
pi ALL=(ALL) NOPASSWD: /usr/bin/nmap
pi ALL=(ALL) NOPASSWD: /usr/bin/masscan
pi ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
```

**Security Note:** Only add NOPASSWD for tools you trust. Always validate scope before running.

### 9. Network Configuration

For optimal performance:

```bash
# Set static IP (edit /etc/dhcpcd.conf)
sudo nano /etc/dhcpcd.conf

# Add at the end (adjust for your network):
interface eth0
static ip_address=192.168.1.250/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1 8.8.8.8

# Enable IP forwarding (if Pi will be used as pivot)
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Reboot to apply network changes
sudo reboot
```

### 10. Test Installation

After reboot:

```bash
# Activate security tools environment
source ~/venvs/sectools/bin/activate

# Test tools
nmap --version
masscan --version
crackmapexec --version
nuclei -version
enum4linux -h

# Test MCP servers
python -m ntree_mcp.scope --test

# Start Claude Code
claude

# In Claude Code, test NTREE activation:
# Type: "Start NTREE test mode"
```

---

## Performance Tuning for Raspberry Pi 5

### Overclocking (Optional - improves scan speed)

```bash
# Edit boot config
sudo nano /boot/firmware/config.txt

# Add these lines for modest overclock:
over_voltage=2
arm_freq=2600

# Reboot
sudo reboot
```

**Warning:** Ensure adequate cooling before overclocking.

### Memory Configuration

```bash
# Increase swap for large scans (if using 4GB model)
sudo dphys-swapfile swapoff
sudo nano /etc/dphys-swapfile
# Set: CONF_SWAPSIZE=4096
sudo dphys-swapfile setup
sudo dphys-swapfile swapon
```

### Storage Optimization

```bash
# Use tmpfs for scan outputs (faster, clears on reboot)
sudo mkdir /mnt/ramdisk
sudo mount -t tmpfs -o size=512M tmpfs /mnt/ramdisk

# Make permanent
echo "tmpfs /mnt/ramdisk tmpfs defaults,size=512M 0 0" | sudo tee -a /etc/fstab
```

---

## Updating NTREE

```bash
# Update MCP servers
cd ~/ntree/ntree-mcp-servers
git pull
source venv/bin/activate
pip install --upgrade -e .

# Update security tools
sudo apt update && sudo apt upgrade -y

# Update Python tools
source ~/venvs/sectools/bin/activate
pip install --upgrade impacket crackmapexec

# Update nuclei templates
nuclei -update-templates

# Update wordlists (SecLists)
cd ~/wordlists/SecLists && git pull
```

---

## Troubleshooting

### MCP Servers Not Found

```bash
# Check MCP server configuration
cat ~/.config/claude-code/mcp-servers.json

# Test MCP server directly
python -m ntree_mcp.scope --test

# Check logs
journalctl --user -u claude-code -f
```

### Permission Denied Errors

```bash
# Fix tool permissions
sudo chmod +x /usr/local/bin/nuclei
sudo chmod +x ~/tools/testssl/testssl.sh

# Verify sudo configuration
sudo -l
```

### Out of Memory Errors

```bash
# Check memory usage
free -h

# Increase swap (see Memory Configuration above)

# Reduce scan intensity
# Use -T3 instead of -T4 in nmap
# Scan smaller subnets at a time
```

### Slow Scan Performance

```bash
# Check network connection
ping -c 4 google.com
ethtool eth0 | grep Speed

# Use Ethernet instead of WiFi
# Ensure Pi is on same network segment as targets
# Use masscan for initial discovery (faster than nmap)
```

### Tool Not Found

```bash
# Ensure security tools environment is activated
source ~/venvs/sectools/bin/activate

# Check PATH
echo $PATH

# Reinstall missing tool
pip install <tool_name>
# or
sudo apt install <tool_name>
```

---

## Maintenance Schedule

### Daily (During Active Engagement)
- Check disk space: `df -h`
- Monitor scan output sizes
- Review engagement logs

### Weekly
- Update nuclei templates: `nuclei -update-templates`
- Check for tool updates: `sudo apt update && sudo apt list --upgradable`

### Monthly
- Full system update: `sudo apt update && sudo apt upgrade -y`
- Update Python packages
- Update wordlists
- Review and archive old engagements

---

## Security Considerations

### Protecting Engagement Data

```bash
# Encrypt engagement directory
sudo apt install -y ecryptfs-utils

# Create encrypted directory
mkdir ~/ntree/engagements_encrypted
sudo mount -t ecryptfs ~/ntree/engagements_encrypted ~/ntree/engagements

# Make encryption automatic (follow prompts)
ecryptfs-setup-private
```

### Secure Storage of Credentials

```bash
# Never store credentials in plaintext
# Use encrypted files for any discovered credentials

# Install pass (password manager)
sudo apt install -y pass gnupg

# Initialize password store
gpg --gen-key
pass init "your-gpg-key-id"

# Store credentials
pass insert ntree/engagements/client1/admin_creds
```

### Network Isolation

- Keep Pi on isolated pentest network when possible
- Use VLAN segmentation
- Never connect to production WiFi during engagement
- Disable unnecessary services: `sudo systemctl disable <service>`

---

## Backup & Recovery

### Backup Engagements

```bash
# Create backup script
cat > ~/ntree/backup_engagement.sh << 'EOF'
#!/bin/bash
ENGAGEMENT_ID=$1
BACKUP_DIR="/media/usb/ntree_backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/${ENGAGEMENT_ID}_${DATE}.tar.gz \
    ~/ntree/engagements/$ENGAGEMENT_ID/

echo "Backup created: $BACKUP_DIR/${ENGAGEMENT_ID}_${DATE}.tar.gz"
EOF

chmod +x ~/ntree/backup_engagement.sh

# Run backup
~/ntree/backup_engagement.sh eng_20250108_001
```

### Full System Backup

```bash
# Backup entire SD card (run from another Linux machine)
# Insert SD card, identify device (e.g., /dev/sdb)
sudo dd if=/dev/sdb of=ntree_pi_backup.img bs=4M status=progress

# Compress backup
gzip ntree_pi_backup.img
```

---

## Next Steps

1. **Test in Lab**: Set up vulnerable VMs (Metasploitable, DVWA) to test NTREE
2. **Customize Templates**: Adjust scope and RoE templates for your needs
3. **Develop MCP Servers**: Implement the Python MCP servers (see MCP_SERVER_IMPLEMENTATION.md)
4. **Create Engagement Workflow**: Document your specific pentest process
5. **Train with Examples**: Run through sample engagements to learn the system

---

## Resources

- [Raspberry Pi Documentation](https://www.raspberrypi.com/documentation/)
- [Claude Code Documentation](https://claude.ai/docs/code)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Kali Linux Tools](https://www.kali.org/tools/) (reference for tool usage)
- [NTREE GitHub Repository](https://github.com/YOUR_USERNAME/ntree-mcp-servers)

---

## Support & Community

- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Join community discussions
- **Updates**: Watch repository for updates
- **Security**: Report security issues privately to security@example.com

---

**Installation Complete!** Your Raspberry Pi 5 is now configured as an NTREE penetration testing platform powered by Claude Code Pro.
