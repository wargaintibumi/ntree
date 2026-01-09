# NTREE MCP Server Implementation Guide

This guide provides the implementation details for NTREE MCP servers that integrate with Claude Code on Raspberry Pi 5.

---

## Architecture Overview

```
Claude Code
    ↓
MCP Protocol
    ↓
NTREE MCP Servers (Python)
    ↓
Security CLI Tools (nmap, enum4linux, etc.)
    ↓
Target Network
```

Each MCP server is a lightweight Python wrapper that:
1. Validates inputs against scope
2. Executes security tools via subprocess
3. Parses tool output into structured JSON
4. Returns results to Claude Code

---

## Project Structure

```
ntree-mcp-servers/
├── README.md
├── setup.py
├── requirements.txt
├── ntree_mcp/
│   ├── __init__.py
│   ├── scope.py          # Scope validation server
│   ├── scan.py           # Network scanning server
│   ├── enum.py           # Service enumeration server
│   ├── vuln.py           # Vulnerability testing server
│   ├── post.py           # Post-exploitation server
│   ├── report.py         # Reporting server
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── scope_parser.py    # CIDR/IP validation
│   │   ├── nmap_parser.py     # Parse nmap XML
│   │   ├── command_runner.py  # Safe subprocess execution
│   │   └── logger.py          # Audit logging
│   └── tests/
│       ├── test_scope.py
│       ├── test_scan.py
│       └── ...
└── examples/
    ├── scope_example.txt
    └── engagement_example.json
```

---

## Core Implementation Files

### 1. setup.py

```python
from setuptools import setup, find_packages

setup(
    name="ntree-mcp-servers",
    version="2.0.0",
    description="NTREE MCP servers for Claude Code penetration testing",
    author="Your Name",
    author_email="you@example.com",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "mcp>=1.0.0",
        "pydantic>=2.0.0",
        "python-nmap>=0.7.1",
        "ipaddress",
        "xmltodict",
        "aiofiles",
    ],
    entry_points={
        "console_scripts": [
            "ntree-scope=ntree_mcp.scope:main",
            "ntree-scan=ntree_mcp.scan:main",
            "ntree-enum=ntree_mcp.enum:main",
            "ntree-vuln=ntree_mcp.vuln:main",
            "ntree-post=ntree_mcp.post:main",
            "ntree-report=ntree_mcp.report:main",
        ],
    },
)
```

### 2. requirements.txt

```
mcp>=1.0.0
pydantic>=2.0.0
python-nmap>=0.7.1
xmltodict>=0.13.0
aiofiles>=23.0.0
ipaddress
typing-extensions
```

---

## MCP Server Implementations

### utils/command_runner.py

```python
"""Safe subprocess command execution with timeout and logging."""

import subprocess
import shlex
import logging
from typing import Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class CommandRunner:
    """Execute shell commands safely with logging and timeout."""

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def run(
        self,
        command: str,
        shell: bool = False,
        capture_output: bool = True,
        check: bool = False,
        cwd: Optional[Path] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a command and return (returncode, stdout, stderr).

        Args:
            command: Command to execute
            shell: Whether to use shell (avoid when possible)
            capture_output: Capture stdout/stderr
            check: Raise exception on non-zero exit
            cwd: Working directory

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        logger.info(f"Executing command: {command}")

        try:
            if not shell:
                cmd_list = shlex.split(command)
            else:
                cmd_list = command

            result = subprocess.run(
                cmd_list,
                shell=shell,
                capture_output=capture_output,
                text=True,
                timeout=self.timeout,
                check=check,
                cwd=cwd,
            )

            logger.debug(f"Command completed with returncode: {result.returncode}")
            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.timeout}s: {command}")
            return -1, "", f"Command timed out after {self.timeout}s"

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with returncode {e.returncode}: {command}")
            return e.returncode, e.stdout, e.stderr

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return -1, "", str(e)


def run_command(command: str, **kwargs) -> Tuple[int, str, str]:
    """Convenience function to run a command."""
    runner = CommandRunner()
    return runner.run(command, **kwargs)
```

### utils/scope_parser.py

```python
"""Scope file parsing and IP validation."""

import ipaddress
import re
from typing import List, Set, Tuple
from pathlib import Path


class ScopeValidator:
    """Parse and validate penetration test scope."""

    def __init__(self, scope_file: Path):
        self.scope_file = scope_file
        self.included_ranges: List[ipaddress.IPv4Network] = []
        self.included_ips: Set[ipaddress.IPv4Address] = []
        self.included_domains: Set[str] = []
        self.excluded_ranges: List[ipaddress.IPv4Network] = []
        self.excluded_ips: Set[ipaddress.IPv4Address] = []

        self._parse_scope_file()

    def _parse_scope_file(self):
        """Parse scope file and populate inclusion/exclusion lists."""
        with open(self.scope_file, 'r') as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Handle exclusions
                if line.startswith('EXCLUDE'):
                    target = line.split(maxsplit=1)[1]
                    self._add_target(target, excluded=True)
                else:
                    self._add_target(line, excluded=False)

    def _add_target(self, target: str, excluded: bool):
        """Add a target to included or excluded lists."""
        try:
            # Try parsing as network (CIDR)
            if '/' in target:
                network = ipaddress.IPv4Network(target, strict=False)
                if excluded:
                    self.excluded_ranges.append(network)
                else:
                    self.included_ranges.append(network)

            # Try parsing as single IP
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                ip = ipaddress.IPv4Address(target)
                if excluded:
                    self.excluded_ips.add(ip)
                else:
                    self.included_ips.add(ip)

            # Otherwise treat as domain
            else:
                if not excluded:
                    self.included_domains.add(target.lower())

        except ValueError as e:
            print(f"Invalid target in scope file: {target} - {e}")

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is in scope.

        Returns:
            (in_scope: bool, reason: str)
        """
        # Try as IP address
        try:
            ip = ipaddress.IPv4Address(target)

            # Check exclusions first
            if ip in self.excluded_ips:
                return False, f"IP {ip} is explicitly excluded"

            for excluded_range in self.excluded_ranges:
                if ip in excluded_range:
                    return False, f"IP {ip} is in excluded range {excluded_range}"

            # Check inclusions
            if ip in self.included_ips:
                return True, f"IP {ip} is explicitly included"

            for included_range in self.included_ranges:
                if ip in included_range:
                    return True, f"IP {ip} is in included range {included_range}"

            return False, f"IP {ip} is not in any included scope"

        except ValueError:
            pass

        # Try as domain
        domain = target.lower()

        # Exact match
        if domain in self.included_domains:
            return True, f"Domain {domain} is explicitly included"

        # Wildcard match
        for scope_domain in self.included_domains:
            if scope_domain.startswith('*.'):
                base_domain = scope_domain[2:]
                if domain.endswith(base_domain):
                    return True, f"Domain {domain} matches wildcard {scope_domain}"

        return False, f"Domain {domain} is not in scope"

    def get_all_targets(self) -> List[str]:
        """Get all explicitly defined targets."""
        targets = []
        targets.extend([str(ip) for ip in self.included_ips])
        targets.extend([str(net) for net in self.included_ranges])
        targets.extend(self.included_domains)
        return targets
```

### utils/nmap_parser.py

```python
"""Parse nmap XML output into structured data."""

import xmltodict
from typing import List, Dict, Any


def parse_nmap_xml(xml_path: str) -> Dict[str, Any]:
    """
    Parse nmap XML output file.

    Returns:
        {
            'scan_info': {...},
            'hosts': [
                {
                    'ip': '192.168.1.10',
                    'hostname': 'server01',
                    'status': 'up',
                    'os': 'Linux 4.x',
                    'services': [
                        {
                            'port': 22,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': 'ssh',
                            'version': 'OpenSSH 7.4',
                            'cpe': 'cpe:/a:openbsd:openssh:7.4'
                        }
                    ]
                }
            ]
        }
    """
    with open(xml_path, 'r') as f:
        doc = xmltodict.parse(f.read())

    nmaprun = doc.get('nmaprun', {})

    result = {
        'scan_info': {
            'start_time': nmaprun.get('@startstr'),
            'end_time': nmaprun.get('runstats', {}).get('finished', {}).get('@timestr'),
            'command': nmaprun.get('@args'),
            'version': nmaprun.get('@version'),
        },
        'hosts': []
    }

    # Handle single host or multiple hosts
    hosts = nmaprun.get('host', [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    for host in hosts:
        host_data = _parse_host(host)
        if host_data:
            result['hosts'].append(host_data)

    return result


def _parse_host(host: Dict) -> Dict:
    """Parse a single host from nmap XML."""
    # Get IP address
    address = host.get('address', {})
    if isinstance(address, list):
        # Multiple addresses (IPv4, IPv6, MAC)
        ipv4 = next((a['@addr'] for a in address if a.get('@addrtype') == 'ipv4'), None)
    else:
        ipv4 = address.get('@addr')

    if not ipv4:
        return None

    # Get hostname
    hostnames = host.get('hostnames', {}).get('hostname', [])
    if isinstance(hostnames, dict):
        hostnames = [hostnames]
    hostname = hostnames[0].get('@name') if hostnames else ''

    # Get status
    status = host.get('status', {}).get('@state', 'unknown')

    # Get OS guess
    os_match = host.get('os', {}).get('osmatch', [])
    if isinstance(os_match, dict):
        os_match = [os_match]
    os_guess = os_match[0].get('@name') if os_match else 'Unknown'

    # Get ports/services
    services = []
    ports = host.get('ports', {}).get('port', [])
    if isinstance(ports, dict):
        ports = [ports]

    for port in ports:
        service = _parse_service(port)
        if service:
            services.append(service)

    return {
        'ip': ipv4,
        'hostname': hostname,
        'status': status,
        'os': os_guess,
        'services': services
    }


def _parse_service(port: Dict) -> Dict:
    """Parse a single service from nmap port data."""
    service_info = port.get('service', {})
    state = port.get('state', {})

    return {
        'port': int(port.get('@portid')),
        'protocol': port.get('@protocol', 'tcp'),
        'state': state.get('@state', 'unknown'),
        'service': service_info.get('@name', 'unknown'),
        'product': service_info.get('@product', ''),
        'version': service_info.get('@version', ''),
        'extrainfo': service_info.get('@extrainfo', ''),
        'cpe': service_info.get('cpe', ''),
    }
```

### scope.py - Main MCP Server

```python
"""NTREE Scope Validation MCP Server."""

import asyncio
import logging
from pathlib import Path
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field
import json

from .utils.scope_parser import ScopeValidator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
app = Server("ntree-scope")

# Global scope validator (initialized during init_engagement)
scope_validator: ScopeValidator | None = None


class InitEngagementArgs(BaseModel):
    """Arguments for init_engagement tool."""
    scope_file: str = Field(description="Path to scope file")
    roe_file: str = Field(description="Path to rules of engagement file")


class VerifyScopeArgs(BaseModel):
    """Arguments for verify_scope tool."""
    target: str = Field(description="IP address or domain to verify")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="init_engagement",
            description="Initialize penetration test engagement with scope and ROE validation",
            inputSchema=InitEngagementArgs.model_json_schema()
        ),
        Tool(
            name="verify_scope",
            description="Verify if a target (IP or domain) is within authorized scope",
            inputSchema=VerifyScopeArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    global scope_validator

    if name == "init_engagement":
        args = InitEngagementArgs(**arguments)
        result = await init_engagement(args.scope_file, args.roe_file)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "verify_scope":
        args = VerifyScopeArgs(**arguments)
        result = await verify_scope(args.target)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    else:
        raise ValueError(f"Unknown tool: {name}")


async def init_engagement(scope_file: str, roe_file: str) -> dict:
    """
    Initialize engagement with scope and ROE validation.

    Returns:
        {
            "engagement_id": "eng_20250108_001",
            "validated_scope": {
                "included_ranges": [...],
                "included_ips": [...],
                "included_domains": [...],
                "excluded": [...]
            },
            "restrictions": {...},
            "status": "success"
        }
    """
    global scope_validator

    try:
        # Validate scope file exists
        scope_path = Path(scope_file).expanduser()
        if not scope_path.exists():
            return {
                "status": "error",
                "error": f"Scope file not found: {scope_file}"
            }

        # Initialize scope validator
        scope_validator = ScopeValidator(scope_path)

        # Generate engagement ID
        from datetime import datetime
        engagement_id = f"eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Parse ROE if provided
        restrictions = {}
        if roe_file:
            roe_path = Path(roe_file).expanduser()
            if roe_path.exists():
                with open(roe_path, 'r') as f:
                    # Simple parsing - enhance as needed
                    restrictions = {"roe_file": str(roe_path)}

        return {
            "status": "success",
            "engagement_id": engagement_id,
            "validated_scope": {
                "included_ranges": [str(r) for r in scope_validator.included_ranges],
                "included_ips": [str(ip) for ip in scope_validator.included_ips],
                "included_domains": list(scope_validator.included_domains),
                "excluded_ips": [str(ip) for ip in scope_validator.excluded_ips],
                "excluded_ranges": [str(r) for r in scope_validator.excluded_ranges],
            },
            "restrictions": restrictions,
        }

    except Exception as e:
        logger.error(f"Error initializing engagement: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


async def verify_scope(target: str) -> dict:
    """
    Verify if target is in scope.

    Returns:
        {
            "in_scope": true/false,
            "reason": "explanation",
            "target": "192.168.1.10"
        }
    """
    if not scope_validator:
        return {
            "in_scope": False,
            "reason": "Engagement not initialized. Call init_engagement first.",
            "target": target
        }

    in_scope, reason = scope_validator.is_in_scope(target)

    return {
        "in_scope": in_scope,
        "reason": reason,
        "target": target
    }


async def main():
    """Run the MCP server."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
```

### scan.py - Network Scanning MCP Server

```python
"""NTREE Network Scanning MCP Server."""

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field
import json

from .utils.command_runner import run_command
from .utils.nmap_parser import parse_nmap_xml

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Server("ntree-scan")


class ScanNetworkArgs(BaseModel):
    """Arguments for scan_network tool."""
    targets: str = Field(description="Target IPs or CIDR ranges (comma-separated)")
    scan_type: str = Field(
        description="Scan type: ping_sweep, tcp_syn, full_connect, or udp",
        default="tcp_syn"
    )
    intensity: str = Field(
        description="Scan intensity: stealth, normal, or aggressive",
        default="normal"
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="scan_network",
            description="Perform network scanning to discover live hosts",
            inputSchema=ScanNetworkArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    if name == "scan_network":
        args = ScanNetworkArgs(**arguments)
        result = await scan_network(args.targets, args.scan_type, args.intensity)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    else:
        raise ValueError(f"Unknown tool: {name}")


async def scan_network(targets: str, scan_type: str, intensity: str) -> dict:
    """
    Perform network scan using nmap.

    Returns:
        {
            "scan_id": "scan_20250108_103045",
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "hostname": "server01",
                    "status": "up",
                    "os": "Linux 4.x"
                }
            ],
            "scan_duration": 12.5
        }
    """
    try:
        # Build nmap command based on scan type
        nmap_flags = _build_nmap_flags(scan_type, intensity)

        # Create temporary file for XML output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            xml_output = f.name

        command = f"sudo nmap {nmap_flags} {targets} -oX {xml_output}"

        logger.info(f"Running scan: {command}")
        returncode, stdout, stderr = run_command(command, timeout=600)

        if returncode != 0:
            return {
                "status": "error",
                "error": f"Nmap scan failed: {stderr}"
            }

        # Parse XML output
        scan_result = parse_nmap_xml(xml_output)

        # Clean up temp file
        Path(xml_output).unlink()

        from datetime import datetime
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        return {
            "status": "success",
            "scan_id": scan_id,
            "hosts": scan_result['hosts'],
            "scan_info": scan_result['scan_info']
        }

    except Exception as e:
        logger.error(f"Error during network scan: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


def _build_nmap_flags(scan_type: str, intensity: str) -> str:
    """Build nmap command flags based on scan type and intensity."""
    flags = []

    # Scan type flags
    if scan_type == "ping_sweep":
        flags.append("-sn")
    elif scan_type == "tcp_syn":
        flags.append("-sS")
    elif scan_type == "full_connect":
        flags.append("-sT")
    elif scan_type == "udp":
        flags.append("-sU")
    else:
        flags.append("-sS")  # default

    # Timing flags
    if intensity == "stealth":
        flags.append("-T2")
    elif intensity == "normal":
        flags.append("-T3")
    elif intensity == "aggressive":
        flags.append("-T4")
    else:
        flags.append("-T3")  # default

    # Always include OS detection and version detection if not ping sweep
    if scan_type != "ping_sweep":
        flags.extend(["-O", "-sV"])

    # Additional useful flags
    flags.extend(["-v", "--reason"])

    return " ".join(flags)


async def main():
    """Run the MCP server."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Testing the MCP Servers

### Test Script

```bash
#!/bin/bash
# test_ntree_servers.sh

echo "=== Testing NTREE MCP Servers ==="

# 1. Test scope server
echo -e "\n[1] Testing scope validation..."
python -m ntree_mcp.scope --test

# 2. Test scan server
echo -e "\n[2] Testing network scanning..."
python -m ntree_mcp.scan --test

# 3. Test enum server
echo -e "\n[3] Testing service enumeration..."
python -m ntree_mcp.enum --test

echo -e "\n=== All tests complete ==="
```

### Unit Tests

```python
# tests/test_scope.py

import pytest
from pathlib import Path
from ntree_mcp.utils.scope_parser import ScopeValidator


def test_scope_validator(tmp_path):
    """Test scope validation with sample scope file."""
    # Create test scope file
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("""
# Test scope
192.168.1.0/24
10.0.0.10
example.com
*.internal.example.com

# Excluded
EXCLUDE 192.168.1.1
EXCLUDE 192.168.1.100
    """)

    validator = ScopeValidator(scope_file)

    # Test IP in range
    in_scope, reason = validator.is_in_scope("192.168.1.50")
    assert in_scope is True

    # Test excluded IP
    in_scope, reason = validator.is_in_scope("192.168.1.1")
    assert in_scope is False

    # Test explicit IP
    in_scope, reason = validator.is_in_scope("10.0.0.10")
    assert in_scope is True

    # Test domain
    in_scope, reason = validator.is_in_scope("example.com")
    assert in_scope is True

    # Test wildcard domain
    in_scope, reason = validator.is_in_scope("app.internal.example.com")
    assert in_scope is True

    # Test out of scope
    in_scope, reason = validator.is_in_scope("8.8.8.8")
    assert in_scope is False


# Run tests
# pytest tests/test_scope.py -v
```

---

## Deployment

### Build and Install

```bash
# Clone repository
cd ~/ntree
git clone https://github.com/YOUR_USERNAME/ntree-mcp-servers.git
cd ntree-mcp-servers

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Run tests
pytest tests/ -v
```

### Configure Claude Code

Add to `~/.config/claude-code/mcp-servers.json`:

```json
{
  "mcpServers": {
    "ntree-scope": {
      "command": "/home/pi/ntree/ntree-mcp-servers/venv/bin/python",
      "args": ["-m", "ntree_mcp.scope"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree",
        "PYTHONPATH": "/home/pi/ntree/ntree-mcp-servers"
      }
    },
    "ntree-scan": {
      "command": "/home/pi/ntree/ntree-mcp-servers/venv/bin/python",
      "args": ["-m", "ntree_mcp.scan"],
      "env": {
        "NTREE_HOME": "/home/pi/ntree",
        "PYTHONPATH": "/home/pi/ntree/ntree-mcp-servers"
      }
    }
  }
}
```

---

## Next Steps

1. Implement remaining MCP servers (enum, vuln, post, report)
2. Add error handling and retries
3. Implement rate limiting
4. Add comprehensive logging
5. Create integration tests with actual tools
6. Build CI/CD pipeline
7. Write user documentation

---

This provides the foundation for NTREE MCP servers. The pattern is consistent across all servers:
- Parse inputs with Pydantic
- Validate scope
- Execute tools safely
- Parse outputs
- Return structured JSON

Follow this pattern for remaining servers (enum.py, vuln.py, post.py, report.py).
