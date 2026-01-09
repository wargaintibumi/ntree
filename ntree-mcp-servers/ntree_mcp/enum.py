"""
NTREE Service Enumeration MCP Server
Handles detailed service enumeration for discovered hosts
"""

import asyncio
import json
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.command_runner import run_command
from .utils.nmap_parser import parse_nmap_xml
from .utils.logger import get_logger

logger = get_logger(__name__)

app = Server("ntree-enum")


class EnumerateServicesArgs(BaseModel):
    """Arguments for enumerate_services tool."""
    host: str = Field(description="Target host IP address")
    ports: str = Field(
        default="default",
        description="Ports to enumerate: 'default', 'all', or specific ports like '22,80,443'"
    )


class EnumerateWebArgs(BaseModel):
    """Arguments for enumerate_web tool."""
    url: str = Field(description="Target URL (e.g., http://example.com)")
    depth: int = Field(default=2, description="Depth of enumeration (1-3)")


class EnumerateSMBArgs(BaseModel):
    """Arguments for enumerate_smb tool."""
    host: str = Field(description="Target host IP address")


class EnumerateDomainArgs(BaseModel):
    """Arguments for enumerate_domain tool."""
    domain_controller: str = Field(description="Domain controller IP address")
    username: str = Field(default="", description="Optional username for authenticated enumeration")
    password: str = Field(default="", description="Optional password for authenticated enumeration")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available enumeration tools."""
    return [
        Tool(
            name="enumerate_services",
            description="Perform detailed service enumeration on a host using nmap version detection and NSE scripts",
            inputSchema=EnumerateServicesArgs.model_json_schema()
        ),
        Tool(
            name="enumerate_web",
            description="Enumerate web application using nikto, technology detection, and directory brute-forcing",
            inputSchema=EnumerateWebArgs.model_json_schema()
        ),
        Tool(
            name="enumerate_smb",
            description="Enumerate SMB/Windows services including shares, users, groups, and domain information",
            inputSchema=EnumerateSMBArgs.model_json_schema()
        ),
        Tool(
            name="enumerate_domain",
            description="Enumerate Active Directory domain controller for users, groups, computers, and policies",
            inputSchema=EnumerateDomainArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    try:
        if name == "enumerate_services":
            args = EnumerateServicesArgs(**arguments)
            result = await enumerate_services(args.host, args.ports)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "enumerate_web":
            args = EnumerateWebArgs(**arguments)
            result = await enumerate_web(args.url, args.depth)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "enumerate_smb":
            args = EnumerateSMBArgs(**arguments)
            result = await enumerate_smb(args.host)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "enumerate_domain":
            args = EnumerateDomainArgs(**arguments)
            result = await enumerate_domain(
                args.domain_controller,
                args.username,
                args.password
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def enumerate_services(host: str, ports: str = "default") -> dict:
    """
    Perform detailed service enumeration using nmap.

    Args:
        host: Target IP address
        ports: Port specification

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "services": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "7.4",
                    "cpe": "cpe:/a:openbsd:openssh:7.4",
                    "scripts": [...]
                },
                ...
            ],
            "summary": "Found 5 open services"
        }
    """
    try:
        logger.info(f"Enumerating services on {host}")

        # Build port specification
        if ports == "default":
            port_spec = ""  # nmap default ports
        elif ports == "all":
            port_spec = "-p-"  # all 65535 ports
        else:
            port_spec = f"-p {ports}"

        # Create temporary file for XML output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            xml_output = Path(f.name)

        try:
            # Build nmap command with aggressive service detection
            cmd_parts = [
                "sudo", "nmap",
                "-sV",  # Version detection
                "-sC",  # Default scripts
                "--version-intensity", "9",  # Maximum version detection
                "-T3",  # Normal timing
                "-v",   # Verbose
            ]

            if port_spec:
                cmd_parts.append(port_spec)

            cmd_parts.extend(["-oX", str(xml_output)])
            cmd_parts.append(host)

            command = " ".join(cmd_parts)

            logger.debug(f"Executing: {command}")

            # Run enumeration (timeout 15 minutes for detailed scans)
            returncode, stdout, stderr = await run_command(command, timeout=900)

            if returncode != 0:
                logger.error(f"Service enumeration failed: {stderr}")
                return {
                    "status": "error",
                    "error": f"nmap enumeration failed: {stderr[:500]}"
                }

            # Parse results
            scan_result = parse_nmap_xml(str(xml_output))

            if not scan_result['hosts']:
                return {
                    "status": "success",
                    "host": host,
                    "services": [],
                    "summary": "No services detected (host may be down or filtered)"
                }

            host_data = scan_result['hosts'][0]
            services = host_data.get('services', [])

            # Enrich services with additional information
            enriched_services = []
            for svc in services:
                enriched = await _enrich_service(host, svc)
                enriched_services.append(enriched)

            summary = f"Found {len([s for s in services if s['state'] == 'open'])} open services"

            logger.info(f"Service enumeration complete for {host}: {summary}")

            return {
                "status": "success",
                "host": host,
                "hostname": host_data.get('hostname', ''),
                "os": host_data.get('os', 'Unknown'),
                "services": enriched_services,
                "summary": summary,
                "command": command
            }

        finally:
            # Clean up temp file
            if xml_output.exists():
                xml_output.unlink()

    except Exception as e:
        logger.error(f"Error enumerating services on {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _enrich_service(host: str, service: dict) -> dict:
    """Enrich service information with additional context."""
    enriched = service.copy()

    # Add vulnerability hints based on service/version
    vulnerabilities = []

    # Check for known vulnerable services
    service_name = service.get('service', '').lower()
    version = service.get('version', '').lower()

    # Common vulnerable services
    if 'smb' in service_name or service.get('port') == 445:
        vulnerabilities.append("SMB service detected - check for EternalBlue, SMB signing")

    if 'ftp' in service_name and service.get('port') == 21:
        vulnerabilities.append("FTP detected - check for anonymous login, weak credentials")

    if 'telnet' in service_name:
        vulnerabilities.append("Telnet detected - unencrypted, consider replacing with SSH")

    if 'mysql' in service_name and service.get('port') == 3306:
        vulnerabilities.append("MySQL exposed - check for weak credentials, public access")

    if 'rdp' in service_name or service.get('port') == 3389:
        vulnerabilities.append("RDP detected - check for BlueKeep, weak credentials")

    if 'ssh' in service_name:
        # Parse SSH version for vulnerabilities
        if 'openssh' in version:
            version_match = re.search(r'(\d+\.\d+)', version)
            if version_match:
                ver = float(version_match.group(1))
                if ver < 7.4:
                    vulnerabilities.append("Outdated OpenSSH version - multiple CVEs")

    enriched['vulnerability_hints'] = vulnerabilities

    return enriched


async def enumerate_web(url: str, depth: int = 2) -> dict:
    """
    Enumerate web application.

    Args:
        url: Target URL
        depth: Enumeration depth (1-3)

    Returns:
        {
            "status": "success",
            "url": "http://example.com",
            "technologies": ["Apache/2.4.41", "PHP/7.4"],
            "endpoints": ["/admin", "/api", ...],
            "vulnerabilities": [...],
            "security_headers": {...}
        }
    """
    try:
        logger.info(f"Enumerating web application: {url}")

        result = {
            "status": "success",
            "url": url,
            "technologies": [],
            "endpoints": [],
            "vulnerabilities": [],
            "security_headers": {},
            "forms": [],
        }

        # 1. Basic HTTP headers and technology detection
        tech_info = await _detect_web_technologies(url)
        result['technologies'] = tech_info['technologies']
        result['security_headers'] = tech_info['security_headers']

        # 2. Run nikto for vulnerability scanning
        if depth >= 2:
            nikto_results = await _run_nikto(url)
            result['vulnerabilities'] = nikto_results

        # 3. Directory/endpoint enumeration
        if depth >= 2:
            endpoints = await _enumerate_web_directories(url, depth)
            result['endpoints'] = endpoints

        # 4. Form detection
        forms = await _detect_forms(url)
        result['forms'] = forms

        summary = f"Found {len(result['technologies'])} technologies, " \
                  f"{len(result['endpoints'])} endpoints, " \
                  f"{len(result['vulnerabilities'])} potential issues"

        result['summary'] = summary

        logger.info(f"Web enumeration complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error enumerating web app {url}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _detect_web_technologies(url: str) -> dict:
    """Detect web technologies using HTTP headers."""
    technologies = []
    security_headers = {
        'present': [],
        'missing': []
    }

    try:
        # Use curl to get headers
        command = f"curl -I -L -s {url}"
        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0:
            # Parse headers
            for line in stdout.split('\n'):
                line = line.strip()

                # Technology detection
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    technologies.append(server)

                if line.lower().startswith('x-powered-by:'):
                    powered = line.split(':', 1)[1].strip()
                    technologies.append(powered)

                # Security headers
                header_name = line.split(':', 1)[0].lower()
                if header_name in ['x-frame-options', 'x-xss-protection',
                                   'x-content-type-options', 'strict-transport-security',
                                   'content-security-policy']:
                    security_headers['present'].append(line.split(':', 1)[0])

        # Check for missing security headers
        important_headers = ['X-Frame-Options', 'X-XSS-Protection',
                            'X-Content-Type-Options', 'Strict-Transport-Security',
                            'Content-Security-Policy']

        for header in important_headers:
            if header not in security_headers['present']:
                security_headers['missing'].append(header)

    except Exception as e:
        logger.warning(f"Error detecting web technologies: {e}")

    return {
        'technologies': technologies,
        'security_headers': security_headers
    }


async def _run_nikto(url: str) -> list:
    """Run nikto vulnerability scanner."""
    vulnerabilities = []

    try:
        command = f"nikto -h {url} -Tuning 123bde -timeout 30"
        returncode, stdout, stderr = await run_command(command, timeout=300)

        if returncode == 0 or returncode == 1:  # nikto returns 1 on findings
            # Parse nikto output
            for line in stdout.split('\n'):
                if '+' in line and any(keyword in line.lower() for keyword in
                                      ['osvdb', 'cve', 'vulnerable', 'error', 'found']):
                    vulnerabilities.append(line.strip())

    except Exception as e:
        logger.warning(f"Error running nikto: {e}")

    return vulnerabilities[:20]  # Limit to top 20


async def _enumerate_web_directories(url: str, depth: int) -> list:
    """Enumerate web directories using gobuster."""
    endpoints = []

    try:
        # Use common wordlist
        wordlist = "/usr/share/wordlists/dirb/common.txt"

        # Fallback wordlist
        if not Path(wordlist).exists():
            wordlist = "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt"

        if not Path(wordlist).exists():
            logger.warning("No wordlist found for directory enumeration")
            return endpoints

        command = f"gobuster dir -u {url} -w {wordlist} -t 10 -q --timeout 10s"

        returncode, stdout, stderr = await run_command(command, timeout=180)

        if returncode == 0:
            # Parse gobuster output
            for line in stdout.split('\n'):
                if line.strip() and not line.startswith('='):
                    # Extract endpoint from line like: "/admin (Status: 200)"
                    match = re.search(r'(/[^\s]+)', line)
                    if match:
                        endpoints.append(match.group(1))

    except Exception as e:
        logger.warning(f"Error enumerating directories: {e}")

    return endpoints[:50]  # Limit results


async def _detect_forms(url: str) -> list:
    """Detect HTML forms (basic detection with curl)."""
    forms = []

    try:
        command = f"curl -s -L {url}"
        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0:
            # Simple form detection
            form_count = stdout.lower().count('<form')
            if form_count > 0:
                forms.append(f"Detected {form_count} HTML form(s)")

    except Exception as e:
        logger.warning(f"Error detecting forms: {e}")

    return forms


async def enumerate_smb(host: str) -> dict:
    """
    Enumerate SMB/Windows services.

    Args:
        host: Target IP address

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "shares": [...],
            "users": [...],
            "groups": [...],
            "domain": "WORKGROUP",
            "os_info": "Windows Server 2019",
            "smb_version": "SMBv2/v3",
            "signing_required": false
        }
    """
    try:
        logger.info(f"Enumerating SMB on {host}")

        result = {
            "status": "success",
            "host": host,
            "shares": [],
            "users": [],
            "groups": [],
            "domain": "",
            "os_info": "",
            "smb_version": "",
            "signing_required": None,
        }

        # Run enum4linux
        command = f"enum4linux -a {host}"
        returncode, stdout, stderr = await run_command(command, timeout=300)

        if returncode != 0 and not stdout:
            return {
                "status": "error",
                "error": f"enum4linux failed: {stderr[:500]}"
            }

        # Parse enum4linux output
        parsed = _parse_enum4linux_output(stdout)
        result.update(parsed)

        # Additionally check SMB signing with nmap
        signing_check = await _check_smb_signing(host)
        result['signing_required'] = signing_check

        summary = f"Domain: {result['domain']}, " \
                  f"Shares: {len(result['shares'])}, " \
                  f"Users: {len(result['users'])}, " \
                  f"Signing: {'Required' if signing_check else 'Not Required'}"

        result['summary'] = summary

        logger.info(f"SMB enumeration complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error enumerating SMB on {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def _parse_enum4linux_output(output: str) -> dict:
    """Parse enum4linux output."""
    result = {
        "shares": [],
        "users": [],
        "groups": [],
        "domain": "",
        "os_info": "",
    }

    lines = output.split('\n')

    for i, line in enumerate(lines):
        # Parse domain
        if 'Domain Name:' in line or 'Workgroup:' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                result['domain'] = parts[1].strip()

        # Parse OS info
        if 'OS:' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                result['os_info'] = parts[1].strip()

        # Parse shares
        if 'Sharename' in line and 'Type' in line:
            # Next lines contain shares
            for j in range(i + 1, min(i + 20, len(lines))):
                share_line = lines[j].strip()
                if share_line and not share_line.startswith('-'):
                    parts = share_line.split()
                    if parts:
                        result['shares'].append(parts[0])

        # Parse users
        if 'user:' in line.lower():
            match = re.search(r'user:\[([^\]]+)\]', line, re.IGNORECASE)
            if match:
                user = match.group(1)
                if user not in result['users']:
                    result['users'].append(user)

        # Parse groups
        if 'group:' in line.lower():
            match = re.search(r'group:\[([^\]]+)\]', line, re.IGNORECASE)
            if match:
                group = match.group(1)
                if group not in result['groups']:
                    result['groups'].append(group)

    return result


async def _check_smb_signing(host: str) -> Optional[bool]:
    """Check if SMB signing is required using nmap."""
    try:
        command = f"sudo nmap -p445 --script smb-security-mode {host}"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        if returncode == 0:
            if 'message_signing: required' in stdout.lower():
                return True
            elif 'message_signing: disabled' in stdout.lower():
                return False

    except Exception as e:
        logger.warning(f"Error checking SMB signing: {e}")

    return None


async def enumerate_domain(
    domain_controller: str,
    username: str = "",
    password: str = ""
) -> dict:
    """
    Enumerate Active Directory domain controller.

    Args:
        domain_controller: DC IP address
        username: Optional username for authenticated enum
        password: Optional password

    Returns:
        {
            "status": "success",
            "dc": "192.168.1.10",
            "domain": "CORP.LOCAL",
            "users": [...],
            "groups": [...],
            "computers": [...],
            "policies": {...}
        }
    """
    try:
        logger.info(f"Enumerating Active Directory on {domain_controller}")

        result = {
            "status": "success",
            "dc": domain_controller,
            "domain": "",
            "users": [],
            "groups": [],
            "computers": [],
            "policies": {},
        }

        # For unauthenticated enumeration, use enum4linux
        if not username:
            logger.info("Performing unauthenticated AD enumeration")
            command = f"enum4linux -a {domain_controller}"
        else:
            # For authenticated, could use ldapsearch or crackmapexec
            logger.info("Performing authenticated AD enumeration")
            # This would require crackmapexec or impacket
            # For now, fall back to enum4linux
            command = f"enum4linux -u {username} -p {password} -a {domain_controller}"

        returncode, stdout, stderr = await run_command(command, timeout=300)

        if returncode != 0 and not stdout:
            return {
                "status": "error",
                "error": f"AD enumeration failed: {stderr[:500]}"
            }

        # Parse output (similar to SMB enumeration)
        parsed = _parse_enum4linux_output(stdout)
        result.update(parsed)

        summary = f"Domain: {result['domain']}, " \
                  f"Users: {len(result['users'])}, " \
                  f"Groups: {len(result['groups'])}"

        result['summary'] = summary

        logger.info(f"AD enumeration complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error enumerating AD on {domain_controller}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def main():
    """Main entry point for enum server."""
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-enum v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Enumeration Server - Test Mode")
            return

    async def run_server():
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
