"""
NTREE Network Scanning MCP Server
Handles network discovery and port scanning
"""

import asyncio
import json
import os
import re
import shlex
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.command_runner import SecurityTools, run_command
from .utils.nmap_parser import parse_nmap_xml, summarize_scan
from .utils.logger import get_logger

logger = get_logger(__name__)

app = Server("ntree-scan")


# Helper function to handle manual review responses
def handle_command_result(returncode: int, stdout: str, stderr: str, operation: str) -> dict:
    """
    Handle command execution results, including manual review cases.

    Args:
        returncode: Command return code
        stdout: Command stdout
        stderr: Command stderr
        operation: Description of operation (for logging)

    Returns:
        Dict with status and details
    """
    # Check for manual review status (returncode = -2)
    if returncode == -2:
        try:
            manual_review_data = json.loads(stdout)
            logger.warning(f"{operation} requires manual review: {manual_review_data.get('reason')}")

            return {
                "status": "needs_manual_review",
                "operation": operation,
                "reason": manual_review_data.get("reason"),
                "details": manual_review_data.get("details"),
                "recommendation": manual_review_data.get("recommendation"),
                "tool": manual_review_data.get("tool"),
                "safe_alternative": manual_review_data.get("safe_alternative"),
                "original_command": manual_review_data.get("original_command")
            }
        except json.JSONDecodeError:
            return {
                "status": "needs_manual_review",
                "operation": operation,
                "reason": "Interactive tool detected",
                "details": stderr
            }

    # Normal error
    if returncode != 0:
        return {
            "status": "error",
            "error": f"{operation} failed: {stderr[:500]}"
        }

    # Success
    return {
        "status": "success",
        "data": stdout
    }


class ScanNetworkArgs(BaseModel):
    """Arguments for scan_network tool."""
    targets: str = Field(description="Target IPs or CIDR ranges (comma-separated if multiple)")
    scan_type: str = Field(
        default="tcp_syn",
        description="Scan type: ping_sweep, tcp_syn, full_connect, or udp"
    )
    intensity: str = Field(
        default="normal",
        description="Scan intensity: stealth (T2), normal (T3), or aggressive (T4)"
    )
    ports: str = Field(
        default="",
        description="Port specification (e.g., '22,80,443' or '1-1000'). Empty for default ports."
    )


class PassiveReconArgs(BaseModel):
    """Arguments for passive_recon tool."""
    domain: str = Field(description="Domain name for passive reconnaissance")


class NucleiScanArgs(BaseModel):
    """Arguments for nuclei_scan tool."""
    targets: str = Field(description="Target URLs or IPs (comma-separated for multiple)")
    severity: str = Field(
        default="all",
        description="Severity filter: critical, high, medium, low, info, or all"
    )
    templates: str = Field(
        default="",
        description="Specific template tags (e.g., 'cve,exposure,misconfiguration'). Empty for all templates."
    )


class NiktoScanArgs(BaseModel):
    """Arguments for nikto_scan tool."""
    target: str = Field(description="Target web server URL (e.g., http://example.com)")
    port: int = Field(default=80, description="Target port (default: 80)")
    ssl: bool = Field(default=False, description="Use SSL/HTTPS (default: False)")


class MasscanArgs(BaseModel):
    """Arguments for masscan tool."""
    targets: str = Field(description="Target IPs or CIDR ranges")
    ports: str = Field(
        default="0-65535",
        description="Port range (e.g., '1-1000' or '80,443,8080')"
    )
    rate: int = Field(
        default=1000,
        description="Packet transmission rate (packets per second, default: 1000)"
    )


class MasscanNmapArgs(BaseModel):
    """Arguments for masscan_nmap_comprehensive tool."""
    targets: str = Field(description="IP addresses or CIDR ranges (comma-separated)")
    port_range: str = Field(
        default="1-65535",
        description="Port range to scan (default: all ports 1-65535)"
    )
    masscan_rate: int = Field(
        default=1000,
        description="Masscan packet rate (packets/sec, default: 1000)"
    )
    nmap_intensity: str = Field(
        default="normal",
        description="Nmap timing: stealth (T2), normal (T3), or aggressive (T4)"
    )
    skip_vuln_scripts: bool = Field(
        default=False,
        description="Skip NSE vulnerability scripts for faster scanning"
    )


# Input validation functions to prevent command injection
def validate_ip_or_cidr(target: str) -> bool:
    """Validate IP address or CIDR range."""
    # IP address pattern
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # CIDR pattern
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'

    if re.match(ip_pattern, target) or re.match(cidr_pattern, target):
        # Validate octets are 0-255
        octets = target.split('/')[0].split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            # Validate CIDR prefix if present
            if '/' in target:
                prefix = int(target.split('/')[1])
                return 0 <= prefix <= 32
            return True
    return False


def validate_port_range(port_range: str) -> bool:
    """Validate port range specification."""
    # Allow patterns like: 80, 1-1000, 80,443,8080, 1-65535
    if not re.match(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$', port_range):
        return False

    # Validate individual port numbers
    parts = port_range.replace('-', ',').split(',')
    try:
        ports = [int(p) for p in parts]
        return all(0 < p <= 65535 for p in ports)
    except ValueError:
        return False


def validate_targets(targets: str) -> str:
    """
    Validate and sanitize targets parameter.
    Returns sanitized targets or raises ValueError.
    """
    # Split by comma and validate each target
    target_list = [t.strip() for t in targets.split(',')]

    for target in target_list:
        if not validate_ip_or_cidr(target):
            raise ValueError(f"Invalid IP or CIDR format: {target}")

    # Return sanitized targets (re-joined)
    return ','.join(target_list)


def validate_url(url: str) -> bool:
    """Validate URL format for web scanning."""
    # Simple URL validation - must start with http:// or https://
    url_pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:[0-9]{1,5})?(/.*)?$'
    return bool(re.match(url_pattern, url))


def validate_template_tags(tags: str) -> bool:
    """Validate nuclei template tags - alphanumeric, hyphens, commas only."""
    if not tags:
        return True
    # Allow alphanumeric, hyphens, commas, spaces
    return bool(re.match(r'^[a-zA-Z0-9\-,\s]+$', tags))


def validate_severity(severity: str) -> bool:
    """Validate nuclei severity parameter."""
    valid_severities = ["critical", "high", "medium", "low", "info", "all"]
    return severity.lower() in valid_severities


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="scan_network",
            description="Perform network scanning to discover live hosts and open ports using nmap",
            inputSchema=ScanNetworkArgs.model_json_schema()
        ),
        Tool(
            name="passive_recon",
            description="Perform passive reconnaissance (DNS, OSINT) without directly scanning targets",
            inputSchema=PassiveReconArgs.model_json_schema()
        ),
        Tool(
            name="nuclei_scan",
            description="Run Nuclei vulnerability scanner with modern templates for CVEs, misconfigurations, and exposures",
            inputSchema=NucleiScanArgs.model_json_schema()
        ),
        Tool(
            name="nikto_scan",
            description="Run Nikto web server vulnerability scanner to identify common web vulnerabilities",
            inputSchema=NiktoScanArgs.model_json_schema()
        ),
        Tool(
            name="masscan",
            description="Fast port scanner using masscan - much faster than nmap for large port ranges",
            inputSchema=MasscanArgs.model_json_schema()
        ),
        Tool(
            name="masscan_nmap_comprehensive",
            description="Two-stage comprehensive scan: masscan for fast host/port discovery, then nmap for deep vulnerability analysis",
            inputSchema=MasscanNmapArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    try:
        if name == "scan_network":
            args = ScanNetworkArgs(**arguments)
            result = await scan_network(
                args.targets,
                args.scan_type,
                args.intensity,
                args.ports
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "passive_recon":
            args = PassiveReconArgs(**arguments)
            result = await passive_recon(args.domain)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "nuclei_scan":
            args = NucleiScanArgs(**arguments)
            result = await nuclei_scan(
                args.targets,
                args.severity,
                args.templates
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "nikto_scan":
            args = NiktoScanArgs(**arguments)
            result = await nikto_scan(
                args.target,
                args.port,
                args.ssl
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "masscan":
            args = MasscanArgs(**arguments)
            result = await masscan(
                args.targets,
                args.ports,
                args.rate
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "masscan_nmap_comprehensive":
            args = MasscanNmapArgs(**arguments)
            result = await masscan_nmap_comprehensive(
                args.targets,
                args.port_range,
                args.masscan_rate,
                args.nmap_intensity,
                args.skip_vuln_scripts
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def scan_network(
    targets: str,
    scan_type: str = "tcp_syn",
    intensity: str = "normal",
    ports: str = ""
) -> dict:
    """
    Perform network scan using nmap.

    Args:
        targets: Target IPs or CIDR ranges
        scan_type: Type of scan
        intensity: Scan timing/intensity
        ports: Port specification

    Returns:
        {
            "status": "success",
            "scan_id": "scan_20250108_103045",
            "hosts": [...],
            "scan_info": {...},
            "summary": "..."
        }
    """
    try:
        logger.info(f"Starting network scan: targets={targets}, type={scan_type}, intensity={intensity}")

        # Validate inputs to prevent command injection
        try:
            targets = validate_targets(targets)
        except ValueError as e:
            logger.error(f"Invalid targets: {e}")
            return {"status": "error", "error": f"Invalid targets: {e}"}

        if ports and not validate_port_range(ports):
            logger.error(f"Invalid port specification: {ports}")
            return {"status": "error", "error": f"Invalid port specification: {ports}"}

        # Build nmap flags
        nmap_flags = _build_nmap_flags(scan_type, intensity)

        # Create temporary directory and construct XML output path
        # Use UUID to prevent injection and race conditions
        import uuid
        temp_dir = Path(tempfile.mkdtemp())
        xml_output = temp_dir / f"nmap_{uuid.uuid4()}.xml"

        try:
            # Build command with proper escaping
            cmd_parts = ["sudo", "nmap", nmap_flags]

            if ports:
                cmd_parts.extend(["-p", shlex.quote(ports)])

            cmd_parts.extend(["-oX", shlex.quote(str(xml_output))])
            cmd_parts.append(shlex.quote(targets))

            command = " ".join(cmd_parts)

            logger.debug(f"Executing: {command}")

            # Run scan (timeout 10 minutes for network scans)
            returncode, stdout, stderr = await run_command(command, timeout=600)

            if returncode != 0:
                logger.error(f"Nmap scan failed: {stderr}")
                return {
                    "status": "error",
                    "error": f"Nmap scan failed with returncode {returncode}",
                    "stderr": stderr[:1000]  # Truncate error output
                }

            # Parse XML output
            scan_result = parse_nmap_xml(str(xml_output))

            # Generate scan ID
            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create summary
            summary = summarize_scan(scan_result)

            logger.info(f"Scan complete: {len(scan_result['hosts'])} hosts discovered")

            return {
                "status": "success",
                "scan_id": scan_id,
                "hosts": scan_result['hosts'],
                "scan_info": scan_result['scan_info'],
                "summary": summary,
                "command": command
            }

        finally:
            # Clean up temp directory and files
            try:
                if xml_output.exists():
                    xml_output.unlink()
                if temp_dir.exists():
                    temp_dir.rmdir()
            except Exception as e:
                logger.warning(f"Failed to clean up temp files: {e}")

    except Exception as e:
        logger.error(f"Error during network scan: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def _build_nmap_flags(scan_type: str, intensity: str) -> str:
    """Build nmap command flags based on scan type and intensity."""
    flags = []

    # Scan type flags
    scan_type_map = {
        "ping_sweep": "-sn",  # Ping scan only, no port scan
        "tcp_syn": "-sS",      # SYN scan (stealth)
        "full_connect": "-sT", # Full TCP connect
        "udp": "-sU",          # UDP scan
    }

    flags.append(scan_type_map.get(scan_type, "-sS"))

    # Timing flags
    intensity_map = {
        "stealth": "-T2",
        "normal": "-T3",
        "aggressive": "-T4",
    }

    flags.append(intensity_map.get(intensity, "-T3"))

    # Additional flags for detailed scans
    if scan_type != "ping_sweep":
        flags.extend([
            "-sV",       # Version detection
            "-O",        # OS detection
            "--osscan-limit",  # Limit OS detection to promising targets
        ])

    # Always add verbose and reason flags
    flags.extend(["-v", "--reason"])

    return " ".join(flags)


async def passive_recon(domain: str) -> dict:
    """
    Perform passive reconnaissance on a domain.

    Args:
        domain: Domain name to research

    Returns:
        {
            "status": "success",
            "domain": "example.com",
            "dns_records": {...},
            "subdomains": [...],
            "whois": "...",
        }
    """
    try:
        logger.info(f"Starting passive recon for domain: {domain}")

        result = {
            "status": "success",
            "domain": domain,
            "dns_records": {},
            "subdomains": [],
            "whois": "",
        }

        # DNS enumeration
        dns_records = await _enumerate_dns(domain)
        result["dns_records"] = dns_records

        # Subdomain enumeration (using dnsenum if available)
        subdomains = await _enumerate_subdomains(domain)
        result["subdomains"] = subdomains

        # WHOIS lookup
        whois_data = await _whois_lookup(domain)
        result["whois"] = whois_data

        logger.info(f"Passive recon complete for {domain}")

        return result

    except Exception as e:
        logger.error(f"Error during passive recon: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _enumerate_dns(domain: str) -> dict:
    """Enumerate DNS records for a domain."""
    dns_records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SOA": [],
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

    for record_type in record_types:
        try:
            command = f"dig +short {domain} {record_type}"
            returncode, stdout, stderr = await run_command(command, timeout=30)

            if returncode == 0 and stdout.strip():
                records = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
                dns_records[record_type] = records

        except Exception as e:
            logger.warning(f"Error enumerating {record_type} records for {domain}: {e}")

    return dns_records


async def _enumerate_subdomains(domain: str) -> list:
    """Enumerate subdomains using passive techniques."""
    subdomains = set()

    try:
        # Try using dnsenum if available
        command = f"dnsenum --enum {domain} --noreverse"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            # Parse dnsenum output for subdomains
            for line in stdout.split('\n'):
                if domain in line:
                    # Extract subdomain from line
                    parts = line.split()
                    for part in parts:
                        if domain in part and '.' in part:
                            subdomains.add(part)

    except Exception as e:
        logger.warning(f"Error enumerating subdomains: {e}")

    return sorted(list(subdomains))


async def _whois_lookup(domain: str) -> str:
    """Perform WHOIS lookup."""
    try:
        command = f"whois {domain}"
        returncode, stdout, stderr = await run_command(command, timeout=30)

        if returncode == 0:
            return stdout

    except Exception as e:
        logger.warning(f"Error performing WHOIS lookup: {e}")

    return ""


async def nuclei_scan(
    targets: str,
    severity: str = "all",
    templates: str = ""
) -> dict:
    """
    Perform vulnerability scan using Nuclei.

    Args:
        targets: Target URLs or IPs
        severity: Severity filter
        templates: Template tags to use

    Returns:
        {
            "status": "success",
            "scan_id": "nuclei_20250110_103045",
            "findings": [...],
            "total_findings": 5,
            "summary": "..."
        }
    """
    try:
        logger.info(f"Starting Nuclei scan: targets={targets}, severity={severity}")

        # Validate severity to prevent command injection
        if not validate_severity(severity):
            logger.error(f"Invalid severity: {severity}")
            return {"status": "error", "error": f"Invalid severity. Use: critical, high, medium, low, info, or all"}

        # Validate template tags
        if templates and not validate_template_tags(templates):
            logger.error(f"Invalid template tags: {templates}")
            return {"status": "error", "error": "Invalid template tags format"}

        # Validate targets (URLs or IPs)
        target_list = [t.strip() for t in targets.split(',')]
        for target in target_list:
            # Allow both URLs and IPs for nuclei
            if not (validate_url(target) or validate_ip_or_cidr(target)):
                logger.error(f"Invalid target: {target}")
                return {"status": "error", "error": f"Invalid target format: {target}"}

        # Create temporary file for JSON output using UUID
        import uuid
        json_output = Path(f"/tmp/nuclei_{uuid.uuid4()}.json")

        try:
            # Build nuclei command with proper escaping
            cmd_parts = ["nuclei"]

            # Add targets
            if len(target_list) == 1:
                cmd_parts.extend(["-u", shlex.quote(target_list[0])])
            else:
                # Create target file with UUID
                target_file = Path(f"/tmp/nuclei_targets_{uuid.uuid4()}.txt")
                target_file.write_text('\n'.join(target_list))
                cmd_parts.extend(["-l", shlex.quote(str(target_file))])

            # Add severity filter
            if severity != "all":
                cmd_parts.extend(["-severity", shlex.quote(severity)])

            # Add template tags
            if templates:
                cmd_parts.extend(["-tags", shlex.quote(templates)])

            # Output as JSON
            cmd_parts.extend(["-json", "-o", shlex.quote(str(json_output))])

            # Silent mode (reduce noise)
            cmd_parts.append("-silent")

            command = " ".join(cmd_parts)
            logger.debug(f"Executing: {command}")

            # Run nuclei scan (timeout 15 minutes)
            returncode, stdout, stderr = await run_command(command, timeout=900)

            # Parse JSON output
            findings = []
            if json_output.exists() and json_output.stat().st_size > 0:
                try:
                    # Nuclei outputs one JSON object per line
                    for line in json_output.read_text().strip().split('\n'):
                        if line.strip():
                            finding = json.loads(line)
                            findings.append({
                                "template_id": finding.get("template-id", "unknown"),
                                "name": finding.get("info", {}).get("name", "Unknown"),
                                "severity": finding.get("info", {}).get("severity", "info"),
                                "matched_at": finding.get("matched-at", ""),
                                "description": finding.get("info", {}).get("description", ""),
                                "cvss_score": finding.get("info", {}).get("classification", {}).get("cvss-score", 0),
                                "cve_id": finding.get("info", {}).get("classification", {}).get("cve-id", []),
                            })
                except Exception as e:
                    logger.error(f"Error parsing Nuclei output: {e}")

            # Generate scan ID
            scan_id = f"nuclei_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create summary
            severity_counts = {}
            for finding in findings:
                sev = finding.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            summary = f"Nuclei scan complete: {len(findings)} findings - " + ", ".join(
                f"{sev}: {count}" for sev, count in severity_counts.items()
            )

            logger.info(summary)

            return {
                "status": "success",
                "scan_id": scan_id,
                "findings": findings,
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
                "summary": summary,
                "command": command
            }

        finally:
            # Clean up temp files
            if json_output.exists():
                json_output.unlink()
            if 'target_file' in locals() and target_file.exists():
                target_file.unlink()

    except Exception as e:
        logger.error(f"Error during Nuclei scan: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def nikto_scan(
    target: str,
    port: int = 80,
    ssl: bool = False
) -> dict:
    """
    Perform web vulnerability scan using Nikto.

    Args:
        target: Target web server URL
        port: Target port
        ssl: Use SSL/HTTPS

    Returns:
        {
            "status": "success",
            "scan_id": "nikto_20250110_103045",
            "findings": [...],
            "total_findings": 12,
            "summary": "..."
        }
    """
    try:
        logger.info(f"Starting Nikto scan: target={target}, port={port}, ssl={ssl}")

        # Validate target (URL or IP)
        if not (validate_url(target) or validate_ip_or_cidr(target)):
            logger.error(f"Invalid target: {target}")
            return {"status": "error", "error": f"Invalid target format: {target}"}

        # Validate port number
        if not isinstance(port, int) or not (1 <= port <= 65535):
            logger.error(f"Invalid port: {port}")
            return {"status": "error", "error": f"Invalid port number: {port}"}

        # Create temporary file for output using UUID
        import uuid
        output_file = Path(f"/tmp/nikto_{uuid.uuid4()}.txt")

        try:
            # Build nikto command with proper escaping
            cmd_parts = ["nikto"]
            cmd_parts.extend(["-h", shlex.quote(target)])
            cmd_parts.extend(["-p", str(port)])  # Port is validated as int, safe

            if ssl:
                cmd_parts.append("-ssl")

            # Output to file
            cmd_parts.extend(["-o", shlex.quote(str(output_file))])
            cmd_parts.extend(["-Format", "txt"])

            # No interactive prompts
            cmd_parts.append("-ask no")

            command = " ".join(cmd_parts)
            logger.debug(f"Executing: {command}")

            # Run nikto scan (timeout 20 minutes)
            returncode, stdout, stderr = await run_command(command, timeout=1200)

            # Parse output
            findings = []
            if output_file.exists():
                output_content = output_file.read_text()

                # Parse nikto output for findings
                for line in output_content.split('\n'):
                    line = line.strip()
                    if line.startswith('+'):
                        # This is a finding
                        findings.append({
                            "description": line[1:].strip(),
                            "severity": "medium",  # Nikto doesn't provide severity
                        })

            # Generate scan ID
            scan_id = f"nikto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            summary = f"Nikto scan complete: {len(findings)} potential issues found"

            logger.info(summary)

            return {
                "status": "success",
                "scan_id": scan_id,
                "findings": findings,
                "total_findings": len(findings),
                "summary": summary,
                "command": command,
                "raw_output": output_content if output_file.exists() else ""
            }

        finally:
            # Clean up temp file
            if output_file.exists():
                output_file.unlink()

    except Exception as e:
        logger.error(f"Error during Nikto scan: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def masscan(
    targets: str,
    ports: str = "0-65535",
    rate: int = 1000
) -> dict:
    """
    Perform fast port scan using masscan.

    Args:
        targets: Target IPs or CIDR ranges
        ports: Port range
        rate: Packet transmission rate

    Returns:
        {
            "status": "success",
            "scan_id": "masscan_20250110_103045",
            "hosts": [...],
            "total_ports": 250,
            "summary": "..."
        }
    """
    try:
        logger.info(f"Starting masscan: targets={targets}, ports={ports}, rate={rate}")

        # Validate inputs to prevent command injection
        try:
            targets = validate_targets(targets)
        except ValueError as e:
            logger.error(f"Invalid targets: {e}")
            return {"status": "error", "error": f"Invalid targets: {e}"}

        if not validate_port_range(ports):
            logger.error(f"Invalid port range: {ports}")
            return {"status": "error", "error": f"Invalid port range: {ports}"}

        # Validate rate is a positive integer
        if not isinstance(rate, int) or rate <= 0:
            logger.error(f"Invalid rate: {rate}")
            return {"status": "error", "error": f"Invalid rate (must be positive integer): {rate}"}

        # Create temporary directory and construct output path using UUID
        import uuid
        temp_dir = Path(tempfile.mkdtemp())
        output_file = temp_dir / f"masscan_{uuid.uuid4()}.txt"

        try:
            # Build masscan command with proper escaping
            cmd_parts = ["sudo", "masscan"]
            cmd_parts.extend(["-p", shlex.quote(ports)])
            cmd_parts.extend(["--rate", str(rate)])  # rate is validated as int, safe
            cmd_parts.extend(["-oL", shlex.quote(str(output_file))])
            cmd_parts.append(shlex.quote(targets))

            command = " ".join(cmd_parts)
            logger.debug(f"Executing: {command}")

            # Run masscan (timeout 30 minutes for large scans)
            returncode, stdout, stderr = await run_command(command, timeout=1800)

            if returncode != 0:
                logger.error(f"Masscan failed: {stderr}")
                return {
                    "status": "error",
                    "error": f"Masscan failed with returncode {returncode}",
                    "stderr": stderr[:1000]
                }

            # Parse output
            hosts = {}
            if output_file.exists():
                for line in output_file.read_text().split('\n'):
                    if line.startswith('open'):
                        # Format: open tcp 80 1.2.3.4 1234567890
                        parts = line.split()
                        if len(parts) >= 4:
                            protocol = parts[1]
                            port = parts[2]
                            ip = parts[3]

                            if ip not in hosts:
                                hosts[ip] = []

                            hosts[ip].append({
                                "port": int(port),
                                "protocol": protocol,
                                "state": "open"
                            })

            # Generate scan ID
            scan_id = f"masscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Calculate total open ports
            total_ports = sum(len(ports) for ports in hosts.values())

            summary = f"Masscan complete: {len(hosts)} hosts, {total_ports} open ports found"

            logger.info(summary)

            return {
                "status": "success",
                "scan_id": scan_id,
                "hosts": [
                    {
                        "ip": ip,
                        "ports": ports
                    }
                    for ip, ports in hosts.items()
                ],
                "total_hosts": len(hosts),
                "total_ports": total_ports,
                "summary": summary,
                "command": command
            }

        finally:
            # Clean up temp directory and files
            try:
                if output_file.exists():
                    output_file.unlink()
                if temp_dir.exists():
                    temp_dir.rmdir()
            except Exception as e:
                logger.warning(f"Failed to clean up temp files: {e}")

    except Exception as e:
        logger.error(f"Error during masscan: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def masscan_nmap_comprehensive(
    targets: str,
    port_range: str = "1-65535",
    masscan_rate: int = 1000,
    nmap_intensity: str = "normal",
    skip_vuln_scripts: bool = False
) -> dict:
    """
    Two-stage comprehensive scan using masscan for discovery and nmap for analysis.

    Args:
        targets: IP addresses or CIDR ranges
        port_range: Port range to scan
        masscan_rate: Masscan packet rate
        nmap_intensity: Nmap timing (stealth/normal/aggressive)
        skip_vuln_scripts: Skip NSE vulnerability scripts

    Returns:
        {
            "status": "success",
            "scan_id": "masscan_nmap_20260112_120045",
            "stage1_masscan": {...},
            "stage2_nmap": {...},
            "summary": {...}
        }
    """
    try:
        # Validate inputs to prevent command injection
        try:
            targets = validate_targets(targets)
        except ValueError as e:
            logger.error(f"Invalid targets: {e}")
            return {"status": "error", "error": f"Invalid targets: {e}"}

        if not validate_port_range(port_range):
            logger.error(f"Invalid port range: {port_range}")
            return {"status": "error", "error": f"Invalid port range: {port_range}"}

        # Validate intensity
        if nmap_intensity not in ["stealth", "normal", "aggressive"]:
            logger.error(f"Invalid intensity: {nmap_intensity}")
            return {"status": "error", "error": f"Invalid intensity. Use: stealth, normal, or aggressive"}

        # Validate rate
        if not (1 <= masscan_rate <= 100000):
            logger.error(f"Invalid rate: {masscan_rate}")
            return {"status": "error", "error": "Rate must be between 1 and 100000"}

        logger.info(f"Starting masscan+nmap comprehensive scan on {targets}")

        # Stage 1: Masscan Discovery
        logger.info(f"Stage 1: Masscan discovery - targets={targets}, ports={port_range}, rate={masscan_rate}")

        # Use unique filename with UUID to prevent race conditions
        import uuid
        masscan_output = f"/tmp/masscan_{uuid.uuid4()}.json"

        # Build masscan command with quoted parameters (safe from injection)
        masscan_cmd = f"sudo masscan {shlex.quote(targets)} -p{shlex.quote(port_range)} --rate {masscan_rate} -oJ {shlex.quote(masscan_output)}"

        # Execute masscan
        start_time = time.time()
        returncode, stdout, stderr = await run_command(masscan_cmd, timeout=1800)
        masscan_duration = time.time() - start_time

        if returncode != 0:
            logger.error(f"Masscan failed: {stderr}")
            return {"status": "error", "error": f"Masscan failed: {stderr[:500]}"}

        # Parse masscan JSON output
        host_ports = _parse_masscan_output(masscan_output)

        # Clean up masscan output file
        try:
            if os.path.exists(masscan_output):
                os.unlink(masscan_output)
        except Exception as e:
            logger.warning(f"Failed to clean up masscan output: {e}")

        if not host_ports:
            logger.info("No live hosts or open ports detected")
            return {
                "status": "success",
                "message": "No live hosts or open ports detected",
                "stage1_masscan": {
                    "duration": masscan_duration,
                    "hosts_found": 0,
                    "total_ports_found": 0
                }
            }

        logger.info(f"Masscan found {len(host_ports)} hosts with {sum(len(ports) for ports in host_ports.values())} open ports")

        # Stage 2: Nmap Deep Analysis
        logger.info(f"Stage 2: Nmap vulnerability analysis on {len(host_ports)} discovered hosts")

        nmap_results = []
        start_time = time.time()

        # Process hosts in parallel (max 5 concurrent)
        semaphore = asyncio.Semaphore(5)

        async def analyze_host(host, ports):
            async with semaphore:
                return await _run_nmap_analysis(host, ports, nmap_intensity, skip_vuln_scripts)

        tasks = [analyze_host(host, ports) for host, ports in host_ports.items()]
        nmap_results = await asyncio.gather(*tasks, return_exceptions=True)

        nmap_duration = time.time() - start_time

        # Count vulnerabilities
        vuln_count = sum(
            len(r.get('vulnerabilities', []))
            for r in nmap_results
            if isinstance(r, dict) and r.get('status') == 'success'
        )

        # Return aggregated results
        return {
            "status": "success",
            "scan_id": f"masscan_nmap_{int(time.time())}",
            "stage1_masscan": {
                "targets_scanned": targets,
                "port_range": port_range,
                "rate": masscan_rate,
                "duration": masscan_duration,
                "hosts_found": len(host_ports),
                "total_ports_found": sum(len(ports) for ports in host_ports.values()),
                "results": host_ports
            },
            "stage2_nmap": {
                "hosts_analyzed": len([r for r in nmap_results if isinstance(r, dict)]),
                "duration": nmap_duration,
                "vulnerabilities_found": vuln_count,
                "results": [r for r in nmap_results if isinstance(r, dict)]
            },
            "summary": {
                "total_duration": masscan_duration + nmap_duration,
                "live_hosts": len(host_ports),
                "total_open_ports": sum(len(ports) for ports in host_ports.values()),
                "vulnerabilities_found": vuln_count
            }
        }

    except Exception as e:
        logger.error(f"Error during masscan+nmap scan: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def _parse_masscan_output(json_path: str) -> dict:
    """
    Parse masscan JSON output and group ports by host.

    Returns:
        dict: {host_ip: [port1, port2, ...]}
    """
    host_ports = {}

    try:
        with open(json_path, 'r') as f:
            # Masscan JSON is newline-delimited, not a single array
            data = f.read()

        # Parse line by line (masscan outputs one JSON object per line)
        for line in data.strip().split('\n'):
            if not line or line.startswith('#'):
                continue

            try:
                entry = json.loads(line.rstrip(','))

                if 'ports' in entry:
                    for port_entry in entry['ports']:
                        ip = entry['ip']
                        port = port_entry['port']

                        if ip not in host_ports:
                            host_ports[ip] = []
                        host_ports[ip].append(port)
            except json.JSONDecodeError:
                continue

        # Sort ports for each host
        for ip in host_ports:
            host_ports[ip] = sorted(host_ports[ip])

    except Exception as e:
        logger.error(f"Error parsing masscan output: {e}")

    return host_ports


async def _run_nmap_analysis(host: str, ports: list, intensity: str, skip_vuln_scripts: bool) -> dict:
    """
    Run nmap analysis on a single host with discovered ports.

    Returns:
        dict: {status, ip, ports, services, os, vulnerabilities}
    """
    try:
        logger.info(f"Analyzing {host} - ports: {ports}")

        # Validate host IP to prevent command injection
        if not validate_ip_or_cidr(host):
            logger.error(f"Invalid host IP: {host}")
            return {"status": "error", "ip": host, "error": "Invalid IP address"}

        # Validate ports are integers
        try:
            port_list = [int(p) for p in ports]
            if not all(1 <= p <= 65535 for p in port_list):
                raise ValueError("Port out of range")
            port_str = ','.join(map(str, port_list))
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid ports for {host}: {e}")
            return {"status": "error", "ip": host, "error": f"Invalid port specification: {e}"}

        # Timing
        timing_map = {"stealth": "-T2", "normal": "-T3", "aggressive": "-T4"}
        timing = timing_map.get(intensity, "-T3")

        # Build flags
        flags = f"-sS -sV -O --osscan-limit -sC {timing}"
        if not skip_vuln_scripts:
            flags += " --script vuln"

        # Output file - use UUID to prevent injection and race conditions
        import uuid
        output_xml = f"/tmp/nmap_{uuid.uuid4()}.xml"

        # Command - use shlex.quote() to safely escape all parameters
        command = f"sudo nmap {flags} -p {shlex.quote(port_str)} -oX {shlex.quote(output_xml)} {shlex.quote(host)}"

        # Execute
        returncode, stdout, stderr = await run_command(command, timeout=600)

        if returncode != 0:
            logger.error(f"Nmap failed for {host}: {stderr}")
            return {"status": "error", "ip": host, "error": stderr[:500]}

        # Parse XML
        scan_results = parse_nmap_xml(output_xml)

        # Extract host data
        host_data = scan_results.get('hosts', [{}])[0] if scan_results.get('hosts') else {}

        # Clean up
        try:
            if os.path.exists(output_xml):
                os.unlink(output_xml)
        except Exception as e:
            logger.warning(f"Failed to clean up {output_xml}: {e}")

        return {
            "status": "success",
            "ip": host,
            "ports": ports,
            "services": host_data.get('services', []),
            "os": host_data.get('os', 'Unknown'),
            "os_accuracy": host_data.get('os_accuracy', 0),
            "vulnerabilities": _extract_vulnerabilities(host_data)
        }

    except Exception as e:
        logger.error(f"Error analyzing {host}: {e}")
        return {"status": "error", "ip": host, "error": str(e)}


def _extract_vulnerabilities(host_data: dict) -> list:
    """
    Extract vulnerability information from nmap results.

    Returns:
        list: [{port, service, vuln_id, description, severity}]
    """
    vulnerabilities = []

    for service in host_data.get('services', []):
        port = service.get('port')
        service_name = service.get('service', 'unknown')

        for script in service.get('scripts', []):
            script_id = script.get('id', '')

            # NSE vuln scripts typically have IDs like "smb-vuln-ms17-010"
            if 'vuln' in script_id or 'CVE' in script.get('output', ''):
                vulnerabilities.append({
                    'port': port,
                    'service': service_name,
                    'vuln_id': script_id,
                    'description': script.get('output', '')[:500],  # Truncate long outputs
                    'severity': _estimate_severity(script_id, script.get('output', ''))
                })

    return vulnerabilities


def _estimate_severity(script_id: str, output: str) -> str:
    """Estimate vulnerability severity based on script output."""
    output_lower = output.lower()

    # Critical keywords
    if any(word in output_lower for word in ['remote code execution', 'rce', 'unauthenticated']):
        return 'critical'

    # High keywords
    if any(word in output_lower for word in ['vulnerable', 'exploit', 'compromise']):
        return 'high'

    # Medium keywords
    if any(word in output_lower for word in ['information disclosure', 'weak', 'outdated']):
        return 'medium'

    return 'low'


def main():
    """Main entry point for scan server."""
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-scan v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Scan Server - Test Mode")
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
