"""
NTREE Network Scanning MCP Server
Handles network discovery and port scanning
"""

import asyncio
import json
import tempfile
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

        # Build nmap flags
        nmap_flags = _build_nmap_flags(scan_type, intensity)

        # Create temporary file for XML output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            xml_output = Path(f.name)

        try:
            # Build command
            cmd_parts = ["sudo", "nmap", nmap_flags]

            if ports:
                cmd_parts.extend(["-p", ports])

            cmd_parts.extend(["-oX", str(xml_output)])
            cmd_parts.append(targets)

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
            # Clean up temp file
            if xml_output.exists():
                xml_output.unlink()

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

        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json_output = Path(f.name)

        try:
            # Build nuclei command
            cmd_parts = ["nuclei"]

            # Add targets
            target_list = [t.strip() for t in targets.split(',')]
            if len(target_list) == 1:
                cmd_parts.extend(["-u", target_list[0]])
            else:
                # Create target file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                    target_file = Path(tf.name)
                    tf.write('\n'.join(target_list))
                cmd_parts.extend(["-l", str(target_file)])

            # Add severity filter
            if severity != "all":
                cmd_parts.extend(["-severity", severity])

            # Add template tags
            if templates:
                cmd_parts.extend(["-tags", templates])

            # Output as JSON
            cmd_parts.extend(["-json", "-o", str(json_output)])

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

        # Create temporary file for output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = Path(f.name)

        try:
            # Build nikto command
            cmd_parts = ["nikto"]
            cmd_parts.extend(["-h", target])
            cmd_parts.extend(["-p", str(port)])

            if ssl:
                cmd_parts.append("-ssl")

            # Output to file
            cmd_parts.extend(["-o", str(output_file)])
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

        # Create temporary file for output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = Path(f.name)

        try:
            # Build masscan command
            cmd_parts = ["sudo", "masscan"]
            cmd_parts.extend(["-p", ports])
            cmd_parts.extend(["--rate", str(rate)])
            cmd_parts.extend(["-oL", str(output_file)])
            cmd_parts.append(targets)

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
            # Clean up temp file
            if output_file.exists():
                output_file.unlink()

    except Exception as e:
        logger.error(f"Error during masscan: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


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
