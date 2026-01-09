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
