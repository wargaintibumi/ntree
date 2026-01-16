"""
NTREE Wi-Fi and Router Security Assessment MCP Server
Handles wireless network scanning and router misconfiguration detection
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
from typing import Any, Dict, List, Tuple

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.command_runner import run_command
from .utils.logger import get_logger
from .utils.wifi_utils import (
    BLOCKED_OPERATIONS,
    check_root_privileges,
    detect_default_ssid,
    enable_monitor_mode,
    get_wireless_interfaces,
    is_operation_blocked,
    load_router_credentials,
    parse_airodump_csv,
    parse_wash_output,
    restore_managed_mode,
    validate_bssid,
    validate_channel,
    validate_interface,
    validate_secondary_interface,
    validate_ssid,
)

logger = get_logger(__name__)

app = Server("ntree-wifi")


# ============================================================================
# Rate Limiting for Router Credential Testing
# ============================================================================

_credential_attempts: Dict[str, List[float]] = {}  # {router_ip: [timestamps]}
MAX_CRED_ATTEMPTS = 3
ATTEMPT_WINDOW = 300  # 5 minutes


def check_credential_rate_limit(router_ip: str) -> Tuple[bool, int]:
    """
    Check if credential testing is rate limited for a router.

    Args:
        router_ip: Router IP address

    Returns:
        Tuple of (is_allowed, attempts_remaining)
    """
    now = time.time()

    if router_ip not in _credential_attempts:
        _credential_attempts[router_ip] = []

    # Remove old attempts outside the window
    _credential_attempts[router_ip] = [
        ts for ts in _credential_attempts[router_ip]
        if now - ts < ATTEMPT_WINDOW
    ]

    attempts = len(_credential_attempts[router_ip])
    remaining = MAX_CRED_ATTEMPTS - attempts

    if attempts >= MAX_CRED_ATTEMPTS:
        return False, 0

    return True, remaining


def record_credential_attempt(router_ip: str):
    """Record a credential testing attempt."""
    if router_ip not in _credential_attempts:
        _credential_attempts[router_ip] = []
    _credential_attempts[router_ip].append(time.time())


# ============================================================================
# Pydantic Argument Models
# ============================================================================

class ScanWirelessNetworksArgs(BaseModel):
    """Arguments for scan_wireless_networks tool."""
    interface: str = Field(
        default="wlan1",
        description="Secondary wireless interface (NOT the primary/default route interface)"
    )
    duration: int = Field(
        default=30,
        description="Scan duration in seconds (10-120)"
    )
    channel: int = Field(
        default=0,
        description="Specific channel to scan (0 for all channels)"
    )
    passive_only: bool = Field(
        default=True,
        description="Use passive scanning only (no probe requests)"
    )


class CheckWifiSecurityArgs(BaseModel):
    """Arguments for check_wifi_security tool."""
    bssid: str = Field(description="Target network BSSID (MAC address)")
    ssid: str = Field(default="", description="Target network SSID (optional)")
    interface: str = Field(
        default="wlan1",
        description="Secondary wireless interface for scanning"
    )


class DetectRouterIssuesArgs(BaseModel):
    """Arguments for detect_router_issues tool."""
    router_ip: str = Field(description="Router IP address to check")
    check_types: list = Field(
        default=["default_creds", "http_admin", "firmware", "upnp", "dns"],
        description="Check types: default_creds, http_admin, firmware, upnp, dns, snmp"
    )
    approved: bool = Field(
        default=False,
        description="Explicit approval required for credential testing (MUST be true)"
    )


class CheckVLANSegmentationArgs(BaseModel):
    """Arguments for check_vlan_segmentation tool."""
    source_network: str = Field(description="Source network/subnet you're on")
    target_networks: list = Field(description="Target VLANs/networks to test reachability")
    interface: str = Field(default="", description="Interface to use (optional)")


# ============================================================================
# Input Validation
# ============================================================================

def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation."""
    if '/' not in cidr:
        return False
    ip, prefix = cidr.rsplit('/', 1)
    if not validate_ip(ip):
        return False
    try:
        prefix_int = int(prefix)
        return 0 <= prefix_int <= 32
    except ValueError:
        return False


# ============================================================================
# Tool Registration
# ============================================================================

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available Wi-Fi/Router security tools."""
    return [
        Tool(
            name="scan_wireless_networks",
            description="Passively scan for wireless networks. Returns SSID, BSSID, channel, encryption type, signal strength, and WPS status. Requires WIFI_ALLOWED in scope and secondary interface.",
            inputSchema=ScanWirelessNetworksArgs.model_json_schema()
        ),
        Tool(
            name="check_wifi_security",
            description="Analyze security configuration of a specific wireless network. Checks encryption strength, WPS vulnerabilities, and default SSID patterns.",
            inputSchema=CheckWifiSecurityArgs.model_json_schema()
        ),
        Tool(
            name="detect_router_issues",
            description="Detect router misconfigurations including default credentials, HTTP admin panels without TLS, outdated firmware, UPnP exposure, and DNS issues. Credential testing requires approval.",
            inputSchema=DetectRouterIssuesArgs.model_json_schema()
        ),
        Tool(
            name="check_vlan_segmentation",
            description="Test network segmentation between VLANs by checking reachability across network boundaries. Identifies improper isolation.",
            inputSchema=CheckVLANSegmentationArgs.model_json_schema()
        ),
    ]


# ============================================================================
# Tool Handler
# ============================================================================

@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    try:
        if name == "scan_wireless_networks":
            args = ScanWirelessNetworksArgs(**arguments)
            result = await scan_wireless_networks(
                args.interface,
                args.duration,
                args.channel,
                args.passive_only
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "check_wifi_security":
            args = CheckWifiSecurityArgs(**arguments)
            result = await check_wifi_security(
                args.bssid,
                args.ssid,
                args.interface
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "detect_router_issues":
            args = DetectRouterIssuesArgs(**arguments)
            result = await detect_router_issues(
                args.router_ip,
                args.check_types,
                args.approved
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "check_vlan_segmentation":
            args = CheckVLANSegmentationArgs(**arguments)
            result = await check_vlan_segmentation(
                args.source_network,
                args.target_networks,
                args.interface
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


# ============================================================================
# Tool Implementations
# ============================================================================

async def scan_wireless_networks(
    interface: str = "wlan1",
    duration: int = 30,
    channel: int = 0,
    passive_only: bool = True
) -> dict:
    """
    Scan for wireless networks using passive techniques.

    Args:
        interface: Wireless interface to use (must be secondary, not default route)
        duration: Scan duration in seconds
        channel: Specific channel (0 for all)
        passive_only: Use passive scanning only

    Returns:
        {
            "status": "success",
            "interface": "wlan1",
            "networks": [...],
            "summary": "..."
        }
    """
    try:
        logger.info(f"Starting wireless scan: interface={interface}, duration={duration}s")

        # Check root privileges
        is_root, root_msg = check_root_privileges()
        if not is_root:
            return {"status": "error", "error": root_msg}

        # Validate interface format
        if not validate_interface(interface):
            return {"status": "error", "error": f"Invalid interface name: {interface}"}

        # Validate this is a secondary interface (not default route)
        is_secondary, sec_msg = validate_secondary_interface(interface)
        if not is_secondary:
            return {"status": "error", "error": sec_msg}

        # Validate channel
        if not validate_channel(channel):
            return {"status": "error", "error": f"Invalid channel: {channel}"}

        # Validate duration (10-120 seconds)
        duration = max(10, min(duration, 120))

        # Enable monitor mode
        success, monitor_iface, mon_msg = await enable_monitor_mode(interface)
        if not success:
            return {"status": "error", "error": f"Failed to enable monitor mode: {mon_msg}"}

        try:
            # Create temp file for airodump output
            import uuid
            output_prefix = f"/tmp/airodump_{uuid.uuid4()}"

            # Build airodump-ng command
            cmd_parts = [
                "timeout", str(duration + 5),
                "airodump-ng",
                "--write", output_prefix,
                "--output-format", "csv",
                "--write-interval", "5"
            ]

            if channel > 0:
                cmd_parts.extend(["--channel", str(channel)])

            cmd_parts.append(monitor_iface)

            command = " ".join(cmd_parts)
            logger.debug(f"Running: {command}")

            # Run airodump-ng (will timeout after duration)
            returncode, stdout, stderr = await run_command(command, timeout=duration + 30)

            # Parse the CSV output
            csv_file = f"{output_prefix}-01.csv"
            networks = []

            if Path(csv_file).exists():
                networks = parse_airodump_csv(csv_file)

            # If airodump found nothing, try fallback with iw scan
            # Some adapters (e.g., RTL8188EUS) have limited monitor mode support
            if not networks:
                logger.info("Airodump found no networks, trying fallback with iw scan")
                # Restore managed mode first for iw scan
                await restore_managed_mode(monitor_iface)

                # Use iw scan in managed mode
                networks = await _fallback_iw_scan(interface)

                # Re-enable monitor mode for WPS check if we found networks
                if networks:
                    success, monitor_iface, _ = await enable_monitor_mode(interface)

            # Check for WPS on discovered networks
            if networks:
                wps_info = await _check_wps_status(monitor_iface, duration=10)
                # Merge WPS info into networks
                wps_by_bssid = {w["bssid"]: w for w in wps_info}
                for network in networks:
                    bssid = network.get("bssid", "")
                    if bssid in wps_by_bssid:
                        network["wps_enabled"] = True
                        network["wps_locked"] = wps_by_bssid[bssid].get("wps_locked", False)
                        network["wps_version"] = wps_by_bssid[bssid].get("wps_version", "")
                    else:
                        network["wps_enabled"] = False

                # Check for default SSIDs
                for network in networks:
                    ssid = network.get("ssid", "")
                    is_default, default_type = detect_default_ssid(ssid)
                    network["default_ssid"] = is_default
                    if is_default:
                        network["default_ssid_type"] = default_type

            # Clean up temp files
            for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
                temp_file = Path(f"{output_prefix}{ext}")
                if temp_file.exists():
                    temp_file.unlink()

            # Generate summary
            wps_count = sum(1 for n in networks if n.get("wps_enabled", False))
            default_count = sum(1 for n in networks if n.get("default_ssid", False))
            weak_crypto = sum(1 for n in networks if n.get("encryption", "").upper() in ["WEP", "OPEN"])

            summary = f"Found {len(networks)} networks"
            issues = []
            if wps_count > 0:
                issues.append(f"{wps_count} with WPS")
            if default_count > 0:
                issues.append(f"{default_count} with default SSIDs")
            if weak_crypto > 0:
                issues.append(f"{weak_crypto} with weak encryption")
            if issues:
                summary += f" ({', '.join(issues)})"

            logger.info(summary)

            return {
                "status": "success",
                "interface": interface,
                "monitor_interface": monitor_iface,
                "scan_duration": duration,
                "networks": networks,
                "total_networks": len(networks),
                "wps_enabled_count": wps_count,
                "default_ssid_count": default_count,
                "weak_encryption_count": weak_crypto,
                "summary": summary
            }

        finally:
            # Restore managed mode
            await restore_managed_mode(monitor_iface)

    except Exception as e:
        logger.error(f"Error during wireless scan: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


async def _check_wps_status(interface: str, duration: int = 10) -> List[Dict]:
    """Check WPS status using wash."""
    try:
        import uuid
        output_file = f"/tmp/wash_{uuid.uuid4()}.txt"

        command = f"timeout {duration} wash -i {interface} -C 2>&1 | tee {output_file}"
        returncode, stdout, stderr = await run_command(command, timeout=duration + 10)

        wps_networks = []
        if Path(output_file).exists():
            with open(output_file, 'r') as f:
                output = f.read()
            wps_networks = parse_wash_output(output)
            Path(output_file).unlink()
        elif stdout:
            wps_networks = parse_wash_output(stdout)

        return wps_networks

    except Exception as e:
        logger.warning(f"WPS check failed: {e}")
        return []


async def _fallback_iw_scan(interface: str) -> List[Dict]:
    """
    Fallback wireless scan using iw (managed mode).
    Used when airodump-ng doesn't work (e.g., limited driver support).
    """
    try:
        logger.info(f"Running fallback iw scan on {interface}")

        # Ensure interface is in managed mode and up
        await run_command(f"ip link set {interface} down", timeout=10)
        await run_command(f"iw dev {interface} set type managed", timeout=10)
        await run_command(f"ip link set {interface} up", timeout=10)

        # Wait for interface to stabilize
        import asyncio
        await asyncio.sleep(2)

        # Run iw scan (may need sudo for some systems)
        returncode, stdout, stderr = await run_command(
            f"iw dev {interface} scan",
            timeout=30
        )

        if returncode != 0:
            logger.warning(f"iw scan failed (code {returncode}): {stderr}")
            # Try triggering scan first, then dump results
            await run_command(f"iw dev {interface} scan trigger", timeout=10)
            await asyncio.sleep(3)
            returncode, stdout, stderr = await run_command(
                f"iw dev {interface} scan dump",
                timeout=30
            )
            if returncode != 0:
                logger.warning(f"iw scan dump also failed: {stderr}")
                return []

        networks = []
        current_network = None

        for line in stdout.split('\n'):
            line = line.strip()

            # New BSS (network)
            if line.startswith("BSS "):
                if current_network and current_network.get("bssid"):
                    networks.append(current_network)
                # Extract BSSID from "BSS aa:bb:cc:dd:ee:ff(on wlan1)"
                bssid_match = re.match(r'BSS ([0-9a-fA-F:]{17})', line)
                current_network = {
                    "bssid": bssid_match.group(1).upper() if bssid_match else "",
                    "ssid": "",
                    "channel": 0,
                    "signal": -100,
                    "encryption": "OPEN",
                    "hidden": False
                }

            elif current_network:
                if line.startswith("SSID:"):
                    ssid = line[5:].strip()
                    current_network["ssid"] = ssid
                    current_network["hidden"] = not ssid

                elif line.startswith("freq:"):
                    # Convert frequency to channel
                    try:
                        freq = float(line.split(":")[1].strip().split()[0])
                        if 2400 <= freq <= 2500:
                            current_network["channel"] = int((freq - 2407) / 5)
                        elif 5000 <= freq <= 6000:
                            current_network["channel"] = int((freq - 5000) / 5)
                    except:
                        pass

                elif line.startswith("signal:"):
                    try:
                        signal = float(line.split(":")[1].strip().split()[0])
                        current_network["signal"] = int(signal)
                        current_network["power"] = int(signal)
                    except:
                        pass

                elif "WPA2" in line or "RSN" in line:
                    current_network["encryption"] = "WPA2"
                elif "WPA" in line and "WPA2" not in current_network.get("encryption", ""):
                    current_network["encryption"] = "WPA"
                elif "WEP" in line:
                    current_network["encryption"] = "WEP"
                elif "Privacy" in line:
                    if current_network["encryption"] == "OPEN":
                        current_network["encryption"] = "ENCRYPTED"

        # Don't forget the last network
        if current_network and current_network.get("bssid"):
            networks.append(current_network)

        logger.info(f"iw scan found {len(networks)} networks")
        return networks

    except Exception as e:
        logger.error(f"Fallback iw scan failed: {e}")
        return []


async def check_wifi_security(
    bssid: str,
    ssid: str = "",
    interface: str = "wlan1"
) -> dict:
    """
    Analyze security configuration of a specific wireless network.

    Args:
        bssid: Target network BSSID
        ssid: Target network SSID (optional)
        interface: Wireless interface to use

    Returns:
        {
            "status": "success",
            "bssid": "...",
            "security_issues": [...],
            "recommendations": [...]
        }
    """
    try:
        logger.info(f"Checking Wi-Fi security: BSSID={bssid}, SSID={ssid}")

        # Check root privileges
        is_root, root_msg = check_root_privileges()
        if not is_root:
            return {"status": "error", "error": root_msg}

        # Validate BSSID
        if not validate_bssid(bssid):
            return {"status": "error", "error": f"Invalid BSSID format: {bssid}"}

        # Validate interface
        if not validate_interface(interface):
            return {"status": "error", "error": f"Invalid interface name: {interface}"}

        is_secondary, sec_msg = validate_secondary_interface(interface)
        if not is_secondary:
            return {"status": "error", "error": sec_msg}

        security_issues = []
        recommendations = []
        network_info = {
            "bssid": bssid.upper(),
            "ssid": ssid,
            "encryption": "unknown",
            "wps_enabled": False,
            "wps_locked": False
        }

        # Enable monitor mode for scanning
        success, monitor_iface, mon_msg = await enable_monitor_mode(interface)
        if not success:
            return {"status": "error", "error": f"Failed to enable monitor mode: {mon_msg}"}

        try:
            # Scan for the specific network
            import uuid
            output_prefix = f"/tmp/airodump_{uuid.uuid4()}"

            command = f"timeout 15 airodump-ng --bssid {bssid} --write {output_prefix} --output-format csv {monitor_iface}"
            await run_command(command, timeout=20)

            csv_file = f"{output_prefix}-01.csv"
            if Path(csv_file).exists():
                networks = parse_airodump_csv(csv_file)
                if networks:
                    network_info.update(networks[0])

                # Clean up
                for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml"]:
                    temp_file = Path(f"{output_prefix}{ext}")
                    if temp_file.exists():
                        temp_file.unlink()

            # Check encryption type
            encryption = network_info.get("encryption", "").upper()

            if encryption == "OPEN" or not encryption:
                security_issues.append({
                    "type": "open_network",
                    "severity": "critical",
                    "description": "Network has no encryption - all traffic is visible"
                })
                recommendations.append("Enable WPA3 or WPA2 encryption immediately")

            elif encryption == "WEP":
                security_issues.append({
                    "type": "weak_encryption",
                    "severity": "critical",
                    "description": "WEP encryption is broken and can be cracked in minutes"
                })
                recommendations.append("Upgrade to WPA2 or WPA3 encryption")

            elif "WPA-" in encryption and "WPA2" not in encryption:
                security_issues.append({
                    "type": "outdated_encryption",
                    "severity": "high",
                    "description": "WPA (original) has known vulnerabilities"
                })
                recommendations.append("Upgrade to WPA2 or WPA3")

            elif "WPA2-PSK" in encryption:
                security_issues.append({
                    "type": "psk_mode",
                    "severity": "info",
                    "description": "WPA2-PSK is secure but shared key can be vulnerable to offline attacks"
                })
                recommendations.append("Consider WPA2-Enterprise for business environments")

            # Check for WPS
            wps_info = await _check_wps_status(monitor_iface, duration=10)
            wps_by_bssid = {w["bssid"].upper(): w for w in wps_info}

            if bssid.upper() in wps_by_bssid:
                network_info["wps_enabled"] = True
                wps_data = wps_by_bssid[bssid.upper()]
                network_info["wps_locked"] = wps_data.get("wps_locked", False)
                network_info["wps_version"] = wps_data.get("wps_version", "")

                if not wps_data.get("wps_locked", False):
                    security_issues.append({
                        "type": "wps_enabled",
                        "severity": "high",
                        "description": "WPS is enabled and unlocked - vulnerable to brute force attacks"
                    })
                    recommendations.append("Disable WPS in router settings")
                else:
                    security_issues.append({
                        "type": "wps_locked",
                        "severity": "medium",
                        "description": "WPS is enabled but locked - may still be vulnerable"
                    })
                    recommendations.append("Consider disabling WPS entirely")

            # Check for default SSID
            current_ssid = network_info.get("ssid", ssid)
            is_default, default_type = detect_default_ssid(current_ssid)
            network_info["default_ssid"] = is_default

            if is_default:
                security_issues.append({
                    "type": "default_ssid",
                    "severity": "medium",
                    "description": f"Default SSID detected ({default_type}) - may indicate default configuration"
                })
                recommendations.append("Change SSID to a custom name and verify all settings are configured")

            # Generate summary
            critical = sum(1 for i in security_issues if i["severity"] == "critical")
            high = sum(1 for i in security_issues if i["severity"] == "high")
            medium = sum(1 for i in security_issues if i["severity"] == "medium")

            summary = f"Security check complete: {len(security_issues)} issues found"
            if critical > 0:
                summary += f" ({critical} critical)"

            return {
                "status": "success",
                "network": network_info,
                "security_issues": security_issues,
                "issue_count": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "total": len(security_issues)
                },
                "recommendations": recommendations,
                "summary": summary
            }

        finally:
            await restore_managed_mode(monitor_iface)

    except Exception as e:
        logger.error(f"Error during Wi-Fi security check: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


async def detect_router_issues(
    router_ip: str,
    check_types: list = None,
    approved: bool = False
) -> dict:
    """
    Detect router misconfigurations.

    Args:
        router_ip: Router IP address
        check_types: Types of checks to perform
        approved: Explicit approval for credential testing

    Returns:
        {
            "status": "success",
            "router_ip": "...",
            "issues": [...],
            "recommendations": [...]
        }
    """
    try:
        if check_types is None:
            check_types = ["http_admin", "firmware", "upnp", "dns"]

        logger.info(f"Detecting router issues: router_ip={router_ip}, checks={check_types}")

        # Validate router IP
        if not validate_ip(router_ip):
            return {"status": "error", "error": f"Invalid router IP: {router_ip}"}

        issues = []
        recommendations = []
        router_info = {
            "ip": router_ip,
            "http_port": None,
            "https_port": None,
            "firmware_version": None,
            "model": None
        }

        # Check for credential testing approval
        if "default_creds" in check_types:
            if not approved:
                return {
                    "status": "error",
                    "error": "APPROVAL REQUIRED: Credential testing requires explicit approval. Set approved=true to proceed.",
                    "check_types_requiring_approval": ["default_creds"]
                }

            # Check rate limit
            is_allowed, remaining = check_credential_rate_limit(router_ip)
            if not is_allowed:
                return {
                    "status": "error",
                    "error": f"Rate limit exceeded: max {MAX_CRED_ATTEMPTS} attempts per {ATTEMPT_WINDOW}s",
                    "attempts_remaining": 0
                }

        # HTTP Admin Panel Check
        if "http_admin" in check_types:
            http_issues = await _check_http_admin(router_ip)
            issues.extend(http_issues["issues"])
            recommendations.extend(http_issues["recommendations"])
            router_info.update(http_issues.get("info", {}))

        # Firmware Version Check
        if "firmware" in check_types:
            fw_issues = await _check_firmware(router_ip, router_info)
            issues.extend(fw_issues["issues"])
            recommendations.extend(fw_issues["recommendations"])

        # UPnP Check
        if "upnp" in check_types:
            upnp_issues = await _check_upnp(router_ip)
            issues.extend(upnp_issues["issues"])
            recommendations.extend(upnp_issues["recommendations"])

        # DNS Check
        if "dns" in check_types:
            dns_issues = await _check_dns(router_ip)
            issues.extend(dns_issues["issues"])
            recommendations.extend(dns_issues["recommendations"])

        # Default Credentials Check (requires approval)
        if "default_creds" in check_types and approved:
            cred_issues = await _check_default_credentials(router_ip)
            issues.extend(cred_issues["issues"])
            recommendations.extend(cred_issues["recommendations"])
            record_credential_attempt(router_ip)

        # SNMP Check
        if "snmp" in check_types:
            snmp_issues = await _check_snmp(router_ip)
            issues.extend(snmp_issues["issues"])
            recommendations.extend(snmp_issues["recommendations"])

        # Generate summary
        critical = sum(1 for i in issues if i.get("severity") == "critical")
        high = sum(1 for i in issues if i.get("severity") == "high")

        summary = f"Router check complete: {len(issues)} issues found"
        if critical > 0:
            summary += f" ({critical} critical, {high} high)"

        return {
            "status": "success",
            "router_ip": router_ip,
            "router_info": router_info,
            "issues": issues,
            "issue_count": {
                "critical": critical,
                "high": high,
                "total": len(issues)
            },
            "recommendations": list(set(recommendations)),  # Deduplicate
            "summary": summary
        }

    except Exception as e:
        logger.error(f"Error during router issue detection: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


async def _check_http_admin(router_ip: str) -> dict:
    """Check HTTP admin panel configuration."""
    issues = []
    recommendations = []
    info = {}

    try:
        # Check HTTP (port 80)
        returncode, stdout, stderr = await run_command(
            f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{router_ip}/",
            timeout=10
        )

        if returncode == 0 and stdout.strip() in ["200", "301", "302", "401", "403"]:
            info["http_port"] = 80
            issues.append({
                "type": "http_admin_no_tls",
                "severity": "high",
                "description": "HTTP admin panel accessible without TLS encryption",
                "port": 80
            })
            recommendations.append("Enable HTTPS and disable HTTP access to admin panel")

        # Check HTTPS (port 443)
        returncode, stdout, stderr = await run_command(
            f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 -k https://{router_ip}/",
            timeout=10
        )

        if returncode == 0 and stdout.strip() in ["200", "301", "302", "401", "403"]:
            info["https_port"] = 443

            # Check for self-signed certificate
            returncode, stdout, stderr = await run_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 https://{router_ip}/",
                timeout=10
            )

            if returncode != 0:
                issues.append({
                    "type": "self_signed_cert",
                    "severity": "medium",
                    "description": "HTTPS uses self-signed or invalid certificate",
                    "port": 443
                })

        # Check common alternate ports
        for port in [8080, 8443, 8000]:
            returncode, stdout, stderr = await run_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 http://{router_ip}:{port}/",
                timeout=8
            )

            if returncode == 0 and stdout.strip() in ["200", "301", "302", "401", "403"]:
                info[f"http_port_{port}"] = port
                issues.append({
                    "type": "http_admin_alt_port",
                    "severity": "medium",
                    "description": f"Admin panel accessible on alternate port {port}",
                    "port": port
                })

    except Exception as e:
        logger.warning(f"HTTP admin check failed: {e}")

    return {"issues": issues, "recommendations": recommendations, "info": info}


async def _check_firmware(router_ip: str, router_info: dict) -> dict:
    """Check firmware information."""
    issues = []
    recommendations = []

    try:
        # Try to get banner/version from HTTP headers
        returncode, stdout, stderr = await run_command(
            f"curl -s -I --connect-timeout 5 http://{router_ip}/ 2>/dev/null | head -20",
            timeout=10
        )

        if returncode == 0 and stdout:
            # Look for Server header
            for line in stdout.split('\n'):
                if line.lower().startswith('server:'):
                    server_info = line.split(':', 1)[1].strip()
                    router_info["server_banner"] = server_info

                    # Check for version information disclosure
                    if any(v in server_info.lower() for v in ['version', 'v1.', 'v2.', '1.0', '2.0']):
                        issues.append({
                            "type": "version_disclosure",
                            "severity": "low",
                            "description": f"Firmware/software version disclosed: {server_info}"
                        })

        # Try UPnP for device info
        returncode, stdout, stderr = await run_command(
            f"curl -s --connect-timeout 5 'http://{router_ip}:1900/rootDesc.xml' 2>/dev/null",
            timeout=10
        )

        if returncode == 0 and stdout and '<modelName>' in stdout:
            # Parse model info
            model_match = re.search(r'<modelName>([^<]+)</modelName>', stdout)
            if model_match:
                router_info["model"] = model_match.group(1)

            firmware_match = re.search(r'<firmwareVersion>([^<]+)</firmwareVersion>', stdout)
            if firmware_match:
                router_info["firmware_version"] = firmware_match.group(1)
                issues.append({
                    "type": "firmware_info_exposed",
                    "severity": "info",
                    "description": f"Firmware version exposed via UPnP: {firmware_match.group(1)}"
                })

    except Exception as e:
        logger.warning(f"Firmware check failed: {e}")

    return {"issues": issues, "recommendations": recommendations}


async def _check_upnp(router_ip: str) -> dict:
    """Check UPnP configuration."""
    issues = []
    recommendations = []

    try:
        # Check for UPnP on common ports
        for port in [1900, 5000, 49152]:
            returncode, stdout, stderr = await run_command(
                f"curl -s --connect-timeout 3 'http://{router_ip}:{port}/' 2>/dev/null | head -5",
                timeout=8
            )

            if returncode == 0 and stdout and ('upnp' in stdout.lower() or 'igd' in stdout.lower()):
                issues.append({
                    "type": "upnp_enabled",
                    "severity": "medium",
                    "description": f"UPnP service accessible on port {port}",
                    "port": port
                })
                recommendations.append("Disable UPnP unless specifically required")

        # SSDP discovery
        returncode, stdout, stderr = await run_command(
            f"echo -e 'M-SEARCH * HTTP/1.1\\r\\nHOST: {router_ip}:1900\\r\\nMAN: \"ssdp:discover\"\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -u -w3 {router_ip} 1900 2>/dev/null | head -20",
            timeout=10
        )

        if returncode == 0 and stdout and 'HTTP/1.1 200' in stdout:
            issues.append({
                "type": "ssdp_responding",
                "severity": "low",
                "description": "Router responds to SSDP discovery requests"
            })

    except Exception as e:
        logger.warning(f"UPnP check failed: {e}")

    return {"issues": issues, "recommendations": recommendations}


async def _check_dns(router_ip: str) -> dict:
    """Check DNS configuration."""
    issues = []
    recommendations = []

    try:
        # Check if router is an open resolver
        returncode, stdout, stderr = await run_command(
            f"dig @{router_ip} google.com +short +time=3 +tries=1 2>/dev/null",
            timeout=10
        )

        if returncode == 0 and stdout.strip():
            # Check if it resolves external domains (open resolver)
            issues.append({
                "type": "dns_open_resolver",
                "severity": "medium",
                "description": "Router acts as DNS resolver - verify this is intentional"
            })

            # Check for DNS rebinding protection
            returncode, stdout, stderr = await run_command(
                f"dig @{router_ip} localhost +short +time=3 +tries=1 2>/dev/null",
                timeout=10
            )

            if returncode == 0 and '127.0.0.1' in stdout:
                issues.append({
                    "type": "dns_rebind_possible",
                    "severity": "low",
                    "description": "DNS resolves localhost - may allow DNS rebinding attacks"
                })

    except Exception as e:
        logger.warning(f"DNS check failed: {e}")

    return {"issues": issues, "recommendations": recommendations}


async def _check_default_credentials(router_ip: str) -> dict:
    """Check for default credentials (rate limited, requires approval)."""
    issues = []
    recommendations = []

    try:
        # Load credentials from SecLists
        credentials = load_router_credentials()

        # Limit to first 5 common pairs to stay low-noise
        test_credentials = credentials[:5]

        for username, password in test_credentials:
            # Test HTTP Basic Auth
            auth_string = f"{username}:{password}"

            returncode, stdout, stderr = await run_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 -u '{auth_string}' http://{router_ip}/",
                timeout=10
            )

            if returncode == 0 and stdout.strip() == "200":
                issues.append({
                    "type": "default_credentials",
                    "severity": "critical",
                    "description": f"Default credentials work: {username}:{password[:2]}***",
                    "username": username,
                    "password_hint": f"{password[:2]}***"
                })
                recommendations.append("Change default router credentials immediately")
                break  # Stop after finding working credentials

            # Small delay between attempts
            await asyncio.sleep(0.5)

    except Exception as e:
        logger.warning(f"Credential check failed: {e}")

    return {"issues": issues, "recommendations": recommendations}


async def _check_snmp(router_ip: str) -> dict:
    """Check SNMP configuration."""
    issues = []
    recommendations = []

    try:
        # Check for SNMP with default community strings
        for community in ["public", "private"]:
            returncode, stdout, stderr = await run_command(
                f"snmpwalk -v2c -c {community} {router_ip} system 2>/dev/null | head -3",
                timeout=10
            )

            if returncode == 0 and stdout and 'SNMPv2-MIB' in stdout:
                issues.append({
                    "type": "snmp_default_community",
                    "severity": "high",
                    "description": f"SNMP accessible with default community string: {community}"
                })
                recommendations.append("Disable SNMP or change community strings")
                break

    except Exception as e:
        logger.warning(f"SNMP check failed: {e}")

    return {"issues": issues, "recommendations": recommendations}


async def check_vlan_segmentation(
    source_network: str,
    target_networks: list,
    interface: str = ""
) -> dict:
    """
    Test network segmentation between VLANs.

    Args:
        source_network: Current network/subnet
        target_networks: List of target networks to test
        interface: Interface to use (optional)

    Returns:
        {
            "status": "success",
            "reachable_networks": [...],
            "unreachable_networks": [...],
            "segmentation_issues": [...]
        }
    """
    try:
        logger.info(f"Checking VLAN segmentation from {source_network} to {target_networks}")

        # Validate source network
        if not (validate_ip(source_network) or validate_cidr(source_network)):
            return {"status": "error", "error": f"Invalid source network: {source_network}"}

        # Validate target networks
        for target in target_networks:
            if not (validate_ip(target) or validate_cidr(target)):
                return {"status": "error", "error": f"Invalid target network: {target}"}

        reachable = []
        unreachable = []
        segmentation_issues = []

        for target in target_networks:
            # Extract a test IP from CIDR if needed
            test_ip = target.split('/')[0] if '/' in target else target

            # If CIDR, use first usable IP
            if '/' in target:
                try:
                    import ipaddress
                    network = ipaddress.ip_network(target, strict=False)
                    hosts = list(network.hosts())
                    if hosts:
                        test_ip = str(hosts[0])
                except Exception:
                    pass

            # ICMP ping test
            cmd = f"ping -c 2 -W 2 {test_ip}"
            if interface:
                cmd = f"ping -c 2 -W 2 -I {interface} {test_ip}"

            returncode, stdout, stderr = await run_command(cmd, timeout=10)

            if returncode == 0 and "bytes from" in stdout:
                reachable.append({
                    "network": target,
                    "test_ip": test_ip,
                    "method": "icmp",
                    "response_time": _extract_ping_time(stdout)
                })

                segmentation_issues.append({
                    "type": "cross_vlan_reachable",
                    "severity": "medium",
                    "description": f"Network {target} is reachable from {source_network} via ICMP"
                })
            else:
                # Try TCP probe on common ports
                tcp_reachable = False
                for port in [22, 80, 443, 445]:
                    returncode, stdout, stderr = await run_command(
                        f"nc -z -w 2 {test_ip} {port} 2>/dev/null",
                        timeout=5
                    )

                    if returncode == 0:
                        tcp_reachable = True
                        reachable.append({
                            "network": target,
                            "test_ip": test_ip,
                            "method": f"tcp/{port}"
                        })
                        segmentation_issues.append({
                            "type": "cross_vlan_tcp",
                            "severity": "medium",
                            "description": f"Network {target} reachable on TCP port {port} from {source_network}"
                        })
                        break

                if not tcp_reachable:
                    unreachable.append({
                        "network": target,
                        "test_ip": test_ip
                    })

        # Generate summary
        summary = f"Segmentation check: {len(reachable)} reachable, {len(unreachable)} blocked"
        if segmentation_issues:
            summary += f" ({len(segmentation_issues)} potential issues)"

        return {
            "status": "success",
            "source_network": source_network,
            "reachable_networks": reachable,
            "unreachable_networks": unreachable,
            "segmentation_issues": segmentation_issues,
            "summary": summary
        }

    except Exception as e:
        logger.error(f"Error during VLAN segmentation check: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


def _extract_ping_time(ping_output: str) -> str:
    """Extract round-trip time from ping output."""
    match = re.search(r'time[=<](\d+\.?\d*)\s*ms', ping_output)
    if match:
        return f"{match.group(1)}ms"
    return "unknown"


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for Wi-Fi server."""
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-wifi v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Wi-Fi Server - Test Mode")
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
