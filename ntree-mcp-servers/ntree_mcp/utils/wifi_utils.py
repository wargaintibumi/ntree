"""
Wi-Fi and Router Security Assessment Utilities
Validation, monitor mode management, and output parsing
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Blocked Operations - Safety Controls
# ============================================================================

BLOCKED_OPERATIONS = [
    "deauth",           # Deauthentication attacks
    "aireplay",         # Active injection (includes deauth)
    "aircrack",         # WPA/WEP cracking
    "hashcat",          # Password cracking
    "cowpatty",         # WPA cracking
    "reaver",           # WPS brute force
    "bully",            # WPS brute force
    "wifite",           # Automated attacks
    "fern",             # Automated attacks
    "fluxion",          # Evil twin attacks
    "mdk3",             # Denial of service
    "mdk4",             # Denial of service
]


def is_operation_blocked(command: str) -> Tuple[bool, str]:
    """
    Check if a command contains blocked operations.

    Args:
        command: Command string to check

    Returns:
        Tuple of (is_blocked, reason)
    """
    command_lower = command.lower()
    for blocked in BLOCKED_OPERATIONS:
        if blocked in command_lower:
            return True, f"Operation '{blocked}' is explicitly blocked for safety"
    return False, ""


# ============================================================================
# Root Privilege Check
# ============================================================================

def check_root_privileges() -> Tuple[bool, str]:
    """
    Check if running with root privileges.

    Returns:
        Tuple of (is_root, message)
    """
    if os.geteuid() == 0:
        return True, "Running as root"
    return False, "Wi-Fi operations require root privileges. Run with sudo."


# ============================================================================
# Validation Functions
# ============================================================================

def validate_bssid(bssid: str) -> bool:
    """
    Validate BSSID (MAC address) format.

    Args:
        bssid: BSSID string to validate

    Returns:
        True if valid MAC address format
    """
    pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    return bool(re.match(pattern, bssid))


def validate_ssid(ssid: str) -> bool:
    """
    Validate SSID format.

    Args:
        ssid: SSID string to validate

    Returns:
        True if valid SSID (1-32 printable characters)
    """
    if not ssid or len(ssid) > 32:
        return False
    # Allow printable ASCII characters
    return all(32 <= ord(c) <= 126 for c in ssid)


def validate_channel(channel: int) -> bool:
    """
    Validate Wi-Fi channel number.

    Args:
        channel: Channel number to validate

    Returns:
        True if valid Wi-Fi channel
    """
    # 2.4GHz channels (1-14)
    channels_24ghz = list(range(1, 15))

    # 5GHz channels (common ones)
    channels_5ghz = [
        36, 40, 44, 48,           # UNII-1
        52, 56, 60, 64,           # UNII-2A
        100, 104, 108, 112, 116,  # UNII-2C
        120, 124, 128, 132, 136, 140, 144,  # UNII-2C Extended
        149, 153, 157, 161, 165   # UNII-3
    ]

    valid_channels = channels_24ghz + channels_5ghz

    # Channel 0 means "all channels"
    return channel == 0 or channel in valid_channels


def validate_interface(interface: str) -> bool:
    """
    Validate wireless interface name format.

    Args:
        interface: Interface name to validate

    Returns:
        True if valid interface name format
    """
    # Common formats: wlan0, wlan1, wlp2s0, ath0, etc.
    pattern = r'^[a-zA-Z]+[0-9a-zA-Z]*$'
    return bool(re.match(pattern, interface)) and len(interface) <= 15


# ============================================================================
# Interface Management
# ============================================================================

def get_default_route_interface() -> Optional[str]:
    """
    Get the interface used for the default route.

    Returns:
        Interface name or None if not found
    """
    try:
        # Use ip route to find default route interface
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 and result.stdout:
            # Parse output like: "default via 192.168.1.1 dev wlan0 proto dhcp"
            parts = result.stdout.split()
            if "dev" in parts:
                dev_index = parts.index("dev")
                if dev_index + 1 < len(parts):
                    return parts[dev_index + 1]
    except Exception as e:
        logger.warning(f"Error getting default route interface: {e}")

    return None


def validate_secondary_interface(interface: str) -> Tuple[bool, str]:
    """
    Validate that interface is NOT the default route interface.

    Args:
        interface: Interface name to check

    Returns:
        Tuple of (is_valid, message)
    """
    default_iface = get_default_route_interface()

    if default_iface is None:
        logger.warning("Could not determine default route interface")
        return True, "Warning: Could not verify default route interface"

    if interface == default_iface:
        return False, f"Cannot use primary interface '{interface}' - it handles network connectivity. Use a secondary adapter."

    return True, f"Interface '{interface}' is not the default route (safe to use)"


def get_wireless_interfaces() -> List[Dict]:
    """
    Get list of wireless interfaces on the system.

    Returns:
        List of interface dictionaries with name, mode, and status
    """
    interfaces = []

    try:
        # Use iw dev to list wireless interfaces
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            current_interface = None

            for line in result.stdout.split('\n'):
                line = line.strip()

                if line.startswith("Interface"):
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {
                        "name": line.split()[1],
                        "mode": "unknown",
                        "type": "wireless"
                    }
                elif current_interface and line.startswith("type"):
                    current_interface["mode"] = line.split()[1]

            if current_interface:
                interfaces.append(current_interface)

    except FileNotFoundError:
        logger.warning("iw command not found - wireless tools may not be installed")
    except Exception as e:
        logger.warning(f"Error listing wireless interfaces: {e}")

    return interfaces


# ============================================================================
# Monitor Mode Management
# ============================================================================

async def enable_monitor_mode(interface: str) -> Tuple[bool, str, str]:
    """
    Enable monitor mode on wireless interface using iw commands.

    SAFE APPROACH: Uses iw instead of airmon-ng to avoid killing
    wpa_supplicant and disrupting the primary network connection.

    Args:
        interface: Interface name (e.g., wlan1)

    Returns:
        Tuple of (success, monitor_interface_name, message)
    """
    from .command_runner import run_command

    # Validate interface first
    is_secondary, msg = validate_secondary_interface(interface)
    if not is_secondary:
        return False, "", msg

    try:
        # Check if already in monitor mode
        returncode, stdout, stderr = await run_command(
            f"iw dev {interface} info 2>/dev/null | grep -i monitor",
            timeout=10
        )

        if returncode == 0 and "monitor" in stdout.lower():
            logger.info(f"Interface {interface} already in monitor mode")
            return True, interface, "Already in monitor mode"

        logger.info(f"Enabling monitor mode on {interface} (safe method)")

        # Step 1: Tell NetworkManager to ignore this interface (if NM is running)
        # This prevents NM from interfering without killing it
        await run_command(
            f"nmcli device set {interface} managed no 2>/dev/null || true",
            timeout=10
        )

        # Step 2: Bring interface down
        returncode, stdout, stderr = await run_command(
            f"ip link set {interface} down",
            timeout=10
        )
        if returncode != 0:
            return False, "", f"Failed to bring interface down: {stderr}"

        # Step 3: Set monitor mode using iw
        returncode, stdout, stderr = await run_command(
            f"iw dev {interface} set type monitor",
            timeout=10
        )
        if returncode != 0:
            # Try to bring interface back up before failing
            await run_command(f"ip link set {interface} up", timeout=10)
            return False, "", f"Failed to set monitor mode: {stderr}"

        # Step 4: Bring interface back up
        returncode, stdout, stderr = await run_command(
            f"ip link set {interface} up",
            timeout=10
        )
        if returncode != 0:
            return False, "", f"Failed to bring interface up: {stderr}"

        # Step 5: Verify monitor mode
        returncode, stdout, stderr = await run_command(
            f"iw dev {interface} info",
            timeout=10
        )

        if returncode == 0 and "monitor" in stdout.lower():
            logger.info(f"Monitor mode enabled on {interface}")
            return True, interface, f"Monitor mode enabled on {interface}"

        return False, "", "Failed to verify monitor mode"

    except Exception as e:
        logger.error(f"Error enabling monitor mode: {e}")
        return False, "", str(e)


async def restore_managed_mode(interface: str) -> Tuple[bool, str]:
    """
    Restore managed mode on wireless interface.

    SAFE APPROACH: Uses iw to restore managed mode without
    affecting other network interfaces.

    Args:
        interface: Interface name (may include 'mon' suffix)

    Returns:
        Tuple of (success, message)
    """
    from .command_runner import run_command

    # Handle interface names with 'mon' suffix
    base_interface = interface.replace("mon", "") if interface.endswith("mon") else interface

    try:
        logger.info(f"Restoring managed mode on {interface}")

        # Step 1: Bring interface down
        await run_command(f"ip link set {interface} down", timeout=10)

        # Step 2: Set managed mode using iw
        returncode, stdout, stderr = await run_command(
            f"iw dev {interface} set type managed",
            timeout=10
        )

        if returncode != 0:
            logger.warning(f"iw set type managed failed: {stderr}")
            # Try with base interface name
            if interface != base_interface:
                await run_command(
                    f"iw dev {base_interface} set type managed",
                    timeout=10
                )

        # Step 3: Bring interface back up
        await run_command(f"ip link set {interface} up 2>/dev/null || ip link set {base_interface} up", timeout=10)

        # Step 4: Tell NetworkManager to manage the interface again
        await run_command(
            f"nmcli device set {base_interface} managed yes 2>/dev/null || true",
            timeout=10
        )

        return True, "Managed mode restored"

    except Exception as e:
        logger.error(f"Error restoring managed mode: {e}")
        return False, str(e)


# ============================================================================
# Output Parsers
# ============================================================================

def parse_airodump_csv(csv_path: str) -> List[Dict]:
    """
    Parse airodump-ng CSV output file.

    Args:
        csv_path: Path to CSV file

    Returns:
        List of network dictionaries
    """
    networks = []

    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        in_networks_section = False
        header_found = False

        for line in lines:
            line = line.strip()

            if not line:
                continue

            # airodump CSV has two sections: networks and clients
            # Networks section starts with "BSSID, First time seen, ..."
            if line.startswith("BSSID,"):
                in_networks_section = True
                header_found = True
                continue

            # Clients section starts with "Station MAC, First time seen, ..."
            if line.startswith("Station MAC,"):
                in_networks_section = False
                continue

            if in_networks_section and header_found:
                parts = [p.strip() for p in line.split(',')]

                if len(parts) >= 14:
                    bssid = parts[0]

                    # Validate BSSID
                    if not validate_bssid(bssid):
                        continue

                    # Parse encryption
                    privacy = parts[5].strip()
                    cipher = parts[6].strip()
                    auth = parts[7].strip()

                    encryption = "OPEN"
                    if "WPA3" in privacy:
                        encryption = "WPA3"
                    elif "WPA2" in privacy:
                        encryption = f"WPA2-{auth}" if auth else "WPA2"
                    elif "WPA" in privacy:
                        encryption = f"WPA-{auth}" if auth else "WPA"
                    elif "WEP" in privacy:
                        encryption = "WEP"
                    elif "OPN" in privacy:
                        encryption = "OPEN"

                    network = {
                        "bssid": bssid,
                        "first_seen": parts[1],
                        "last_seen": parts[2],
                        "channel": int(parts[3]) if parts[3].strip().isdigit() else 0,
                        "speed": parts[4],
                        "encryption": encryption,
                        "cipher": cipher,
                        "auth": auth,
                        "power": int(parts[8]) if parts[8].strip().lstrip('-').isdigit() else -100,
                        "beacons": int(parts[9]) if parts[9].strip().isdigit() else 0,
                        "data": int(parts[10]) if parts[10].strip().isdigit() else 0,
                        "ssid": parts[13] if len(parts) > 13 else "",
                        "hidden": parts[13].strip() == "" if len(parts) > 13 else True,
                    }
                    networks.append(network)

    except FileNotFoundError:
        logger.error(f"CSV file not found: {csv_path}")
    except Exception as e:
        logger.error(f"Error parsing airodump CSV: {e}")

    return networks


def parse_wash_output(output: str) -> List[Dict]:
    """
    Parse wash (WPS scanner) output.

    Args:
        output: Raw wash output string

    Returns:
        List of WPS-enabled network dictionaries
    """
    wps_networks = []

    try:
        lines = output.strip().split('\n')

        # Skip header lines
        data_started = False

        for line in lines:
            line = line.strip()

            if not line:
                continue

            # Data starts after header (look for dashes or BSSID pattern)
            if line.startswith('--') or line.startswith('=='):
                data_started = True
                continue

            if not data_started:
                # Check if this looks like a BSSID line
                if re.match(r'^[0-9A-Fa-f]{2}:', line):
                    data_started = True
                else:
                    continue

            # Parse wash output line
            # Format: BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
            parts = line.split()

            if len(parts) >= 6:
                bssid = parts[0]

                if validate_bssid(bssid):
                    wps_info = {
                        "bssid": bssid,
                        "channel": int(parts[1]) if parts[1].isdigit() else 0,
                        "signal": int(parts[2]) if parts[2].lstrip('-').isdigit() else -100,
                        "wps_version": parts[3],
                        "wps_locked": parts[4].upper() == "YES" or parts[4] == "1",
                        "vendor": parts[5] if len(parts) > 5 else "",
                        "ssid": " ".join(parts[6:]) if len(parts) > 6 else "",
                    }
                    wps_networks.append(wps_info)

    except Exception as e:
        logger.error(f"Error parsing wash output: {e}")

    return wps_networks


# ============================================================================
# Default SSID Pattern Detection
# ============================================================================

DEFAULT_SSID_PATTERNS = [
    # Router manufacturers
    (r'^NETGEAR', "NETGEAR router"),
    (r'^NETGEAR-', "NETGEAR router"),
    (r'^linksys', "Linksys router"),
    (r'^Linksys', "Linksys router"),
    (r'^ASUS', "ASUS router"),
    (r'^ASUS_', "ASUS router"),
    (r'^TP-Link', "TP-Link router"),
    (r'^TP-LINK', "TP-Link router"),
    (r'^D-Link', "D-Link router"),
    (r'^DLINK', "D-Link router"),
    (r'^Cisco', "Cisco equipment"),
    (r'^ARRIS', "ARRIS router"),
    (r'^ATT', "AT&T router"),
    (r'^Verizon', "Verizon router"),
    (r'^XFINITY', "Xfinity/Comcast router"),
    (r'^xfinitywifi', "Xfinity hotspot"),
    (r'^Frontier', "Frontier router"),
    (r'^CenturyLink', "CenturyLink router"),
    (r'^SKY', "Sky router"),
    (r'^BT-', "BT router"),
    (r'^EE-', "EE router"),
    (r'^virginmedia', "Virgin Media router"),
    (r'^HUAWEI', "Huawei router"),
    (r'^ZTE', "ZTE router"),
    (r'^Ubiquiti', "Ubiquiti equipment"),
    (r'^UniFi', "Ubiquiti UniFi"),

    # Generic patterns
    (r'^default', "Default SSID"),
    (r'^DEFAULT', "Default SSID"),
    (r'^setup$', "Setup network"),
    (r'^admin$', "Admin network"),
    (r'^HOME-', "ISP default naming"),
    (r'^DIRECT-', "Wi-Fi Direct"),
    (r'^PRINTER', "Printer network"),
]


def detect_default_ssid(ssid: str) -> Tuple[bool, str]:
    """
    Check if SSID matches known default patterns.

    Args:
        ssid: SSID to check

    Returns:
        Tuple of (is_default, pattern_description)
    """
    if not ssid:
        return True, "Hidden/empty SSID"

    for pattern, description in DEFAULT_SSID_PATTERNS:
        if re.match(pattern, ssid, re.IGNORECASE):
            return True, description

    return False, ""


# ============================================================================
# SecLists Credential Loading
# ============================================================================

def load_router_credentials(seclists_path: str = "/usr/share/seclists") -> List[Tuple[str, str]]:
    """
    Load default router credentials from SecLists.

    Args:
        seclists_path: Path to SecLists directory

    Returns:
        List of (username, password) tuples
    """
    credentials = []

    # Common credential files in SecLists
    cred_files = [
        "Passwords/Default-Credentials/default-passwords.csv",
        "Passwords/Default-Credentials/router-default-passwords.txt",
        "Passwords/Default-Credentials/default-http-login-hunter.csv",
    ]

    for cred_file in cred_files:
        full_path = Path(seclists_path) / cred_file

        if not full_path.exists():
            continue

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Handle CSV format
                    if ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            # Assume first is username, second is password
                            username = parts[0].strip().strip('"')
                            password = parts[1].strip().strip('"')
                            if username and password:
                                credentials.append((username, password))
                    # Handle colon-separated format
                    elif ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            username = parts[0].strip()
                            password = parts[1].strip()
                            if username:
                                credentials.append((username, password))

        except Exception as e:
            logger.warning(f"Error loading credentials from {cred_file}: {e}")

    # Add common hardcoded defaults if no file found
    if not credentials:
        credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "1234"),
            ("admin", ""),
            ("root", "root"),
            ("root", "admin"),
            ("root", "password"),
            ("user", "user"),
            ("guest", "guest"),
        ]

    # Remove duplicates while preserving order
    seen = set()
    unique_credentials = []
    for cred in credentials:
        if cred not in seen:
            seen.add(cred)
            unique_credentials.append(cred)

    logger.info(f"Loaded {len(unique_credentials)} router credential pairs")
    return unique_credentials
