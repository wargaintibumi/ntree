"""
NTREE Scope Validation MCP Server
Manages engagement initialization and scope validation
"""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.scope_parser import ScopeValidator
from .utils.logger import get_logger

logger = get_logger(__name__)

# Initialize MCP server
app = Server("ntree-scope")

# Global scope validator (set during init_engagement)
_scope_validator: Optional[ScopeValidator] = None
_current_engagement_id: Optional[str] = None


class InitEngagementArgs(BaseModel):
    """Arguments for init_engagement tool."""
    scope_file: str = Field(description="Path to scope file containing authorized targets")
    roe_file: str = Field(default="", description="Path to rules of engagement file (optional)")


class VerifyScopeArgs(BaseModel):
    """Arguments for verify_scope tool."""
    target: str = Field(description="IP address or domain to verify against scope")


class SaveFindingArgs(BaseModel):
    """Arguments for save_finding tool."""
    title: str = Field(description="Finding title (e.g., 'SMB Signing Disabled')")
    severity: str = Field(description="Severity: critical, high, medium, low, or informational")
    description: str = Field(description="Detailed description of the finding")
    affected_hosts: list = Field(description="List of affected IP addresses or hostnames")
    evidence: str = Field(default="", description="Evidence/proof (command output, screenshots path, etc.)")
    cvss_score: float = Field(default=0.0, description="CVSS score (0.0-10.0)")
    remediation: str = Field(default="", description="Recommended remediation steps")
    references: list = Field(default=[], description="CVE IDs, URLs, or other references")
    exploitable: bool = Field(default=False, description="Whether vulnerability was confirmed exploitable")


class UpdateStateArgs(BaseModel):
    """Arguments for update_state tool."""
    phase: str = Field(default="", description="Current phase (RECON, ENUM, VULN, EXPLOIT, POST, REPORT)")
    hosts: list = Field(default=[], description="Discovered hosts to add")
    services: list = Field(default=[], description="Discovered services to add")
    credentials: list = Field(default=[], description="Discovered credentials to add (username:service:access_level)")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="init_engagement",
            description="Initialize penetration test engagement with scope and ROE validation. Must be called before any other actions.",
            inputSchema=InitEngagementArgs.model_json_schema()
        ),
        Tool(
            name="verify_scope",
            description="Verify if a target (IP or domain) is within the authorized scope. Returns true/false with reason.",
            inputSchema=VerifyScopeArgs.model_json_schema()
        ),
        Tool(
            name="save_finding",
            description="Save a security finding discovered during the pentest. Findings are used to generate reports.",
            inputSchema=SaveFindingArgs.model_json_schema()
        ),
        Tool(
            name="update_state",
            description="Update engagement state with discovered assets (hosts, services, credentials) and current phase.",
            inputSchema=UpdateStateArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    try:
        if name == "init_engagement":
            args = InitEngagementArgs(**arguments)
            result = await init_engagement(args.scope_file, args.roe_file)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "verify_scope":
            args = VerifyScopeArgs(**arguments)
            result = await verify_scope(args.target)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "save_finding":
            args = SaveFindingArgs(**arguments)
            result = await save_finding(
                args.title,
                args.severity,
                args.description,
                args.affected_hosts,
                args.evidence,
                args.cvss_score,
                args.remediation,
                args.references,
                args.exploitable
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "update_state":
            args = UpdateStateArgs(**arguments)
            result = await update_state(
                args.phase,
                args.hosts,
                args.services,
                args.credentials
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def init_engagement(scope_file: str, roe_file: str = "") -> dict:
    """
    Initialize engagement with scope and ROE validation.

    Args:
        scope_file: Path to scope file
        roe_file: Path to rules of engagement file (optional)

    Returns:
        {
            "status": "success",
            "engagement_id": "eng_20250108_103045",
            "validated_scope": {
                "included_ranges": ["192.168.1.0/24"],
                "included_ips": ["10.0.0.50"],
                "included_domains": ["example.com"],
                "excluded_ips": ["192.168.1.1"],
                "excluded_ranges": []
            },
            "restrictions": {...},
            "engagement_dir": "/home/pi/ntree/engagements/eng_20250108_103045"
        }
    """
    global _scope_validator, _current_engagement_id

    try:
        logger.info(f"Initializing engagement with scope file: {scope_file}")

        # Expand path
        scope_path = Path(scope_file).expanduser().resolve()

        if not scope_path.exists():
            return {
                "status": "error",
                "error": f"Scope file not found: {scope_file}"
            }

        # Initialize scope validator
        _scope_validator = ScopeValidator(scope_path)

        # Generate engagement ID
        _current_engagement_id = f"eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Create engagement directory structure
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        engagement_dir = ntree_home / "engagements" / _current_engagement_id

        engagement_dir.mkdir(parents=True, exist_ok=True)
        (engagement_dir / "scans").mkdir(exist_ok=True)
        (engagement_dir / "findings").mkdir(exist_ok=True)
        (engagement_dir / "evidence").mkdir(exist_ok=True)
        (engagement_dir / "credentials").mkdir(exist_ok=True)
        (engagement_dir / "reports").mkdir(exist_ok=True)

        logger.info(f"Created engagement directory: {engagement_dir}")

        # Parse ROE if provided
        restrictions = {}
        if roe_file:
            roe_path = Path(roe_file).expanduser().resolve()
            if roe_path.exists():
                # Simple ROE parsing - just store the path for now
                # Can be enhanced to parse specific restrictions
                restrictions["roe_file"] = str(roe_path)
                logger.info(f"Loaded ROE file: {roe_path}")

        # Save scope to engagement directory
        scope_copy = engagement_dir / "scope.txt"
        scope_copy.write_text(scope_path.read_text())

        # Create initial state file
        state = {
            "engagement_id": _current_engagement_id,
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "phase": "INITIALIZATION",
            "scope_file": str(scope_path),
            "roe_file": restrictions.get("roe_file", ""),
            "engagement_dir": str(engagement_dir),
            "discovered_assets": {
                "hosts": [],
                "services": [],
                "credentials": []
            },
            "findings": [],
            "action_history": []
        }

        state_file = engagement_dir / "state.json"
        state_file.write_text(json.dumps(state, indent=2))

        logger.info(f"Engagement {_current_engagement_id} initialized successfully")

        return {
            "status": "success",
            "engagement_id": _current_engagement_id,
            "validated_scope": {
                "included_ranges": [str(r) for r in _scope_validator.included_ranges],
                "included_ips": [str(ip) for ip in _scope_validator.included_ips],
                "included_domains": list(_scope_validator.included_domains),
                "excluded_ips": [str(ip) for ip in _scope_validator.excluded_ips],
                "excluded_ranges": [str(r) for r in _scope_validator.excluded_ranges],
            },
            "scope_summary": _scope_validator.get_scope_summary(),
            "restrictions": restrictions,
            "engagement_dir": str(engagement_dir),
        }

    except Exception as e:
        logger.error(f"Error initializing engagement: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def verify_scope(target: str) -> dict:
    """
    Verify if target is in scope.

    Args:
        target: IP address or domain to check

    Returns:
        {
            "in_scope": true/false,
            "reason": "explanation",
            "target": "192.168.1.10"
        }
    """
    global _scope_validator

    if not _scope_validator:
        return {
            "in_scope": False,
            "reason": "Engagement not initialized. Call init_engagement first.",
            "target": target
        }

    try:
        in_scope, reason = _scope_validator.is_in_scope(target)

        logger.info(f"Scope check: {target} -> {'IN SCOPE' if in_scope else 'OUT OF SCOPE'}")

        if not in_scope:
            logger.warning(f"SCOPE VIOLATION BLOCKED: {target} - {reason}")

        return {
            "in_scope": in_scope,
            "reason": reason,
            "target": target,
            "engagement_id": _current_engagement_id
        }

    except Exception as e:
        logger.error(f"Error verifying scope for {target}: {e}")
        return {
            "in_scope": False,
            "reason": f"Error during scope validation: {str(e)}",
            "target": target
        }


async def save_finding(
    title: str,
    severity: str,
    description: str,
    affected_hosts: list,
    evidence: str = "",
    cvss_score: float = 0.0,
    remediation: str = "",
    references: list = None,
    exploitable: bool = False
) -> dict:
    """
    Save a security finding to the engagement directory.

    Args:
        title: Finding title
        severity: Severity level
        description: Detailed description
        affected_hosts: List of affected hosts
        evidence: Evidence/proof
        cvss_score: CVSS score
        remediation: Remediation steps
        references: CVE IDs, URLs
        exploitable: Whether confirmed exploitable

    Returns:
        {
            "status": "success",
            "finding_id": "finding_001",
            "finding_path": "/path/to/finding.json"
        }
    """
    global _current_engagement_id

    if not _current_engagement_id:
        return {
            "status": "error",
            "error": "Engagement not initialized. Call init_engagement first."
        }

    try:
        # Get engagement directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        engagement_dir = ntree_home / "engagements" / _current_engagement_id
        findings_dir = engagement_dir / "findings"

        # Generate finding ID
        existing_findings = list(findings_dir.glob("finding_*.json"))
        finding_num = len(existing_findings) + 1
        finding_id = f"finding_{finding_num:03d}"

        # Create finding object
        finding = {
            "finding_id": finding_id,
            "title": title,
            "severity": severity.lower(),
            "description": description,
            "affected_hosts": affected_hosts,
            "evidence": evidence,
            "cvss_score": cvss_score,
            "remediation": remediation,
            "references": references or [],
            "exploitable": exploitable,
            "discovered_at": datetime.now().isoformat(),
            "engagement_id": _current_engagement_id
        }

        # Save finding to file
        finding_path = findings_dir / f"{finding_id}.json"
        finding_path.write_text(json.dumps(finding, indent=2))

        # Update state file with finding reference
        state_file = engagement_dir / "state.json"
        if state_file.exists():
            state = json.loads(state_file.read_text())
            if "findings" not in state:
                state["findings"] = []
            state["findings"].append({
                "id": finding_id,
                "title": title,
                "severity": severity
            })
            state["updated"] = datetime.now().isoformat()
            state_file.write_text(json.dumps(state, indent=2))

        logger.info(f"Saved finding: {finding_id} - {title} ({severity})")

        return {
            "status": "success",
            "finding_id": finding_id,
            "finding_path": str(finding_path),
            "severity": severity,
            "title": title
        }

    except Exception as e:
        logger.error(f"Error saving finding: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


async def update_state(
    phase: str = "",
    hosts: list = None,
    services: list = None,
    credentials: list = None
) -> dict:
    """
    Update engagement state with discovered assets.

    Args:
        phase: Current phase
        hosts: Discovered hosts to add
        services: Discovered services to add
        credentials: Discovered credentials to add

    Returns:
        {
            "status": "success",
            "phase": "ENUM",
            "total_hosts": 12,
            "total_services": 45,
            "total_credentials": 3
        }
    """
    global _current_engagement_id

    if not _current_engagement_id:
        return {
            "status": "error",
            "error": "Engagement not initialized. Call init_engagement first."
        }

    try:
        # Get engagement directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        engagement_dir = ntree_home / "engagements" / _current_engagement_id
        state_file = engagement_dir / "state.json"

        if not state_file.exists():
            return {
                "status": "error",
                "error": f"State file not found for engagement {_current_engagement_id}"
            }

        # Load current state
        state = json.loads(state_file.read_text())

        # Update phase if provided
        if phase:
            state["phase"] = phase.upper()

        # Initialize discovered_assets if not present
        if "discovered_assets" not in state:
            state["discovered_assets"] = {
                "hosts": [],
                "services": [],
                "credentials": []
            }

        # Add hosts (avoid duplicates)
        if hosts:
            existing_hosts = set(state["discovered_assets"]["hosts"])
            for host in hosts:
                if host not in existing_hosts:
                    state["discovered_assets"]["hosts"].append(host)
                    existing_hosts.add(host)

        # Add services (avoid duplicates)
        if services:
            existing_services = set(state["discovered_assets"]["services"])
            for service in services:
                if service not in existing_services:
                    state["discovered_assets"]["services"].append(service)
                    existing_services.add(service)

        # Add credentials (avoid duplicates)
        if credentials:
            existing_creds = set(state["discovered_assets"]["credentials"])
            for cred in credentials:
                if cred not in existing_creds:
                    state["discovered_assets"]["credentials"].append(cred)
                    existing_creds.add(cred)

        # Update timestamp
        state["updated"] = datetime.now().isoformat()

        # Save state
        state_file.write_text(json.dumps(state, indent=2))

        logger.info(f"Updated state: phase={state.get('phase')}, "
                   f"hosts={len(state['discovered_assets']['hosts'])}, "
                   f"services={len(state['discovered_assets']['services'])}")

        return {
            "status": "success",
            "engagement_id": _current_engagement_id,
            "phase": state.get("phase", "UNKNOWN"),
            "total_hosts": len(state["discovered_assets"]["hosts"]),
            "total_services": len(state["discovered_assets"]["services"]),
            "total_credentials": len(state["discovered_assets"]["credentials"]),
            "total_findings": len(state.get("findings", []))
        }

    except Exception as e:
        logger.error(f"Error updating state: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def main():
    """Main entry point for scope server."""
    import sys

    # Handle command-line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-scope v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Scope Server - Test Mode")
            print("This would run tests...")
            return

    # Run MCP server
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
