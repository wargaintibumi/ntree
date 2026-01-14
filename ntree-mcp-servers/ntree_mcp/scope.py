"""
NTREE Scope Validation MCP Server
Manages assessment initialization and scope validation
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

# Global scope validator (set during init_assessment)
_scope_validator: Optional[ScopeValidator] = None
_current_assessment_id: Optional[str] = None


class InitAssessmentArgs(BaseModel):
    """Arguments for init_assessment tool."""
    scope_file: str = Field(description="Path to scope file containing authorized targets")
    title: str = Field(default="", description="Assessment title (e.g., 'Internal Network Pentest'). If empty, uses timestamp.")
    roe_file: str = Field(default="", description="Path to rules of assessment file (optional)")


class VerifyScopeArgs(BaseModel):
    """Arguments for verify_scope tool."""
    target: str = Field(description="IP address or domain to verify against scope")


class SaveFindingArgs(BaseModel):
    """Arguments for save_finding tool."""
    title: str = Field(description="Finding title (e.g., 'SMB Signing Disabled')")
    severity: str = Field(description="Severity: critical, high, medium, low, or informational")
    description: str = Field(description="Detailed description of the finding")
    affected_hosts: list = Field(description="List of affected IP addresses or hostnames")
    evidence: str = Field(default="", description="REQUIRED: Proof of exploitation - command output showing successful exploitation, not just scan results. Include actual exploitation attempts, extracted data, or successful command execution.")
    cvss_score: float = Field(default=0.0, description="CVSS score (0.0-10.0)")
    remediation: str = Field(default="", description="Recommended remediation steps")
    references: list = Field(default=[], description="CVE IDs, URLs, or other references")
    exploitable: bool = Field(default=False, description="Whether vulnerability was confirmed exploitable through actual exploitation attempt")


class UpdateStateArgs(BaseModel):
    """Arguments for update_state tool."""
    phase: str = Field(default="", description="Current phase (RECON, ENUM, VULN, EXPLOIT, POST, REPORT)")
    hosts: list = Field(default=[], description="Discovered hosts to add")
    services: list = Field(default=[], description="Discovered services to add")
    credentials: list = Field(default=[], description="Discovered credentials to add (username:service:access_level)")


class CompleteAssessmentArgs(BaseModel):
    """Arguments for complete_assessment tool."""
    pass  # Uses current assessment ID


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="init_assessment",
            description="Initialize penetration test assessment with scope and ROE validation. Must be called before any other actions.",
            inputSchema=InitAssessmentArgs.model_json_schema()
        ),
        Tool(
            name="verify_scope",
            description="Verify if a target (IP or domain) is within the authorized scope. Returns true/false with reason.",
            inputSchema=VerifyScopeArgs.model_json_schema()
        ),
        Tool(
            name="save_finding",
            description="Save a security finding with PROOF OF EXPLOITATION. Evidence must show actual exploitation success (e.g., command output, extracted data, shell access), NOT just scan results. Findings are used to generate reports.",
            inputSchema=SaveFindingArgs.model_json_schema()
        ),
        Tool(
            name="update_state",
            description="Update assessment state with discovered assets (hosts, services, credentials) and current phase.",
            inputSchema=UpdateStateArgs.model_json_schema()
        ),
        Tool(
            name="complete_assessment",
            description="Mark assessment as complete and automatically generate comprehensive HTML report with all findings.",
            inputSchema=CompleteAssessmentArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    try:
        if name == "init_assessment":
            args = InitAssessmentArgs(**arguments)
            result = await init_assessment(args.scope_file, args.title, args.roe_file)
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

        elif name == "complete_assessment":
            result = await complete_assessment()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def init_assessment(scope_file: str, title: str = "", roe_file: str = "") -> dict:
    """
    Initialize assessment with scope and ROE validation.

    Args:
        scope_file: Path to scope file
        title: Assessment title (if empty, uses timestamp)
        roe_file: Path to rules of assessment file (optional)

    Returns:
        {
            "status": "success",
            "assessment_id": "internal_network_pentest" or "assess_20250108_103045",
            "title": "Internal Network Pentest",
            "validated_scope": {
                "included_ranges": ["192.168.1.0/24"],
                "included_ips": ["10.0.0.50"],
                "included_domains": ["example.com"],
                "excluded_ips": ["192.168.1.1"],
                "excluded_ranges": []
            },
            "restrictions": {...},
            "assessment_dir": "/home/pi/ntree/assessments/internal_network_pentest"
        }
    """
    global _scope_validator, _current_assessment_id

    try:
        logger.info(f"Initializing assessment with scope file: {scope_file}")

        # Expand path
        scope_path = Path(scope_file).expanduser().resolve()

        if not scope_path.exists():
            return {
                "status": "error",
                "error": f"Scope file not found: {scope_file}"
            }

        # Initialize scope validator
        _scope_validator = ScopeValidator(scope_path)

        # Generate assessment ID from title or timestamp
        if title:
            # Convert title to safe directory name
            safe_title = title.lower().replace(" ", "_").replace("-", "_")
            # Remove unsafe characters
            import re
            safe_title = re.sub(r'[^a-z0-9_]', '', safe_title)
            _current_assessment_id = safe_title
        else:
            # Use timestamp if no title provided
            _current_assessment_id = f"assess_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            title = _current_assessment_id

        # Create assessment directory structure
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / _current_assessment_id

        assessment_dir.mkdir(parents=True, exist_ok=True)
        (assessment_dir / "scans").mkdir(exist_ok=True)
        (assessment_dir / "findings").mkdir(exist_ok=True)
        (assessment_dir / "evidence").mkdir(exist_ok=True)
        (assessment_dir / "credentials").mkdir(exist_ok=True)
        (assessment_dir / "reports").mkdir(exist_ok=True)

        logger.info(f"Created assessment directory: {assessment_dir}")

        # Parse ROE if provided
        restrictions = {}
        if roe_file:
            roe_path = Path(roe_file).expanduser().resolve()
            if roe_path.exists():
                # Simple ROE parsing - just store the path for now
                # Can be enhanced to parse specific restrictions
                restrictions["roe_file"] = str(roe_path)
                logger.info(f"Loaded ROE file: {roe_path}")

        # Save scope to assessment directory
        scope_copy = assessment_dir / "scope.txt"
        scope_copy.write_text(scope_path.read_text())

        # Create initial state file
        state = {
            "assessment_id": _current_assessment_id,
            "title": title,
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "phase": "INITIALIZATION",
            "scope_file": str(scope_path),
            "roe_file": restrictions.get("roe_file", ""),
            "assessment_dir": str(assessment_dir),
            "discovered_assets": {
                "hosts": [],
                "services": [],
                "credentials": []
            },
            "findings": [],
            "action_history": []
        }

        state_file = assessment_dir / "state.json"
        state_file.write_text(json.dumps(state, indent=2))

        logger.info(f"Assessment {_current_assessment_id} initialized successfully")

        return {
            "status": "success",
            "assessment_id": _current_assessment_id,
            "title": title,
            "validated_scope": {
                "included_ranges": [str(r) for r in _scope_validator.included_ranges],
                "included_ips": [str(ip) for ip in _scope_validator.included_ips],
                "included_domains": list(_scope_validator.included_domains),
                "excluded_ips": [str(ip) for ip in _scope_validator.excluded_ips],
                "excluded_ranges": [str(r) for r in _scope_validator.excluded_ranges],
            },
            "scope_summary": _scope_validator.get_scope_summary(),
            "restrictions": restrictions,
            "assessment_dir": str(assessment_dir),
        }

    except Exception as e:
        logger.error(f"Error initializing assessment: {e}", exc_info=True)
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
            "reason": "Assessment not initialized. Call init_assessment first.",
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
            "assessment_id": _current_assessment_id
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
    Save a security finding to the assessment directory.

    IMPORTANT: Evidence must be proof of exploitation, not just scan results.
    - Good evidence: Command output showing successful exploitation, extracted data, shell access
    - Bad evidence: Just nmap or nuclei scan output showing a vulnerability exists
    - Best practice: Include the actual exploitation command and its successful output

    Args:
        title: Finding title
        severity: Severity level (critical, high, medium, low, informational)
        description: Detailed description of the vulnerability and exploitation
        affected_hosts: List of affected hosts
        evidence: REQUIRED - Proof of successful exploitation (not just scan results)
        cvss_score: CVSS score (0.0-10.0)
        remediation: Recommended remediation steps
        references: CVE IDs, URLs, or other references
        exploitable: True if vulnerability was confirmed through exploitation attempt

    Returns:
        {
            "status": "success",
            "finding_id": "finding_001",
            "finding_path": "/path/to/finding.json"
        }
    """
    global _current_assessment_id

    if not _current_assessment_id:
        return {
            "status": "error",
            "error": "Assessment not initialized. Call init_assessment first."
        }

    # Validate evidence quality
    if not evidence or len(evidence.strip()) < 50:
        logger.warning(f"Finding '{title}' has insufficient evidence. Evidence should include proof of exploitation, not just scan results.")

    # Warn if evidence looks like just scan output
    scan_indicators = ["nmap", "nuclei", "port", "open", "filtered", "scan", "detected"]
    if evidence and not exploitable:
        evidence_lower = evidence.lower()
        if any(indicator in evidence_lower for indicator in scan_indicators):
            if "successfully" not in evidence_lower and "exploited" not in evidence_lower:
                logger.warning(f"Finding '{title}' evidence appears to be scan results, not exploitation proof. Consider demonstrating actual exploitation.")

    try:
        # Get assessment directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / _current_assessment_id
        findings_dir = assessment_dir / "findings"

        # Generate finding ID
        existing_findings = list(findings_dir.glob("finding_*.json"))
        finding_num = len(existing_findings) + 1
        finding_id = f"finding_{finding_num:03d}"

        # Determine exploitation status
        if exploitable and evidence and len(evidence.strip()) >= 50:
            # Has exploit proof
            exploitation_status = "CONFIRMED"
        elif evidence and len(evidence.strip()) >= 20:
            # Has some evidence but not confirmed exploited
            exploitation_status = "NEEDS_VERIFICATION"
        else:
            # No evidence or insufficient evidence
            exploitation_status = "REQUIRES_MANUAL_CHECK"

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
            "exploitation_status": exploitation_status,
            "discovered_at": datetime.now().isoformat(),
            "assessment_id": _current_assessment_id
        }

        # Save finding to file
        finding_path = findings_dir / f"{finding_id}.json"
        finding_path.write_text(json.dumps(finding, indent=2))

        # Update state file with finding reference
        state_file = assessment_dir / "state.json"
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
    Update assessment state with discovered assets.

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
    global _current_assessment_id

    if not _current_assessment_id:
        return {
            "status": "error",
            "error": "Assessment not initialized. Call init_assessment first."
        }

    try:
        # Get assessment directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / _current_assessment_id
        state_file = assessment_dir / "state.json"

        if not state_file.exists():
            return {
                "status": "error",
                "error": f"State file not found for assessment {_current_assessment_id}"
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
            "assessment_id": _current_assessment_id,
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


async def complete_assessment() -> dict:
    """
    Mark assessment as complete and generate HTML reports.

    Returns:
        {
            "status": "success",
            "assessment_id": "...",
            "phase": "COMPLETE",
            "reports": {
                "comprehensive_html": "/path/to/comprehensive_report.html",
                "executive_html": "/path/to/executive_report.html"
            },
            "risk_assessment": {...},
            "total_findings": 15
        }
    """
    global _current_assessment_id

    try:
        if not _current_assessment_id:
            return {
                "status": "error",
                "error": "No active assessment. Call init_assessment first."
            }

        logger.info(f"Completing assessment {_current_assessment_id}")

        # Get assessment directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / _current_assessment_id

        if not assessment_dir.exists():
            return {
                "status": "error",
                "error": f"Assessment directory not found: {assessment_dir}"
            }

        # Load state
        state_file = assessment_dir / "state.json"
        if not state_file.exists():
            return {
                "status": "error",
                "error": "State file not found"
            }

        state = json.loads(state_file.read_text())

        # Update state to COMPLETE
        state["phase"] = "COMPLETE"
        state["updated"] = datetime.now().isoformat()
        state["completed"] = datetime.now().isoformat()
        state_file.write_text(json.dumps(state, indent=2))

        logger.info("Assessment marked as COMPLETE, generating reports...")

        # Import report functions
        from .report import score_risk, generate_report

        # Score risk
        risk_result = await score_risk(_current_assessment_id)

        # Generate reports (both comprehensive and executive)
        reports = {}

        # Generate comprehensive HTML report
        comp_result = await generate_report(
            _current_assessment_id,
            format="comprehensive",
            output_format="html"
        )

        if comp_result.get("status") == "success":
            reports["comprehensive_html"] = comp_result["report_path"]
            logger.info(f"Comprehensive HTML report: {comp_result['report_path']}")

        # Generate executive HTML report
        exec_result = await generate_report(
            _current_assessment_id,
            format="executive",
            output_format="html"
        )

        if exec_result.get("status") == "success":
            reports["executive_html"] = exec_result["report_path"]
            logger.info(f"Executive HTML report: {exec_result['report_path']}")

        # Generate markdown report as backup
        md_result = await generate_report(
            _current_assessment_id,
            format="comprehensive",
            output_format="markdown"
        )

        if md_result.get("status") == "success":
            reports["comprehensive_md"] = md_result["report_path"]

        logger.info(f"Assessment {_current_assessment_id} completed successfully")

        return {
            "status": "success",
            "assessment_id": _current_assessment_id,
            "title": state.get("title", _current_assessment_id),
            "phase": "COMPLETE",
            "reports": reports,
            "risk_assessment": risk_result if risk_result.get("status") == "success" else {},
            "total_findings": len(state.get("findings", [])),
            "summary": f"Assessment completed with {len(state.get('findings', []))} findings. Reports generated in {assessment_dir / 'reports'}"
        }

    except Exception as e:
        logger.error(f"Error completing assessment: {e}", exc_info=True)
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
