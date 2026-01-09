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
