#!/usr/bin/env python3
"""
NTREE Autonomous Agent - Claude SDK Version
Fully automated penetration testing using Claude SDK Client (claude-code-sdk)
Similar to Claude Code but fully programmatic
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Claude Code SDK imports
try:
    from claude_code_sdk import ClaudeSDKClient, ClaudeCodeOptions
except ImportError:
    print("⚠️  Warning: claude-code-sdk not installed. Install with: pip install claude-code-sdk")
    ClaudeSDKClient = None
    ClaudeCodeOptions = None

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "ntree-mcp-servers"))

from ntree_mcp.scope import init_engagement, verify_scope
from ntree_mcp.scan import scan_network, passive_recon
from ntree_mcp.enum import enumerate_services, enumerate_web, enumerate_smb, enumerate_domain
from ntree_mcp.vuln import test_vuln, check_creds, search_exploits, analyze_config
from ntree_mcp.post import analyze_trust, extract_secrets, map_privileges
from ntree_mcp.report import score_risk, generate_report

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.expanduser('~/ntree/logs/ntree_agent.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ntree_agent_sdk')


class NTREEAgentSDK:
    """
    Autonomous penetration testing agent using Claude SDK Client.

    This version uses claude-code-sdk for more interactive, Claude Code-like behavior
    with full MCP server integration and tool use capabilities.
    """

    def __init__(self, work_dir: str = None):
        """
        Initialize NTREE autonomous agent with Claude SDK.

        Args:
            work_dir: Working directory for Claude sessions
        """
        if not ClaudeSDKClient:
            raise ImportError("claude-code-sdk not installed. Install with: pip install claude-code-sdk")

        self.work_dir = Path(work_dir or os.getenv("NTREE_WORK_DIR", "~/ntree/sessions")).expanduser()
        self.work_dir.mkdir(exist_ok=True, parents=True)
        self.prompts_dir = Path(__file__).parent / "prompts"
        self.engagement_id: Optional[str] = None
        self.findings: List[Dict] = []

        logger.info("NTREE Agent SDK initialized")

    def _load_system_prompt(self) -> str:
        """Load NTREE system prompt for autonomous mode."""
        prompt_file = self.prompts_dir / "ntree_system_prompt.txt"

        if prompt_file.exists():
            return prompt_file.read_text()

        # Default embedded prompt
        return """You are NTREE (Neural Tactical Red-Team Exploitation Engine), an autonomous penetration testing AI.

Your mission is to conduct thorough, professional penetration tests using the security tools available to you.

## Available MCP Tools

You have access to NTREE MCP servers that provide these capabilities:

**Scope Management:**
- init_engagement - Initialize pentest with scope validation
- verify_scope - Check if target is in authorized scope

**Reconnaissance:**
- scan_network - Network scanning with nmap
- passive_recon - DNS/WHOIS research

**Enumeration:**
- enumerate_services - Deep service enumeration
- enumerate_web - Web application profiling
- enumerate_smb - SMB/Windows enumeration
- enumerate_domain - Active Directory enumeration

**Vulnerability Assessment:**
- test_vuln - CVE validation and testing
- check_creds - Credential testing (rate-limited)
- search_exploits - Exploit database search
- analyze_config - Configuration analysis

**Post-Exploitation:**
- analyze_trust - Lateral movement analysis
- extract_secrets - Credential extraction (requires approval)
- map_privileges - Privilege escalation opportunities

**Reporting:**
- score_risk - Risk scoring and aggregation
- generate_report - Multi-format report generation

## Core Principles

1. **Safety First**: ALWAYS validate targets are in scope before any action
2. **Methodical Approach**: Follow structured pentest phases systematically
3. **Evidence Collection**: Document all findings with proof
4. **Professional Standards**: Follow PTES, OWASP, and NIST guidelines
5. **Approval Required**: Get explicit approval for high-risk actions

## Workflow

1. Initialize engagement with scope file
2. Scan networks to discover hosts
3. Enumerate services on discovered hosts
4. Test for vulnerabilities
5. Analyze configurations
6. Map lateral movement and privilege escalation paths
7. Generate comprehensive reports

Work autonomously, make intelligent decisions, and provide actionable security findings."""

    async def run_autonomous_pentest(self, scope_file: str, roe_file: str = "",
                                     max_iterations: int = 50) -> Dict[str, Any]:
        """
        Run fully autonomous penetration test using Claude SDK.

        Args:
            scope_file: Path to scope file
            roe_file: Path to rules of engagement file
            max_iterations: Maximum conversation turns (safety limit)

        Returns:
            Final engagement summary
        """
        logger.info("=" * 80)
        logger.info("STARTING AUTONOMOUS PENETRATION TEST (SDK MODE)")
        logger.info("=" * 80)
        logger.info(f"Scope file: {scope_file}")
        logger.info(f"ROE file: {roe_file}")
        logger.info(f"Max iterations: {max_iterations}")

        # Create session directory
        session_id = f"pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_dir = self.work_dir / session_id
        session_dir.mkdir(exist_ok=True)

        # Setup MCP servers configuration
        mcp_servers_config = self._create_mcp_config(session_dir)

        # Configure Claude SDK options
        options = ClaudeCodeOptions(
            cwd=str(session_dir),
            allowed_tools=[
                # Standard Claude Code tools
                "Bash", "Glob", "Grep", "LS", "Read", "Write", "Edit",
                # MCP tools for NTREE
                "mcp__ntree-scope__init_engagement",
                "mcp__ntree-scope__verify_scope",
                "mcp__ntree-scan__scan_network",
                "mcp__ntree-scan__passive_recon",
                "mcp__ntree-enum__enumerate_services",
                "mcp__ntree-enum__enumerate_web",
                "mcp__ntree-enum__enumerate_smb",
                "mcp__ntree-enum__enumerate_domain",
                "mcp__ntree-vuln__test_vuln",
                "mcp__ntree-vuln__check_creds",
                "mcp__ntree-vuln__search_exploits",
                "mcp__ntree-vuln__analyze_config",
                "mcp__ntree-post__analyze_trust",
                "mcp__ntree-post__extract_secrets",
                "mcp__ntree-post__map_privileges",
                "mcp__ntree-report__score_risk",
                "mcp__ntree-report__generate_report"
            ],
            permission_mode="acceptEdits",
            mcp_servers=mcp_servers_config
        )

        # Initial prompt
        initial_prompt = self._build_initial_prompt(scope_file, roe_file)

        iteration = 0
        try:
            async with ClaudeSDKClient(options=options) as client:
                logger.info("Claude SDK session started")

                # Send initial prompt and collect response
                logger.info(f"\n{'='*80}")
                logger.info(f"ITERATION {iteration + 1}/{max_iterations}")
                logger.info(f"{'='*80}\n")

                await client.query(initial_prompt)
                response_text = await self._collect_response(client)
                iteration += 1

                # Log initial response
                if response_text:
                    logger.info(f"Initial response length: {len(response_text)} chars")

                # Continue processing responses
                while iteration < max_iterations:
                    if not response_text:
                        logger.info("Empty response received")
                        break

                    # Check if pentest is complete
                    if self._is_pentest_complete(response_text):
                        logger.info("Penetration test marked as complete by Claude")
                        break

                    # Check if Claude is asking for continuation
                    if self._needs_continuation(response_text):
                        logger.info(f"\n{'='*80}")
                        logger.info(f"ITERATION {iteration + 1}/{max_iterations}")
                        logger.info(f"{'='*80}\n")

                        continuation = "Continue with the next phase of testing. What should we do next?"
                        await client.query(continuation)
                        response_text = await self._collect_response(client)
                        iteration += 1
                    else:
                        # Claude stopped naturally
                        logger.info("Claude completed without requesting continuation")
                        break

        except Exception as e:
            logger.error(f"Error during pentest: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e),
                "iterations": iteration,
                "session_dir": str(session_dir)
            }

        # Generate summary
        logger.info("=" * 80)
        logger.info("PENETRATION TEST COMPLETE")
        logger.info("=" * 80)

        summary = self._generate_summary(session_dir, iteration)

        logger.info(f"Summary: {json.dumps(summary, indent=2)}")

        return summary

    def _create_mcp_config(self, session_dir: Path) -> Dict[str, Any]:
        """
        Create MCP servers configuration for Claude SDK.

        Args:
            session_dir: Session directory

        Returns:
            MCP servers configuration dict
        """
        # Get paths to MCP servers
        mcp_servers_dir = Path(__file__).parent.parent / "ntree-mcp-servers"
        python_path = mcp_servers_dir / "venv" / "bin" / "python"

        # Fallback to system python if venv doesn't exist
        if not python_path.exists():
            python_path = "python3"
        else:
            python_path = str(python_path)

        return {
            "ntree-scope": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.scope"],
                "env": {
                    "NTREE_HOME": str(Path.home() / "ntree"),
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-scan": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.scan"],
                "env": {
                    "NTREE_HOME": str(Path.home() / "ntree"),
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-enum": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.enum"],
                "env": {
                    "NTREE_HOME": str(Path.home() / "ntree"),
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-vuln": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.vuln"],
                "env": {
                    "NTREE_HOME": str(Path.home() / "ntree"),
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-post": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.post"],
                "env": {
                    "NTREE_HOME": str(Path.home() / "ntree"),
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-report": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.report"],
                "env": {
                    "NTREE_HOME": str(Path.home() / "ntree"),
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            }
        }

    def _build_initial_prompt(self, scope_file: str, roe_file: str) -> str:
        """
        Build initial penetration test prompt.

        Args:
            scope_file: Path to scope file
            roe_file: Path to ROE file

        Returns:
            Prompt string
        """
        prompt = f"""Begin autonomous penetration test with the following parameters:

Scope File: {scope_file}
ROE File: {roe_file or 'None provided'}

Your mission:
1. Initialize the engagement using the init_engagement MCP tool
2. Read the scope file to understand authorized targets
3. Conduct thorough reconnaissance on in-scope targets
4. Enumerate all discovered services
5. Test for vulnerabilities following safe mode principles
6. Document all findings with evidence
7. Generate comprehensive reports

Important Instructions:
- Use MCP tools (prefixed with mcp__ntree-*) to perform all security operations
- ALWAYS verify targets are in scope before testing using verify_scope
- Follow the penetration testing methodology systematically
- Document your findings as you discover them
- When you complete all testing phases, generate a final report

Start by initializing the engagement with the provided scope file."""

        return prompt

    async def _collect_response(self, client) -> str:
        """
        Collect all response messages from Claude SDK.

        Args:
            client: ClaudeSDKClient instance

        Returns:
            Combined response text
        """
        messages = []
        message_count = 0

        try:
            async for message in client.receive_response():
                message_count += 1

                logger.debug(f"Message {message_count}: type={type(message).__name__}")

                # Extract text content
                if hasattr(message, 'content'):
                    for block in message.content:
                        if hasattr(block, 'text') and block.text:
                            messages.append(block.text)
                            logger.debug(f"  - Text block: {len(block.text)} chars")

                        # Log tool use
                        if hasattr(block, 'type') and block.type == 'tool_use':
                            tool_name = getattr(block, 'name', 'unknown')
                            logger.info(f"  - Tool called: {tool_name}")

                elif hasattr(message, 'text') and message.text:
                    messages.append(message.text)
                    logger.debug(f"  - Text: {len(message.text)} chars")

            logger.info(f"Collected {len(messages)} text blocks from {message_count} messages")

        except Exception as e:
            logger.error(f"Error collecting response: {e}", exc_info=True)
            raise

        return "\n".join(messages)

    def _is_pentest_complete(self, response_text: str) -> bool:
        """
        Check if penetration test is complete based on Claude's response.

        Args:
            response_text: Response text from Claude

        Returns:
            True if pentest is complete
        """
        completion_indicators = [
            "penetration test complete",
            "testing complete",
            "engagement complete",
            "assessment complete",
            "final report generated",
            "all testing phases completed"
        ]

        text_lower = response_text.lower()
        return any(indicator in text_lower for indicator in completion_indicators)

    def _needs_continuation(self, response_text: str) -> bool:
        """
        Check if Claude needs continuation prompt.

        Args:
            response_text: Response text from Claude

        Returns:
            True if continuation is needed
        """
        # If response is too short or ends abruptly, continue
        if len(response_text.strip()) < 100:
            return True

        # If Claude explicitly asks what to do next
        continuation_indicators = [
            "what should i do next",
            "should i proceed",
            "next steps",
            "awaiting instructions"
        ]

        text_lower = response_text.lower()
        return any(indicator in text_lower for indicator in continuation_indicators)

    def _generate_summary(self, session_dir: Path, iterations: int) -> Dict[str, Any]:
        """
        Generate pentest summary from session directory.

        Args:
            session_dir: Session directory path
            iterations: Number of iterations completed

        Returns:
            Summary dict
        """
        summary = {
            "status": "complete",
            "iterations": iterations,
            "session_dir": str(session_dir),
            "completion_time": datetime.now().isoformat()
        }

        # Try to find engagement ID from files
        engagement_files = list(session_dir.glob("engagement_*.json"))
        if engagement_files:
            try:
                with open(engagement_files[0]) as f:
                    engagement_data = json.load(f)
                    summary["engagement_id"] = engagement_data.get("engagement_id")
            except:
                pass

        # Count findings
        findings_dir = session_dir / "findings"
        if findings_dir.exists():
            findings_files = list(findings_dir.glob("*.json"))
            summary["findings_count"] = len(findings_files)

        # Find reports
        reports_dir = session_dir / "reports"
        if reports_dir.exists():
            reports = list(reports_dir.glob("*"))
            summary["reports"] = [r.name for r in reports]

        return summary


async def main():
    """Main entry point for SDK-based autonomous agent."""
    import argparse

    parser = argparse.ArgumentParser(description="NTREE Autonomous Penetration Testing Agent (SDK Version)")
    parser.add_argument("--scope", required=True, help="Path to scope file")
    parser.add_argument("--roe", default="", help="Path to ROE file")
    parser.add_argument("--max-iterations", type=int, default=50, help="Maximum iterations")
    parser.add_argument("--work-dir", help="Working directory for sessions")

    args = parser.parse_args()

    try:
        # Initialize agent
        agent = NTREEAgentSDK(work_dir=args.work_dir)

        # Run autonomous pentest
        summary = await agent.run_autonomous_pentest(
            scope_file=args.scope,
            roe_file=args.roe,
            max_iterations=args.max_iterations
        )

        print("\n" + "=" * 80)
        print("PENETRATION TEST SUMMARY")
        print("=" * 80)
        print(json.dumps(summary, indent=2))
        print("=" * 80)

        return 0

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
