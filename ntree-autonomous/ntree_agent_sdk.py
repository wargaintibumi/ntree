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
    from claude_code_sdk import ClaudeSDKClient, ClaudeCodeOptions, ResultMessage
except ImportError:
    print("⚠️  Warning: claude-code-sdk not installed. Install with: pip install claude-code-sdk")
    ClaudeSDKClient = None
    ClaudeCodeOptions = None
    ResultMessage = None

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "ntree-mcp-servers"))

from ntree_mcp.scope import init_assessment, verify_scope
from ntree_mcp.scan import scan_network, passive_recon
from ntree_mcp.enum import enumerate_services, enumerate_web, enumerate_smb, enumerate_domain
from ntree_mcp.vuln import test_vuln, check_creds, search_exploits, analyze_config
from ntree_mcp.post import analyze_trust, extract_secrets, map_privileges
from ntree_mcp.report import score_risk, generate_report

# Setup logging - ensure logs directory exists
log_dir = Path.home() / "ntree" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'ntree_agent.log'),
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

    def __init__(self, work_dir: str = None, assessment_id: str = None, verbose: bool = False,
                 prescan_result: Dict = None):
        """
        Initialize NTREE autonomous agent with Claude SDK.

        Args:
            work_dir: Working directory for Claude sessions
            assessment_id: Custom assessment ID (default: auto-generated from timestamp)
            verbose: Show UserMessage and AssistantMessage contents
            prescan_result: Pre-scan results dict from prescan.py
        """
        if not ClaudeSDKClient:
            raise ImportError("claude-code-sdk not installed. Install with: pip install claude-code-sdk")

        self.work_dir = Path(work_dir or os.getenv("NTREE_WORK_DIR", "~/ntree/sessions")).expanduser()
        self.work_dir.mkdir(exist_ok=True, parents=True)
        self.prompts_dir = Path(__file__).parent / "prompts"
        self.assessment_id: Optional[str] = assessment_id
        self.verbose: bool = verbose
        self.prescan_result: Optional[Dict] = prescan_result
        self.findings: List[Dict] = []
        self.discovered_hosts: List[str] = []
        self.current_phase: str = "init"
        self.phase_order = ["init", "recon", "enum", "vuln", "post", "report"]

        # Track tool usage for validation
        self.tools_called: List[str] = []
        self.scans_performed: int = 0
        self.findings_saved: int = 0

        # Conversation log file (will be set when assessment starts)
        self.conversation_log_path: Optional[Path] = None

        logger.info("NTREE Agent SDK initialized")
        if self.assessment_id:
            logger.info(f"Using custom assessment ID: {self.assessment_id}")
        if self.verbose:
            logger.info("Verbose mode enabled: will show message contents")

    def _init_conversation_log(self):
        """Initialize conversation log file in assessment directory."""
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))

        # Try to find the assessment directory
        if self.assessment_id:
            assessment_dir = ntree_home / "assessments" / self.assessment_id
        else:
            # Find the most recent assessment directory
            assessments_dir = ntree_home / "assessments"
            if assessments_dir.exists():
                assessment_dirs = sorted(
                    [d for d in assessments_dir.iterdir() if d.is_dir()],
                    key=lambda d: d.stat().st_mtime,
                    reverse=True
                )
                if assessment_dirs:
                    assessment_dir = assessment_dirs[0]
                    self.assessment_id = assessment_dir.name
                else:
                    assessment_dir = None
            else:
                assessment_dir = None

        if assessment_dir and assessment_dir.exists():
            self.conversation_log_path = assessment_dir / "conversation_log.txt"
            # Write header
            with open(self.conversation_log_path, 'w') as f:
                f.write(f"# NTREE Conversation Log\n")
                f.write(f"# Assessment: {self.assessment_id}\n")
                f.write(f"# Started: {datetime.now().isoformat()}\n")
                f.write(f"{'='*80}\n\n")
            logger.info(f"Conversation log: {self.conversation_log_path}")

    def _log_message(self, role: str, content: str, tool_name: str = None, tool_input: dict = None):
        """Log a message to the conversation log file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Log to console if verbose
        if self.verbose:
            if role == "user":
                logger.info(f"[UserMessage] {content[:500]}{'...' if len(content) > 500 else ''}")
            elif role == "assistant":
                if tool_name:
                    logger.info(f"[AssistantMessage] Tool call: {tool_name}")
                    if tool_input:
                        logger.info(f"  Input: {json.dumps(tool_input, indent=2)[:500]}")
                else:
                    logger.info(f"[AssistantMessage] {content[:500]}{'...' if len(content) > 500 else ''}")

        # Log to file
        if self.conversation_log_path:
            try:
                with open(self.conversation_log_path, 'a') as f:
                    if role == "user":
                        f.write(f"[{timestamp}] USER:\n")
                        f.write(f"{content}\n")
                        f.write(f"{'-'*40}\n\n")
                    elif role == "assistant":
                        if tool_name:
                            f.write(f"[{timestamp}] ASSISTANT (Tool Call):\n")
                            f.write(f"Tool: {tool_name}\n")
                            if tool_input:
                                f.write(f"Input: {json.dumps(tool_input, indent=2)}\n")
                        else:
                            f.write(f"[{timestamp}] ASSISTANT:\n")
                            f.write(f"{content}\n")
                        f.write(f"{'-'*40}\n\n")
            except Exception as e:
                logger.warning(f"Failed to write to conversation log: {e}")

    def _load_system_prompt(self) -> str:
        """Load NTREE system prompt for autonomous mode."""
        prompt_file = self.prompts_dir / "ntree_system_prompt.txt"

        if prompt_file.exists():
            return prompt_file.read_text()

        # Default embedded prompt
        return """You are NTREE (Neural Tactical Red-Team Exploitation Engine), an autonomous penetration testing AI.

Your mission is to conduct thorough, professional penetration tests using the NTREE MCP tools available to you.

## CRITICAL: USE MCP TOOLS, NOT BASH COMMANDS

⚠️  IMPORTANT: You MUST use the NTREE MCP tools for ALL security operations. DO NOT run bash commands directly for security tasks like nmap, nuclei, or other security tools.

The MCP tools are specifically designed to safely execute security operations with proper validation, rate limiting, and safety controls. Running security tools directly via bash bypasses these critical safety mechanisms.

## Available MCP Tools

You have access to NTREE MCP servers that provide these capabilities:

**Scope Management (ntree-scope server):**
- mcp__ntree-scope__init_assessment - Initialize pentest with scope validation (REQUIRED FIRST)
- mcp__ntree-scope__verify_scope - Check if target is in authorized scope
- mcp__ntree-scope__save_finding - Save security findings with proof of exploitation
- mcp__ntree-scope__update_state - Update assessment state with discovered assets
- mcp__ntree-scope__complete_assessment - Generate final reports

**Reconnaissance (ntree-scan server):**
- mcp__ntree-scan__scan_network - Network scanning with nmap (USE THIS, NOT bash nmap)
- mcp__ntree-scan__passive_recon - DNS/WHOIS research
- mcp__ntree-scan__nuclei_scan - Nuclei vulnerability scanner (MANDATORY)

**Enumeration (ntree-enum server):**
- mcp__ntree-enum__enumerate_services - Deep service enumeration
- mcp__ntree-enum__enumerate_web - Web application profiling
- mcp__ntree-enum__enumerate_smb - SMB/Windows enumeration
- mcp__ntree-enum__enumerate_domain - Active Directory enumeration

**Vulnerability Assessment (ntree-vuln server):**
- mcp__ntree-vuln__test_vuln - CVE validation and testing
- mcp__ntree-vuln__check_creds - Credential testing (rate-limited)
- mcp__ntree-vuln__search_exploits - Exploit database search
- mcp__ntree-vuln__analyze_config - Configuration analysis

**Post-Exploitation (ntree-post server):**
- mcp__ntree-post__analyze_trust - Lateral movement analysis
- mcp__ntree-post__extract_secrets - Credential extraction (requires approval)
- mcp__ntree-post__map_privileges - Privilege escalation opportunities

**Reporting (ntree-report server):**
- mcp__ntree-report__score_risk - Risk scoring and aggregation
- mcp__ntree-report__generate_report - Multi-format report generation

## Core Principles

1. **USE MCP TOOLS**: All security operations MUST use MCP tools (prefixed with mcp__ntree-*), NOT bash commands
2. **Safety First**: ALWAYS validate targets are in scope before any action using verify_scope
3. **Methodical Approach**: Follow structured pentest phases systematically
4. **Evidence Collection**: Document all findings with PROOF OF EXPLOITATION (not just scan results)
5. **Professional Standards**: Follow PTES, OWASP, and NIST guidelines

## MANDATORY WORKFLOW

1. Call mcp__ntree-scope__init_assessment with scope file (REQUIRED FIRST STEP)
2. Call mcp__ntree-scan__scan_network to discover hosts (USE MCP TOOL, NOT bash nmap)
3. Call mcp__ntree-scope__update_state with discovered hosts
4. Call mcp__ntree-scan__nuclei_scan for vulnerability scanning (MANDATORY)
5. Use mcp__ntree-enum__* tools to enumerate discovered services
6. Use mcp__ntree-vuln__* tools to test for vulnerabilities
7. Call mcp__ntree-scope__save_finding for each discovered vulnerability
8. Call mcp__ntree-scope__complete_assessment to generate final report (REQUIRED LAST STEP)

## CRITICAL: Tool Result Handling

After calling each MCP tool, you MUST check the "status" field in the response:

- **status: "success"** - Operation completed successfully. Extract and use the data.
- **status: "needs_manual_review"** - Interactive tool detected. Log it and continue with other operations. DO NOT stop the assessment.
- **status: "error"** - Operation failed. Log the error and try alternative approaches.

NEVER stop the entire assessment because one tool fails. Always continue with remaining operations.

## CRITICAL: State Management

You MUST call mcp__ntree-scope__update_state after discovering new assets:
- After scan_network - update with discovered hosts
- After enumerate_services - update with services
- After finding credentials - update with credentials

This ensures findings are properly recorded in the assessment state.

## CRITICAL: Report Generation - MANDATORY FINAL STEP

⚠️  BEFORE announcing completion, you MUST:
1. Call mcp__ntree-scope__complete_assessment to generate HTML reports (THIS IS MANDATORY)
2. ONLY AFTER the reports are generated, say "PENETRATION TEST COMPLETE"

DO NOT say "complete" or "finished" until AFTER calling complete_assessment.
WITHOUT calling complete_assessment, NO REPORTS WILL BE GENERATED and the assessment will be incomplete.

Order matters:
✅ CORRECT: Call complete_assessment → Wait for success → Announce "PENETRATION TEST COMPLETE"
❌ WRONG: Announce complete → Call complete_assessment (reports won't generate)

## Examples of CORRECT Tool Usage

✅ CORRECT: mcp__ntree-scan__scan_network with target "192.168.1.0/24"
❌ WRONG: bash command "nmap -sV 192.168.1.0/24"

✅ CORRECT: mcp__ntree-scan__nuclei_scan with target "https://example.com"
❌ WRONG: bash command "nuclei -u https://example.com"

✅ CORRECT: mcp__ntree-vuln__check_creds with proper parameters
❌ WRONG: bash command "hydra -L users.txt -P pass.txt ssh://target"

CRITICAL: When saving findings with save_finding, evidence must be proof of successful exploitation,
not just scan results showing a vulnerability exists. Include actual command output showing successful
exploitation, extracted data, or successful command execution.

Work autonomously, make intelligent decisions, and provide actionable security findings using ONLY the MCP tools."""

    async def _test_mcp_connectivity(self, mcp_config: Dict[str, Any]) -> bool:
        """
        Test MCP server connectivity before starting pentest.

        Args:
            mcp_config: MCP servers configuration

        Returns:
            True if all servers are accessible
        """
        logger.info("=" * 80)
        logger.info("TESTING MCP SERVER CONNECTIVITY")
        logger.info("=" * 80)

        all_accessible = True
        for server_name, config in mcp_config.items():
            try:
                python_path = config["command"]
                # Test if the Python interpreter exists
                result = await asyncio.create_subprocess_exec(
                    python_path, "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()
                if result.returncode == 0:
                    logger.info(f"✓ {server_name}: Python executable accessible")
                else:
                    logger.error(f"✗ {server_name}: Python executable not found at {python_path}")
                    all_accessible = False
            except Exception as e:
                logger.error(f"✗ {server_name}: Error testing connectivity - {e}")
                all_accessible = False

        logger.info("=" * 80)
        return all_accessible

    async def run_autonomous_pentest(self, scope_file: str, roe_file: str = "",
                                     max_iterations: int = 50) -> Dict[str, Any]:
        """
        Run fully autonomous penetration test using Claude SDK.

        Args:
            scope_file: Path to scope file
            roe_file: Path to rules of assessment file
            max_iterations: Maximum conversation turns (safety limit)

        Returns:
            Final assessment summary
        """
        logger.info("=" * 80)
        logger.info("STARTING AUTONOMOUS PENETRATION TEST (SDK MODE)")
        logger.info("=" * 80)
        logger.info(f"Scope file: {scope_file}")
        logger.info(f"ROE file: {roe_file}")
        logger.info(f"Max iterations: {max_iterations}")
        if self.prescan_result:
            summary = self.prescan_result.get("summary", {})
            logger.info(f"Prescan results: {summary.get('total_hosts', 0)} hosts, {summary.get('total_open_ports', 0)} ports")

        # Create session directory
        session_id = f"pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_dir = self.work_dir / session_id
        session_dir.mkdir(exist_ok=True)

        # Setup MCP servers configuration
        mcp_servers_config = self._create_mcp_config(session_dir)

        # Test MCP connectivity
        mcp_accessible = await self._test_mcp_connectivity(mcp_servers_config)
        if not mcp_accessible:
            logger.warning("Some MCP servers may not be accessible. Proceeding anyway...")

        # Configure Claude SDK options
        options = ClaudeCodeOptions(
            cwd=str(session_dir),
            allowed_tools=[
                # Standard Claude Code tools
                "Bash", "Glob", "Grep", "LS", "Read", "Write", "Edit",
                # MCP tools for NTREE - Scope Management
                "mcp__ntree-scope__init_assessment",
                "mcp__ntree-scope__verify_scope",
                "mcp__ntree-scope__save_finding",
                "mcp__ntree-scope__update_state",
                "mcp__ntree-scope__complete_assessment",
                # MCP tools for NTREE - Scanning
                "mcp__ntree-scan__scan_network",
                "mcp__ntree-scan__passive_recon",
                "mcp__ntree-scan__nuclei_scan",
                # MCP tools for NTREE - Enumeration
                "mcp__ntree-enum__enumerate_services",
                "mcp__ntree-enum__enumerate_web",
                "mcp__ntree-enum__enumerate_smb",
                "mcp__ntree-enum__enumerate_domain",
                # MCP tools for NTREE - Vulnerability Testing
                "mcp__ntree-vuln__test_vuln",
                "mcp__ntree-vuln__check_creds",
                "mcp__ntree-vuln__search_exploits",
                "mcp__ntree-vuln__analyze_config",
                # MCP tools for NTREE - Post-Exploitation
                "mcp__ntree-post__analyze_trust",
                "mcp__ntree-post__extract_secrets",
                "mcp__ntree-post__map_privileges",
                # MCP tools for NTREE - Reporting
                "mcp__ntree-report__score_risk",
                "mcp__ntree-report__generate_report"
            ],
            permission_mode="acceptEdits",
            mcp_servers=mcp_servers_config
        )

        # Load system prompt and combine with initial prompt
        system_prompt = self._load_system_prompt()
        user_prompt = self._build_initial_prompt(scope_file, roe_file)

        # Combine system context with user prompt for clearer instructions
        # This ensures Claude understands it must use MCP tools from the start
        initial_prompt = f"""## SYSTEM CONTEXT (MANDATORY INSTRUCTIONS)

{system_prompt}

---

## USER REQUEST

{user_prompt}

---

## IMMEDIATE ACTION REQUIRED

⚠️  CRITICAL: You MUST start by calling the MCP tool `mcp__ntree-scope__init_assessment` NOW.
DO NOT respond with text explaining what you will do. Instead, IMMEDIATELY call the MCP tool.

Your very first action should be calling:
- Tool: mcp__ntree-scope__init_assessment
- Parameter: scope_file="{scope_file}"
{f'- Parameter: assessment_id="{self.assessment_id}"' if self.assessment_id else ''}

Call this MCP tool NOW. Do not write an explanation first."""

        iteration = 0
        try:
            async with ClaudeSDKClient(options=options) as client:
                logger.info("Claude SDK session started")
                logger.info(f"Allowed tools: {len(options.allowed_tools)}")
                logger.info(f"MCP servers configured: {list(mcp_servers_config.keys())}")

                # Initialize conversation log (after a short delay to let init_assessment create the dir)
                # We'll re-init after first response when assessment_id is known
                self._init_conversation_log()

                # Log available MCP tools to verify they're accessible
                logger.info("Expected MCP tools:")
                for tool in options.allowed_tools:
                    if tool.startswith("mcp__"):
                        logger.info(f"  - {tool}")

                # Send initial prompt and collect response
                logger.info(f"\n{'='*80}")
                logger.info(f"ITERATION {iteration + 1}/{max_iterations}")
                logger.info(f"{'='*80}\n")

                logger.info(f"Sending initial prompt ({len(initial_prompt)} chars)...")
                self._log_message("user", initial_prompt)
                await client.query(initial_prompt)
                logger.info("Initial query sent successfully, waiting for response...")
                # Increased timeouts: 30 min total, 10 min idle for long scans (nmap, nuclei, masscan)
                response_text = await self._collect_response(client, timeout_seconds=1800, idle_timeout=600)
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

                    # CRITICAL: Check if MCP tools are being used
                    # After first iteration, we should have seen at least init_assessment
                    if iteration == 1 and len(self.tools_called) == 0:
                        logger.warning("=" * 80)
                        logger.warning("NO MCP TOOLS CALLED IN FIRST ITERATION")
                        logger.warning("=" * 80)
                        logger.warning("Claude may be trying to use bash commands instead of MCP tools!")
                        logger.warning("Sending explicit reminder to use MCP tools...")
                        continuation = """⚠️  CRITICAL: You have NOT called any MCP tools yet!

You MUST use the NTREE MCP tools (prefixed with mcp__ntree-*) to perform security testing.
DO NOT use bash commands for security operations.

Required immediate actions:
1. Call mcp__ntree-scope__init_assessment with the scope file
2. Call mcp__ntree-scan__scan_network to scan the target network
3. Use the other mcp__ntree-* tools for enumeration and testing

Start now by calling mcp__ntree-scope__init_assessment."""
                    # Check if scanning hasn't started after 3 iterations
                    elif iteration >= 3 and self.scans_performed == 0:
                        logger.warning("=" * 80)
                        logger.warning(f"NO SCANS PERFORMED AFTER {iteration} ITERATIONS")
                        logger.warning("=" * 80)
                        logger.warning(f"MCP tools called: {len(self.tools_called)}")
                        logger.warning(f"Tools: {self.tools_called}")
                        continuation = """⚠️  You have not performed any network scans yet!

You MUST call mcp__ntree-scan__scan_network to discover hosts and services.
This is a MANDATORY step in penetration testing.

Call mcp__ntree-scan__scan_network NOW with the targets from your scope."""
                    else:
                        # Continue by default - pentests are iterative and multi-phase
                        # Only stop if explicitly marked complete or max iterations reached
                        continuation = "Continue with the next phase of testing. What should we do next?"

                    logger.info(f"\n{'='*80}")
                    logger.info(f"ITERATION {iteration + 1}/{max_iterations}")
                    logger.info(f"{'='*80}\n")

                    logger.info(f"Sending continuation prompt...")
                    self._log_message("user", continuation)
                    await client.query(continuation)
                    logger.info("Continuation query sent successfully, waiting for response...")
                    # Increased timeouts for subsequent iterations too
                    response_text = await self._collect_response(client, timeout_seconds=1800, idle_timeout=600)
                    iteration += 1

                # AUTO-TRIGGER: If we reached max iterations without completing, try to generate report
                logger.info("Pentest loop ended. Checking if report needs to be generated...")

                # Try to discover assessment_id if not already known
                if not self.assessment_id:
                    self.assessment_id = self._discover_assessment_id()
                    if self.assessment_id:
                        logger.info(f"Discovered assessment_id: {self.assessment_id}")

                if not self._is_pentest_complete(response_text):
                    logger.warning("Max iterations reached without completion signal. Auto-triggering report generation...")
                    try:
                        # Import complete_assessment locally to avoid circular imports at module level
                        from ntree_mcp.scope import complete_assessment as complete_fn
                        # complete_assessment() takes NO parameters - it auto-discovers the assessment
                        result = await complete_fn()
                        logger.info(f"Auto-generated report: {result}")
                    except Exception as e:
                        logger.error(f"Failed to auto-generate report: {e}")
                else:
                    logger.info("Pentest marked complete by Claude")

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
        # Get paths to MCP servers - use environment variable or detect location
        # This ensures SDK mode uses the same paths as Claude Code MCP config
        ntree_home = os.getenv("NTREE_HOME", str(Path.home() / "ntree"))

        # First try the development directory (where this script is located)
        dev_mcp_dir = Path(__file__).parent.parent / "ntree-mcp-servers"

        # Then try the installed location
        installed_mcp_dir = Path(ntree_home) / "ntree-mcp-servers"

        # Choose which one exists
        if dev_mcp_dir.exists() and (dev_mcp_dir / "venv" / "bin" / "python").exists():
            mcp_servers_dir = dev_mcp_dir
            python_path = str(mcp_servers_dir / "venv" / "bin" / "python")
            logger.info(f"Using development MCP servers: {mcp_servers_dir}")
        elif installed_mcp_dir.exists() and (installed_mcp_dir / "venv" / "bin" / "python").exists():
            mcp_servers_dir = installed_mcp_dir
            python_path = str(mcp_servers_dir / "venv" / "bin" / "python")
            logger.info(f"Using installed MCP servers: {mcp_servers_dir}")
        else:
            # Fallback to system python
            mcp_servers_dir = dev_mcp_dir if dev_mcp_dir.exists() else installed_mcp_dir
            python_path = "python3"
            logger.warning(f"MCP venv not found, using system python. MCP dir: {mcp_servers_dir}")

        return {
            "ntree-scope": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.scope"],
                "env": {
                    "NTREE_HOME": ntree_home,
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-scan": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.scan"],
                "env": {
                    "NTREE_HOME": ntree_home,
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-enum": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.enum"],
                "env": {
                    "NTREE_HOME": ntree_home,
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-vuln": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.vuln"],
                "env": {
                    "NTREE_HOME": ntree_home,
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-post": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.post"],
                "env": {
                    "NTREE_HOME": ntree_home,
                    "PYTHONPATH": str(mcp_servers_dir)
                }
            },
            "ntree-report": {
                "command": python_path,
                "args": ["-m", "ntree_mcp.report"],
                "env": {
                    "NTREE_HOME": ntree_home,
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
        assessment_id_line = f"Assessment ID: {self.assessment_id}" if self.assessment_id else "Assessment ID: (auto-generated)"

        # Build prescan context if available
        prescan_section = ""
        if self.prescan_result and self.prescan_result.get("status") == "success":
            summary = self.prescan_result.get("summary", {})
            masscan_info = self.prescan_result.get("masscan", {})
            nmap_info = self.prescan_result.get("nmap", {})

            prescan_section = f"""

## PRESCAN RESULTS AVAILABLE (USE THIS DATA)

A prescan has already discovered live hosts in the target network:
- Live hosts: {summary.get('total_hosts', 0)}
- Open ports found: {summary.get('total_open_ports', 0)}
- Services identified: {nmap_info.get('services_identified', 0)}
- Live targets file: {self.prescan_result.get('live_targets_file', 'N/A')}

IMPORTANT: The scope file has been updated to contain only live hosts discovered by the prescan.
You can SKIP the initial network scanning phase and proceed directly to service enumeration.

Use mcp__ntree-scope__init_assessment with the scope file (which now contains live targets).
Then proceed directly to enumeration with mcp__ntree-enum__* tools.
"""

        prompt = f"""Begin autonomous penetration test with the following parameters:

Scope File: {scope_file}
ROE File: {roe_file or 'None provided'}
{assessment_id_line}
{prescan_section}
⚠️  CRITICAL REQUIREMENT: You MUST use NTREE MCP tools (prefixed with mcp__ntree-*) for ALL security operations. DO NOT run bash commands for security tools like nmap, nuclei, hydra, etc.

Your mission:
1. Initialize the assessment using mcp__ntree-scope__init_assessment (REQUIRED FIRST)
2. Read the scope file to understand authorized targets
3. Conduct network scanning using mcp__ntree-scan__scan_network (MANDATORY - DO NOT use bash nmap)
4. Run nuclei vulnerability scanner using mcp__ntree-scan__nuclei_scan (MANDATORY - DO NOT use bash nuclei)
5. Enumerate all discovered services using mcp__ntree-enum__* tools
6. Test for vulnerabilities using mcp__ntree-vuln__* tools with actual exploitation attempts
7. Document all findings using mcp__ntree-scope__save_finding with PROOF OF EXPLOITATION (not just scan results)
8. Generate comprehensive reports using mcp__ntree-scope__complete_assessment

MANDATORY REQUIREMENTS:
- ALL security operations MUST use MCP tools (mcp__ntree-*)
- DO NOT run bash commands for nmap, nuclei, hydra, or any security tools
- You MUST call mcp__ntree-scan__scan_network for port scanning (NOT bash nmap)
- You MUST call mcp__ntree-scan__nuclei_scan for vulnerability scanning (NOT bash nuclei)
- Evidence in findings MUST be proof of exploitation, not just scan output
- Include actual exploitation commands and their successful output

Important Instructions:
- Use ONLY MCP tools (prefixed with mcp__ntree-*) to perform all security operations
- ALWAYS verify targets are in scope before testing using mcp__ntree-scope__verify_scope
- Follow the penetration testing methodology systematically
- Document your findings as you discover them using mcp__ntree-scope__save_finding
- ⚠️  MANDATORY FINAL STEP: Call mcp__ntree-scope__complete_assessment to generate HTML reports BEFORE announcing completion

Start by calling mcp__ntree-scope__init_assessment with the provided scope file{f' and assessment_id="{self.assessment_id}"' if self.assessment_id else ''}.
End by calling mcp__ntree-scope__complete_assessment to generate reports."""

        return prompt

    async def _collect_response(self, client, timeout_seconds: int = 300, idle_timeout: int = 45) -> str:
        """
        Collect all response messages from Claude SDK with timeout.

        Args:
            client: ClaudeSDKClient instance
            timeout_seconds: Maximum time to wait for responses (default: 300s)
            idle_timeout: Seconds of inactivity before considering response complete (default: 45s)

        Returns:
            Combined response text
        """
        messages = []
        message_count = 0
        last_message_time = asyncio.get_event_loop().time()

        try:
            logger.info(f"Waiting for Claude SDK response (timeout: {timeout_seconds}s, idle_timeout: {idle_timeout}s)...")

            async def collect_messages():
                nonlocal message_count, last_message_time

                async def message_iterator():
                    async for message in client.receive_response():
                        yield message

                message_iter = message_iterator()

                while True:
                    try:
                        # Wait for next message with idle timeout
                        message = await asyncio.wait_for(
                            message_iter.__anext__(),
                            timeout=idle_timeout
                        )

                        message_count += 1
                        last_message_time = asyncio.get_event_loop().time()

                        logger.info(f"Message {message_count}: type={type(message).__name__}")

                        # Check for ResultMessage (indicates response is complete)
                        if ResultMessage and isinstance(message, ResultMessage):
                            logger.info(f"  - ResultMessage received (response complete)")
                            return

                        # Extract text content
                        if hasattr(message, 'content'):
                            for block in message.content:
                                if hasattr(block, 'text') and block.text:
                                    messages.append(block.text)
                                    # Log to file and console
                                    self._log_message("assistant", block.text)
                                    if not self.verbose:
                                        logger.debug(f"  - Text block: {len(block.text)} chars")

                                # Log tool use and track for validation
                                if hasattr(block, 'type') and block.type == 'tool_use':
                                    tool_name = getattr(block, 'name', 'unknown')
                                    tool_input = getattr(block, 'input', {})
                                    logger.info(f"  - Tool called: {tool_name}")
                                    # Log to file and console
                                    self._log_message("assistant", "", tool_name=tool_name, tool_input=tool_input)

                                    # Track tool usage
                                    self.tools_called.append(tool_name)

                                    # Track specific tool types
                                    if 'scan_network' in tool_name or 'nuclei_scan' in tool_name:
                                        self.scans_performed += 1
                                    if 'save_finding' in tool_name:
                                        self.findings_saved += 1

                                    # Re-init conversation log after init_assessment creates directory
                                    if 'init_assessment' in tool_name and not self.conversation_log_path:
                                        await asyncio.sleep(1)  # Wait for directory creation
                                        self._init_conversation_log()

                        elif hasattr(message, 'text') and message.text:
                            messages.append(message.text)
                            self._log_message("assistant", message.text)
                            if not self.verbose:
                                logger.debug(f"  - Text: {len(message.text)} chars")

                    except asyncio.TimeoutError:
                        # No new messages for idle_timeout seconds
                        logger.info(f"No messages received for {idle_timeout}s, considering response complete")
                        return
                    except StopAsyncIteration:
                        # Iterator exhausted (natural termination)
                        logger.info("Message iterator exhausted (natural termination)")
                        return

            # Apply overall timeout to message collection
            await asyncio.wait_for(collect_messages(), timeout=timeout_seconds)

            logger.info(f"Collected {len(messages)} text blocks from {message_count} messages")

        except asyncio.TimeoutError:
            logger.error(f"Timeout after {timeout_seconds}s waiting for Claude SDK response")
            logger.error(f"Collected {len(messages)} text blocks before timeout")
            if not messages:
                raise TimeoutError(f"No response from Claude SDK after {timeout_seconds}s")
        except Exception as e:
            logger.error(f"Error collecting response: {e}", exc_info=True)
            raise

        return "\n".join(messages)

    def _is_pentest_complete(self, response_text: str) -> bool:
        """
        Check if penetration test is complete based on Claude's response.

        CRITICAL: Validates that actual testing was performed before allowing completion.
        This prevents premature completion without any real work being done.

        Args:
            response_text: Response text from Claude

        Returns:
            True if pentest is complete AND minimum validation criteria met
        """
        completion_indicators = [
            "penetration test complete",
            "testing complete",
            "assessment complete",
            "assessment complete",
            "final report generated",
            "all testing phases completed"
        ]

        text_lower = response_text.lower()
        completion_mentioned = any(indicator in text_lower for indicator in completion_indicators)

        # If completion is not mentioned, definitely not complete
        if not completion_mentioned:
            return False

        # VALIDATION: Check if minimum testing requirements were met
        min_scans_required = 1  # At least one network scan must be performed
        min_mcp_tools_required = 2  # At least 2 MCP tools must be called (init + scan)

        validation_passed = (
            self.scans_performed >= min_scans_required and
            len(self.tools_called) >= min_mcp_tools_required
        )

        if completion_mentioned and not validation_passed:
            logger.warning("=" * 80)
            logger.warning("COMPLETION VALIDATION FAILED - CONTINUING PENTEST")
            logger.warning("=" * 80)
            logger.warning(f"Scans performed: {self.scans_performed} (minimum: {min_scans_required})")
            logger.warning(f"MCP tools called: {len(self.tools_called)} (minimum: {min_mcp_tools_required})")
            logger.warning(f"Tools used: {self.tools_called}")
            logger.warning("Claude attempted to complete without performing required testing.")
            logger.warning("Forcing continuation to ensure actual penetration testing occurs.")
            logger.warning("=" * 80)
            return False

        # Validation passed - pentest is legitimately complete
        if validation_passed:
            logger.info("=" * 80)
            logger.info("COMPLETION VALIDATION PASSED")
            logger.info("=" * 80)
            logger.info(f"✓ Scans performed: {self.scans_performed}")
            logger.info(f"✓ Findings saved: {self.findings_saved}")
            logger.info(f"✓ Total MCP tools called: {len(self.tools_called)}")
            logger.info(f"✓ Tools used: {', '.join(set(self.tools_called))}")
            logger.info("=" * 80)
            return True

        return False

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

    def _discover_assessment_id(self) -> Optional[str]:
        """
        Discover assessment_id from the filesystem by finding the most recent assessment directory.

        Returns:
            assessment_id if found, None otherwise
        """
        try:
            ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
            assessments_dir = ntree_home / "assessments"

            if not assessments_dir.exists():
                logger.warning(f"Assessments directory not found: {assessments_dir}")
                return None

            # Find all assessment directories (sorted by modification time, newest first)
            assessment_dirs = sorted(
                [d for d in assessments_dir.iterdir() if d.is_dir()],
                key=lambda d: d.stat().st_mtime,
                reverse=True
            )

            if not assessment_dirs:
                logger.warning("No assessment directories found")
                return None

            # Get the most recent assessment directory name
            recent_assessment = assessment_dirs[0]
            assessment_id = recent_assessment.name
            logger.info(f"Discovered assessment directory: {assessment_id}")

            # Validate it has a state.json file
            state_file = recent_assessment / "state.json"
            if state_file.exists():
                return assessment_id
            else:
                logger.warning(f"Assessment directory {assessment_id} has no state.json")
                return None

        except Exception as e:
            logger.error(f"Error discovering assessment_id: {e}", exc_info=True)
            return None

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

        # Try to find assessment ID from files
        assessment_files = list(session_dir.glob("assessment_*.json"))
        if assessment_files:
            try:
                with open(assessment_files[0]) as f:
                    assessment_data = json.load(f)
                    summary["assessment_id"] = assessment_data.get("assessment_id")
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
    parser.add_argument("--assessment-id", help="Custom assessment ID (default: auto-generated from timestamp)")
    parser.add_argument("--max-iterations", type=int, default=50, help="Maximum iterations")
    parser.add_argument("--work-dir", help="Working directory for sessions")
    parser.add_argument("--prescan-result", help="Path to prescan_summary.json from prior prescan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show UserMessage and AssistantMessage contents")

    args = parser.parse_args()

    try:
        # Load prescan result if provided
        prescan_result = None
        if args.prescan_result:
            prescan_path = Path(args.prescan_result)
            if prescan_path.exists():
                with open(prescan_path) as f:
                    prescan_result = json.load(f)
                logger.info(f"Loaded prescan result from {prescan_path}")
            else:
                logger.warning(f"Prescan result file not found: {prescan_path}")

        # Initialize agent
        agent = NTREEAgentSDK(
            work_dir=args.work_dir,
            assessment_id=args.assessment_id,
            verbose=args.verbose,
            prescan_result=prescan_result
        )

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
