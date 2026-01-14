#!/usr/bin/env python3
"""
NTREE Autonomous Agent
Fully automated penetration testing using Claude SDK (Anthropic API)
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from anthropic import Anthropic
import logging

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
logger = logging.getLogger('ntree_agent')


class NTREEAgent:
    """
    Autonomous penetration testing agent powered by Claude SDK.

    This agent orchestrates a complete penetration test using Claude's
    decision-making capabilities combined with security tool execution.
    """

    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        """
        Initialize NTREE autonomous agent.

        Args:
            api_key: Anthropic API key (or set ANTHROPIC_API_KEY env var)
            verbose: Show UserMessage and AssistantMessage contents
        """
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable or api_key parameter required")

        self.client = Anthropic(api_key=self.api_key)
        self.assessment_id: Optional[str] = None
        self.conversation_history: List[Dict] = []
        self.findings: List[Dict] = []
        self.discovered_hosts: List[str] = []
        self.current_phase: str = "init"
        self.phase_order = ["init", "recon", "enum", "vuln", "post", "report"]
        self.error_count: int = 0
        self.verbose: bool = verbose

        # Load system prompt
        self.system_prompt = self._load_system_prompt()

        # Conversation log file (will be set when assessment starts)
        self.conversation_log_path: Optional[Path] = None

        logger.info("NTREE Agent initialized")
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
        return """You are NTREE (Neural Tactical Red-Team Exploitation Engine), an autonomous penetration testing AI.

Your mission is to conduct thorough, professional penetration tests following industry-standard methodology.

## Core Principles

1. **Safety First**: ALWAYS validate targets are in scope before any action
2. **Methodical Approach**: Follow structured pentest phases systematically
3. **Evidence Collection**: Document all findings with proof
4. **Professional Standards**: Follow PTES, OWASP, and NIST guidelines
5. **Approval Required**: Get explicit approval for high-risk actions

## Penetration Test Phases

### Phase 1: Reconnaissance
- Initialize assessment and validate scope
- Passive reconnaissance (DNS, WHOIS)
- Network discovery and host enumeration
- Service identification

### Phase 2: Enumeration
- Deep service enumeration (versions, configs)
- Web application profiling
- SMB/Windows enumeration
- Active Directory enumeration

### Phase 3: Vulnerability Assessment
- CVE validation with safe checks
- Configuration analysis
- Credential testing (rate-limited)
- Exploit availability research

### Phase 4: Exploitation (Requires Approval)
- Safe exploitation attempts
- Privilege escalation mapping
- Lateral movement analysis

### Phase 5: Post-Exploitation (Requires Approval)
- Credential extraction (with approval)
- Trust relationship mapping
- Privilege escalation opportunities

### Phase 6: Reporting
- Risk scoring and aggregation
- Report generation (executive/technical)
- Remediation recommendations

## Decision Making

At each phase, you must:
1. Analyze results from previous actions
2. Decide next logical step based on findings
3. Use appropriate tools for the task
4. Document discoveries
5. Adapt approach based on what you learn

## Tool Usage Rules

- **ALWAYS** verify scope before scanning/testing
- **NEVER** exceed rate limits (3 credential attempts per 5 minutes)
- **NEVER** perform destructive actions without approval
- **ALWAYS** use safe_mode=true for initial vulnerability validation
- **ALWAYS** collect evidence for findings

## Autonomous Operation

You will work independently to:
1. Plan and execute the penetration test
2. Make tactical decisions based on findings
3. Identify and prioritize targets
4. Determine which vulnerabilities to investigate
5. Decide when to move between phases
6. Complete the assessment and generate reports

Work systematically, thoroughly, and professionally. Your goal is to identify security weaknesses
while maintaining strict safety controls and providing actionable remediation guidance."""

    def _get_tool_definitions(self) -> List[Dict]:
        """Get tool definitions for Claude SDK function calling."""
        return [
            {
                "name": "init_assessment",
                "description": "Initialize penetration test assessment with scope validation. MUST be called first.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "scope_file": {
                            "type": "string",
                            "description": "Path to scope file containing authorized targets"
                        },
                        "title": {
                            "type": "string",
                            "description": "Assessment title/ID (e.g., 'internal_network_pentest'). If empty, auto-generates from timestamp."
                        },
                        "roe_file": {
                            "type": "string",
                            "description": "Path to rules of assessment file (optional)"
                        }
                    },
                    "required": ["scope_file"]
                }
            },
            {
                "name": "verify_scope",
                "description": "Verify if a target is within authorized scope. Call before ANY action on a target.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "IP address or domain to verify"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "scan_network",
                "description": "Perform network scanning to discover hosts and services.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "string",
                            "description": "Target IPs or ranges (comma-separated)"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["ping_sweep", "tcp_syn", "full_connect", "udp"],
                            "description": "Type of scan to perform"
                        },
                        "intensity": {
                            "type": "string",
                            "enum": ["stealth", "normal", "aggressive"],
                            "description": "Scan timing intensity"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port specification (e.g., '1-1000', 'top100', 'all')"
                        }
                    },
                    "required": ["targets", "scan_type"]
                }
            },
            {
                "name": "passive_recon",
                "description": "Perform passive reconnaissance (DNS, WHOIS) without touching target.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain name to research"
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "enumerate_services",
                "description": "Deep enumeration of services to identify versions and vulnerabilities.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host IP"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Ports to enumerate (default: discovered ports)"
                        }
                    },
                    "required": ["host"]
                }
            },
            {
                "name": "enumerate_web",
                "description": "Enumerate web application (directories, forms, technologies).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Web application URL"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Enumeration depth (1-5)"
                        }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "enumerate_smb",
                "description": "Enumerate SMB/Windows shares and users.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target Windows/SMB host"
                        }
                    },
                    "required": ["host"]
                }
            },
            {
                "name": "enumerate_domain",
                "description": "Enumerate Active Directory domain information.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain_controller": {
                            "type": "string",
                            "description": "Domain controller IP"
                        },
                        "username": {
                            "type": "string",
                            "description": "Username for authenticated enum (optional)"
                        },
                        "password": {
                            "type": "string",
                            "description": "Password for authenticated enum (optional)"
                        }
                    },
                    "required": ["domain_controller"]
                }
            },
            {
                "name": "test_vuln",
                "description": "Test for specific vulnerability with safe validation.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host"
                        },
                        "service": {
                            "type": "string",
                            "description": "Service name (e.g., 'smb', 'ssh', 'http')"
                        },
                        "vuln_id": {
                            "type": "string",
                            "description": "Vulnerability ID (CVE or common name)"
                        },
                        "safe_mode": {
                            "type": "boolean",
                            "description": "Safe validation only (no exploitation)"
                        },
                        "port": {
                            "type": "integer",
                            "description": "Service port"
                        }
                    },
                    "required": ["host", "service", "vuln_id"]
                }
            },
            {
                "name": "check_creds",
                "description": "Test credentials against service (rate-limited: 3 attempts per 5 min).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host"
                        },
                        "service": {
                            "type": "string",
                            "description": "Service name (ssh, smb, rdp, etc.)"
                        },
                        "username": {
                            "type": "string",
                            "description": "Username to test"
                        },
                        "password": {
                            "type": "string",
                            "description": "Password to test"
                        },
                        "hash_value": {
                            "type": "string",
                            "description": "NTLM hash to test (instead of password)"
                        }
                    },
                    "required": ["host", "service", "username"]
                }
            },
            {
                "name": "search_exploits",
                "description": "Search exploit database for service/version.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "service": {
                            "type": "string",
                            "description": "Service name"
                        },
                        "version": {
                            "type": "string",
                            "description": "Service version"
                        },
                        "platform": {
                            "type": "string",
                            "description": "Platform (windows, linux, etc.)"
                        }
                    },
                    "required": ["service"]
                }
            },
            {
                "name": "analyze_config",
                "description": "Analyze service configuration for security issues.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host"
                        },
                        "service": {
                            "type": "string",
                            "description": "Service to analyze (ssl, smb, ssh)"
                        },
                        "port": {
                            "type": "integer",
                            "description": "Service port"
                        }
                    },
                    "required": ["host", "service"]
                }
            },
            {
                "name": "analyze_trust",
                "description": "Analyze trust relationships for lateral movement.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Compromised host"
                        },
                        "username": {
                            "type": "string",
                            "description": "Compromised username"
                        },
                        "password": {
                            "type": "string",
                            "description": "Password"
                        },
                        "hash_value": {
                            "type": "string",
                            "description": "NTLM hash"
                        },
                        "domain": {
                            "type": "string",
                            "description": "Domain name"
                        }
                    },
                    "required": ["host", "username"]
                }
            },
            {
                "name": "extract_secrets",
                "description": "Extract credentials/secrets (REQUIRES EXPLICIT APPROVAL).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host"
                        },
                        "username": {
                            "type": "string",
                            "description": "Username with access"
                        },
                        "password": {
                            "type": "string",
                            "description": "Password"
                        },
                        "hash_value": {
                            "type": "string",
                            "description": "NTLM hash"
                        },
                        "secret_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Types: hashes, tickets, keys, tokens"
                        },
                        "approved": {
                            "type": "boolean",
                            "description": "MUST be true to execute"
                        }
                    },
                    "required": ["host", "username", "secret_types", "approved"]
                }
            },
            {
                "name": "map_privileges",
                "description": "Map user privileges and escalation opportunities.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host"
                        },
                        "username": {
                            "type": "string",
                            "description": "Username"
                        },
                        "password": {
                            "type": "string",
                            "description": "Password"
                        },
                        "hash_value": {
                            "type": "string",
                            "description": "NTLM hash"
                        }
                    },
                    "required": ["host", "username"]
                }
            },
            {
                "name": "score_risk",
                "description": "Calculate risk scores and aggregate findings.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "assessment_id": {
                            "type": "string",
                            "description": "Assessment ID"
                        }
                    },
                    "required": ["assessment_id"]
                }
            },
            {
                "name": "generate_report",
                "description": "Generate penetration test report.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "assessment_id": {
                            "type": "string",
                            "description": "Assessment ID"
                        },
                        "format": {
                            "type": "string",
                            "enum": ["executive", "technical", "comprehensive"],
                            "description": "Report format"
                        },
                        "output_format": {
                            "type": "string",
                            "enum": ["markdown", "html"],
                            "description": "Output file format"
                        }
                    },
                    "required": ["assessment_id", "format"]
                }
            }
        ]

    async def _execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and return results."""
        logger.info(f"Executing tool: {tool_name} with input: {json.dumps(tool_input, indent=2)}")

        try:
            # Map tool names to functions
            tool_map = {
                "init_assessment": init_assessment,
                "verify_scope": verify_scope,
                "scan_network": scan_network,
                "passive_recon": passive_recon,
                "enumerate_services": enumerate_services,
                "enumerate_web": enumerate_web,
                "enumerate_smb": enumerate_smb,
                "enumerate_domain": enumerate_domain,
                "test_vuln": test_vuln,
                "check_creds": check_creds,
                "search_exploits": search_exploits,
                "analyze_config": analyze_config,
                "analyze_trust": analyze_trust,
                "extract_secrets": extract_secrets,
                "map_privileges": map_privileges,
                "score_risk": score_risk,
                "generate_report": generate_report
            }

            if tool_name not in tool_map:
                return {"status": "error", "error": f"Unknown tool: {tool_name}"}

            # Execute the tool
            result = await tool_map[tool_name](**tool_input)

            # Store assessment ID if this was init_assessment
            if tool_name == "init_assessment" and result.get("status") == "success":
                self.assessment_id = result.get("assessment_id")
                logger.info(f"Assessment initialized: {self.assessment_id}")

            # Track findings for reporting
            if "findings" in result:
                self.findings.extend(result["findings"])

            logger.info(f"Tool {tool_name} completed successfully")
            return result

        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    async def run_autonomous_pentest(self, scope_file: str, roe_file: str = "",
                                     max_iterations: int = 50, assessment_id: str = "") -> Dict[str, Any]:
        """
        Run fully autonomous penetration test.

        Args:
            scope_file: Path to scope file
            roe_file: Path to rules of assessment file
            max_iterations: Maximum conversation turns (safety limit)
            assessment_id: Custom assessment ID (optional)

        Returns:
            Final assessment summary
        """
        logger.info("=" * 80)
        logger.info("STARTING AUTONOMOUS PENETRATION TEST")
        logger.info("=" * 80)
        logger.info(f"Scope file: {scope_file}")
        logger.info(f"ROE file: {roe_file}")
        logger.info(f"Assessment ID: {assessment_id or 'auto-generated'}")
        logger.info(f"Max iterations: {max_iterations}")

        # Initial user message
        initial_message = f"""Begin autonomous penetration test with the following parameters:

Scope File: {scope_file}
ROE File: {roe_file or 'None provided'}
Assessment ID: {assessment_id or 'Will be auto-generated'}

Your mission:
1. Initialize the assessment{f" with ID '{assessment_id}'" if assessment_id else ""}
2. Conduct thorough reconnaissance
3. Enumerate all discovered services
4. Test for vulnerabilities
5. Document all findings with evidence
6. Generate comprehensive reports

Work autonomously through all phases. Make decisions based on findings.
Be thorough, professional, and follow all safety protocols.

Start by initializing the assessment with the provided scope file{f" and use the assessment ID '{assessment_id}'" if assessment_id else ""}."""

        self.conversation_history = [{"role": "user", "content": initial_message}]

        # Initialize conversation log
        self._init_conversation_log()

        # Log initial user message
        self._log_message("user", initial_message)

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            logger.info(f"\n{'='*80}")
            logger.info(f"ITERATION {iteration}/{max_iterations}")
            logger.info(f"{'='*80}\n")

            try:
                # Call Claude API with function calling
                response = self.client.messages.create(
                    model="claude-sonnet-4-5-20250929",
                    max_tokens=4096,
                    system=self.system_prompt,
                    messages=self.conversation_history,
                    tools=self._get_tool_definitions()
                )

                logger.info(f"Claude response - Stop reason: {response.stop_reason}")

                # Log assistant response to file and console
                for block in response.content:
                    if hasattr(block, 'text') and block.text:
                        self._log_message("assistant", block.text)
                    elif hasattr(block, 'type') and block.type == 'tool_use':
                        self._log_message("assistant", "", tool_name=block.name, tool_input=block.input)
                        # Re-init conversation log after init_assessment creates directory
                        if 'init_assessment' in block.name and not self.conversation_log_path:
                            self._init_conversation_log()

                # Process response
                assistant_message = {"role": "assistant", "content": response.content}
                self.conversation_history.append(assistant_message)

                # Handle tool uses
                if response.stop_reason == "tool_use":
                    tool_results = []

                    for block in response.content:
                        if block.type == "tool_use":
                            logger.info(f"Tool requested: {block.name}")

                            # Execute tool
                            result = await self._execute_tool(block.name, block.input)

                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": json.dumps(result, indent=2)
                            })

                    # Add tool results to conversation
                    self.conversation_history.append({
                        "role": "user",
                        "content": tool_results
                    })

                elif response.stop_reason == "end_turn":
                    # Claude decided to stop - check if test is complete
                    final_text = ""
                    for block in response.content:
                        if block.type == "text":
                            final_text += block.text

                    logger.info("Claude ended conversation")
                    logger.info(f"Final message: {final_text}")

                    # Check if penetration test is complete
                    if any(keyword in final_text.lower() for keyword in
                           ["penetration test complete", "testing complete", "assessment complete",
                            "test completed", "assessment complete"]):
                        logger.info("Penetration test marked as complete by Claude")
                        break
                    else:
                        # Encourage continuation if not explicitly complete
                        continuation_msg = "Continue with the next phase of testing. What should we do next?"
                        self.conversation_history.append({
                            "role": "user",
                            "content": continuation_msg
                        })
                        self._log_message("user", continuation_msg)

                else:
                    logger.warning(f"Unexpected stop reason: {response.stop_reason}")
                    break

            except Exception as e:
                logger.error(f"Error in iteration {iteration}: {e}", exc_info=True)
                self.error_count += 1

                # Continue on errors instead of breaking - just add error message to context
                if self.error_count < 5:  # Stop if too many consecutive errors
                    error_msg = f"An error occurred: {str(e)}. Please continue with alternative approaches."
                    self.conversation_history.append({
                        "role": "user",
                        "content": error_msg
                    })
                    self._log_message("user", error_msg)
                else:
                    logger.error("Too many consecutive errors, stopping assessment")
                    break

        # AUTO-TRIGGER: Generate report if not already done
        logger.info("Pentest loop ended. Checking if report needs to be generated...")

        # Try to discover assessment_id if not already known
        if not self.assessment_id:
            self.assessment_id = self._discover_assessment_id()
            if self.assessment_id:
                logger.info(f"Discovered assessment_id: {self.assessment_id}")

        # Auto-trigger report generation
        from ntree_mcp.scope import complete_assessment as complete_fn
        logger.info("Auto-triggering report generation...")
        try:
            # complete_assessment() takes NO parameters - it auto-discovers the assessment
            result = await complete_fn()
            logger.info(f"Report generation result: {result}")
        except Exception as e:
            logger.error(f"Failed to auto-generate report: {e}", exc_info=True)

        # Generate final summary
        logger.info("=" * 80)
        logger.info("PENETRATION TEST COMPLETE")
        logger.info("=" * 80)

        summary = {
            "status": "complete",
            "assessment_id": self.assessment_id,
            "iterations": iteration,
            "findings_count": len(self.findings),
            "conversation_turns": len(self.conversation_history),
            "completion_time": datetime.now().isoformat()
        }

        logger.info(f"Summary: {json.dumps(summary, indent=2)}")

        return summary

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


async def main():
    """Main entry point for autonomous agent."""
    import argparse

    parser = argparse.ArgumentParser(description="NTREE Autonomous Penetration Testing Agent")
    parser.add_argument("--scope", required=True, help="Path to scope file")
    parser.add_argument("--roe", default="", help="Path to ROE file")
    parser.add_argument("--assessment-id", default="", help="Custom assessment ID (optional)")
    parser.add_argument("--max-iterations", type=int, default=50, help="Maximum iterations")
    parser.add_argument("--api-key", help="Anthropic API key (or use ANTHROPIC_API_KEY env var)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show UserMessage and AssistantMessage contents")

    args = parser.parse_args()

    try:
        # Initialize agent
        agent = NTREEAgent(api_key=args.api_key, verbose=args.verbose)

        # Run autonomous pentest
        summary = await agent.run_autonomous_pentest(
            scope_file=args.scope,
            roe_file=args.roe,
            max_iterations=args.max_iterations,
            assessment_id=args.assessment_id
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
