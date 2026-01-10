#!/usr/bin/env python3
"""
NTREE Live Monitor - Real-time penetration test progress viewer

This script monitors NTREE pentest progress without affecting the running test
or consuming any Claude API quota. It watches:
- Agent logs for iteration progress
- Assessment directories for new findings/scans
- State changes and discovered assets
- Automatically switches to new assessments when started

Usage:
    ./ntree_monitor.py                      # Auto-detect and follow new assessments
    ./ntree_monitor.py --assessment eng_20260110_123456
    ./ntree_monitor.py --log-only           # Only show log output
    ./ntree_monitor.py --findings-only      # Only show new findings
    ./ntree_monitor.py --no-follow          # Don't auto-switch to new assessments
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Set, Any
import signal

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    GRAY = '\033[0;90m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'


def colored(text: str, color: str) -> str:
    """Wrap text in color codes."""
    return f"{color}{text}{Colors.NC}"


def print_banner():
    """Print monitor banner."""
    print(colored("""
╔═══════════════════════════════════════════════════════════════════╗
║                  NTREE LIVE MONITOR v1.1                          ║
║              Real-time Penetration Test Viewer                    ║
║           (Auto-follows new assessments by default)               ║
╚═══════════════════════════════════════════════════════════════════╝
""", Colors.CYAN))


def format_timestamp(ts: str) -> str:
    """Format ISO timestamp to readable format."""
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime('%H:%M:%S')
    except:
        return ts[:19] if len(ts) > 19 else ts


class NTREEMonitor:
    """Live monitor for NTREE penetration tests."""

    def __init__(self, ntree_home: str = None, assessment_id: str = None, follow_new: bool = True):
        self.ntree_home = Path(ntree_home or os.getenv("NTREE_HOME", "~/ntree")).expanduser()
        self.logs_dir = self.ntree_home / "logs"
        self.assessments_dir = self.ntree_home / "assessments"

        self.assessment_id = assessment_id
        self.assessment_dir: Optional[Path] = None
        self.assessment_mtime: float = 0  # Track assessment creation time
        self.fixed_assessment = assessment_id is not None  # User specified specific assessment
        self.follow_new = follow_new and not self.fixed_assessment  # Auto-follow new assessments

        # Tracking state
        self.last_log_position = 0
        self.seen_findings: Set[str] = set()
        self.seen_scans: Set[str] = set()
        self.last_state_hash: Optional[str] = None
        self.last_iteration = 0

        # Stats
        self.stats = {
            "iterations": 0,
            "findings": 0,
            "scans": 0,
            "hosts": 0,
            "services": 0,
            "start_time": None
        }

        self.running = True

    def find_latest_assessment(self) -> Optional[Path]:
        """Find the most recent assessment directory."""
        if not self.assessments_dir.exists():
            return None

        assessment_dirs = [
            d for d in self.assessments_dir.iterdir()
            if d.is_dir() and d.name.startswith("eng_")
        ]

        if not assessment_dirs:
            return None

        # Sort by modification time, newest first
        assessment_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return assessment_dirs[0]

    def setup_assessment(self, silent: bool = False) -> bool:
        """Setup assessment directory to monitor."""
        if self.fixed_assessment and self.assessment_id:
            self.assessment_dir = self.assessments_dir / self.assessment_id
            if not self.assessment_dir.exists():
                print(colored(f"[ERROR] Assessment not found: {self.assessment_id}", Colors.RED))
                return False
        else:
            self.assessment_dir = self.find_latest_assessment()
            if not self.assessment_dir:
                if not silent:
                    print(colored("[WARN] No assessment found yet. Waiting...", Colors.YELLOW))
                return False
            self.assessment_id = self.assessment_dir.name

        # Track assessment creation time
        self.assessment_mtime = self.assessment_dir.stat().st_mtime

        if not silent:
            print(colored(f"[*] Monitoring assessment: {self.assessment_id}", Colors.GREEN))
            print(colored(f"[*] Directory: {self.assessment_dir}", Colors.GRAY))
            if self.follow_new:
                print(colored("[*] Auto-follow enabled: will switch to new assessments", Colors.GRAY))
        return True

    def reset_tracking_state(self):
        """Reset all tracking state when switching to new assessment."""
        self.seen_findings.clear()
        self.seen_scans.clear()
        self.last_state_hash = None
        self.last_iteration = 0
        self.stats = {
            "iterations": 0,
            "findings": 0,
            "scans": 0,
            "hosts": 0,
            "services": 0,
            "start_time": datetime.now()
        }

    def check_for_new_assessment(self) -> Optional[Path]:
        """Check if a newer assessment exists."""
        if not self.follow_new:
            return None

        latest = self.find_latest_assessment()
        if not latest:
            return None

        # Check if this is a newer assessment
        latest_mtime = latest.stat().st_mtime
        if latest_mtime > self.assessment_mtime and latest.name != self.assessment_id:
            return latest

        return None

    def switch_to_assessment(self, new_assessment: Path):
        """Switch monitoring to a new assessment."""
        old_id = self.assessment_id

        # Reset state
        self.reset_tracking_state()

        # Setup new assessment
        self.assessment_id = new_assessment.name
        self.assessment_dir = new_assessment
        self.assessment_mtime = new_assessment.stat().st_mtime

        # Announce the switch
        print("\r" + " " * 80 + "\r", end="")  # Clear status line
        print(colored(f"\n{'='*60}", Colors.GREEN))
        print(colored(f"[NEW ASSESSMENT DETECTED]", Colors.GREEN + Colors.BOLD))
        print(colored(f"{'='*60}", Colors.GREEN))
        print(colored(f"  Previous: {old_id}", Colors.GRAY))
        print(colored(f"  Switching to: {self.assessment_id}", Colors.GREEN))
        print(colored(f"  Directory: {self.assessment_dir}", Colors.GRAY))
        print(colored(f"{'='*60}\n", Colors.GREEN))

    def print_status_line(self):
        """Print current status summary line."""
        elapsed = ""
        if self.stats["start_time"]:
            delta = datetime.now() - self.stats["start_time"]
            minutes = int(delta.total_seconds() // 60)
            seconds = int(delta.total_seconds() % 60)
            elapsed = f"{minutes}m{seconds}s"

        status = (
            f"{Colors.GRAY}[{elapsed}]{Colors.NC} "
            f"{Colors.CYAN}Iter:{self.stats['iterations']}{Colors.NC} | "
            f"{Colors.RED}Findings:{self.stats['findings']}{Colors.NC} | "
            f"{Colors.BLUE}Scans:{self.stats['scans']}{Colors.NC} | "
            f"{Colors.GREEN}Hosts:{self.stats['hosts']}{Colors.NC} | "
            f"{Colors.YELLOW}Services:{self.stats['services']}{Colors.NC}"
        )
        print(f"\r{status}", end="", flush=True)

    def watch_log_file(self) -> list:
        """Watch agent log file for new entries."""
        log_file = self.logs_dir / "ntree_agent.log"
        new_lines = []

        if not log_file.exists():
            return new_lines

        try:
            with open(log_file, 'r') as f:
                f.seek(self.last_log_position)
                new_content = f.read()
                self.last_log_position = f.tell()

                if new_content:
                    new_lines = new_content.strip().split('\n')
        except Exception as e:
            pass

        return new_lines

    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line and extract relevant info."""
        if not line.strip():
            return None

        # Extract timestamp and message
        parts = line.split(' - ', 2)
        if len(parts) < 3:
            return None

        timestamp = parts[0]
        level_module = parts[1]
        message = parts[2] if len(parts) > 2 else ""

        # Detect iteration changes
        if "ITERATION" in message:
            try:
                # Extract iteration number
                import re
                match = re.search(r'ITERATION (\d+)/(\d+)', message)
                if match:
                    return {
                        "type": "iteration",
                        "current": int(match.group(1)),
                        "max": int(match.group(2)),
                        "timestamp": timestamp
                    }
            except:
                pass

        # Detect tool calls
        if "Tool called:" in message:
            tool_name = message.split("Tool called:")[-1].strip()
            return {
                "type": "tool_call",
                "tool": tool_name,
                "timestamp": timestamp
            }

        # Detect completion
        if "PENETRATION TEST COMPLETE" in message:
            return {
                "type": "complete",
                "timestamp": timestamp
            }

        # Detect new pentest start
        if "STARTING AUTONOMOUS PENETRATION TEST" in message:
            return {
                "type": "new_pentest",
                "timestamp": timestamp
            }

        # Detect errors
        if "ERROR" in level_module or "error" in message.lower():
            return {
                "type": "error",
                "message": message,
                "timestamp": timestamp
            }

        # Detect collected responses
        if "Collected" in message and "text blocks" in message:
            return {
                "type": "response",
                "message": message,
                "timestamp": timestamp
            }

        return None

    def check_new_findings(self) -> list:
        """Check for new findings in assessment directory."""
        new_findings = []

        if not self.assessment_dir:
            return new_findings

        findings_dir = self.assessment_dir / "findings"
        if not findings_dir.exists():
            return new_findings

        for finding_file in findings_dir.glob("*.json"):
            if finding_file.name not in self.seen_findings:
                self.seen_findings.add(finding_file.name)
                try:
                    with open(finding_file) as f:
                        finding = json.load(f)
                        new_findings.append(finding)
                except:
                    pass

        return new_findings

    def check_new_scans(self) -> list:
        """Check for new scan files."""
        new_scans = []

        if not self.assessment_dir:
            return new_scans

        scans_dir = self.assessment_dir / "scans"
        if not scans_dir.exists():
            return new_scans

        for scan_file in scans_dir.iterdir():
            if scan_file.name not in self.seen_scans:
                self.seen_scans.add(scan_file.name)
                new_scans.append({
                    "filename": scan_file.name,
                    "size": scan_file.stat().st_size,
                    "modified": datetime.fromtimestamp(scan_file.stat().st_mtime)
                })

        return new_scans

    def check_state_changes(self) -> Optional[Dict]:
        """Check for state.json changes."""
        if not self.assessment_dir:
            return None

        state_file = self.assessment_dir / "state.json"
        if not state_file.exists():
            return None

        try:
            with open(state_file) as f:
                content = f.read()
                state = json.load(f) if content else {}

            # Simple hash to detect changes
            current_hash = str(hash(content))
            if current_hash != self.last_state_hash:
                self.last_state_hash = current_hash
                return state
        except:
            pass

        return None

    def format_finding(self, finding: Dict) -> str:
        """Format a finding for display."""
        severity = finding.get("severity", "unknown").upper()
        severity_colors = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.BLUE,
            "INFO": Colors.GRAY
        }
        color = severity_colors.get(severity, Colors.WHITE)

        title = finding.get("title", "Unknown Finding")
        hosts = finding.get("affected_hosts", [])
        cvss = finding.get("cvss_score", "N/A")

        output = f"\n{color}{'='*60}{Colors.NC}\n"
        output += f"{color}[{severity}]{Colors.NC} {Colors.BOLD}{title}{Colors.NC}\n"
        output += f"{color}{'='*60}{Colors.NC}\n"

        if hosts:
            output += f"  {Colors.CYAN}Affected:{Colors.NC} {', '.join(hosts[:5])}"
            if len(hosts) > 5:
                output += f" (+{len(hosts)-5} more)"
            output += "\n"

        if cvss != "N/A":
            output += f"  {Colors.CYAN}CVSS:{Colors.NC} {cvss}\n"

        desc = finding.get("description", "")
        if desc:
            # Truncate long descriptions
            if len(desc) > 200:
                desc = desc[:200] + "..."
            output += f"  {Colors.GRAY}{desc}{Colors.NC}\n"

        return output

    def format_scan(self, scan: Dict) -> str:
        """Format a scan file notification."""
        size_kb = scan["size"] / 1024
        time_str = scan["modified"].strftime("%H:%M:%S")
        return f"  {Colors.BLUE}[SCAN]{Colors.NC} {scan['filename']} ({size_kb:.1f}KB) @ {time_str}"

    async def monitor_loop(self, log_only: bool = False, findings_only: bool = False):
        """Main monitoring loop."""
        print(colored("\n[*] Starting live monitor (Ctrl+C to stop)...\n", Colors.GREEN))
        self.stats["start_time"] = datetime.now()

        # Initial status
        self.print_status_line()

        check_interval = 1.0  # seconds

        while self.running:
            try:
                output_lines = []

                # Check log file
                if not findings_only:
                    new_log_lines = self.watch_log_file()
                    for line in new_log_lines:
                        parsed = self.parse_log_line(line)
                        if parsed:
                            if parsed["type"] == "iteration":
                                self.stats["iterations"] = parsed["current"]
                                if parsed["current"] > self.last_iteration:
                                    self.last_iteration = parsed["current"]
                                    output_lines.append(
                                        f"\n{Colors.CYAN}[ITERATION {parsed['current']}/{parsed['max']}]{Colors.NC}"
                                    )

                            elif parsed["type"] == "tool_call":
                                output_lines.append(
                                    f"  {Colors.MAGENTA}[TOOL]{Colors.NC} {parsed['tool']}"
                                )

                            elif parsed["type"] == "complete":
                                output_lines.append(
                                    f"\n{Colors.GREEN}{'='*60}\n[COMPLETE] Penetration test finished!\n{'='*60}{Colors.NC}"
                                )

                            elif parsed["type"] == "new_pentest":
                                output_lines.append(
                                    f"\n{Colors.CYAN}{'='*60}\n[NEW PENTEST] Starting autonomous penetration test...\n{'='*60}{Colors.NC}"
                                )
                                # Check for new assessment shortly after
                                await asyncio.sleep(2)

                            elif parsed["type"] == "error":
                                output_lines.append(
                                    f"  {Colors.RED}[ERROR]{Colors.NC} {parsed['message'][:100]}"
                                )

                            elif parsed["type"] == "response":
                                output_lines.append(
                                    f"  {Colors.GRAY}[RESPONSE]{Colors.NC} {parsed['message']}"
                                )

                # Check for assessment if not set
                if not self.assessment_dir:
                    if self.setup_assessment(silent=True):
                        output_lines.append(
                            f"\n{Colors.GREEN}[*] Now monitoring: {self.assessment_id}{Colors.NC}"
                        )

                # Check for new assessment (auto-follow)
                if self.follow_new and self.assessment_dir:
                    new_eng = self.check_for_new_assessment()
                    if new_eng:
                        self.switch_to_assessment(new_eng)

                # Check findings
                if not log_only:
                    new_findings = self.check_new_findings()
                    for finding in new_findings:
                        self.stats["findings"] += 1
                        output_lines.append(self.format_finding(finding))

                # Check scans
                if not log_only and not findings_only:
                    new_scans = self.check_new_scans()
                    for scan in new_scans:
                        self.stats["scans"] += 1
                        output_lines.append(self.format_scan(scan))

                # Check state changes
                if not log_only and not findings_only:
                    state = self.check_state_changes()
                    if state:
                        assets = state.get("discovered_assets", {})
                        hosts = assets.get("hosts", [])
                        services = assets.get("services", [])

                        if len(hosts) > self.stats["hosts"]:
                            new_hosts = len(hosts) - self.stats["hosts"]
                            self.stats["hosts"] = len(hosts)
                            output_lines.append(
                                f"  {Colors.GREEN}[HOSTS]{Colors.NC} +{new_hosts} discovered (total: {len(hosts)})"
                            )

                        if len(services) > self.stats["services"]:
                            new_services = len(services) - self.stats["services"]
                            self.stats["services"] = len(services)
                            output_lines.append(
                                f"  {Colors.YELLOW}[SERVICES]{Colors.NC} +{new_services} found (total: {len(services)})"
                            )

                        phase = state.get("phase", "")
                        if phase:
                            output_lines.append(
                                f"  {Colors.CYAN}[PHASE]{Colors.NC} {phase}"
                            )

                # Print output
                if output_lines:
                    print("\r" + " " * 80 + "\r", end="")  # Clear status line
                    for line in output_lines:
                        print(line)
                    self.print_status_line()

                await asyncio.sleep(check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"\n{Colors.RED}[ERROR] {e}{Colors.NC}")
                await asyncio.sleep(check_interval)

    def stop(self):
        """Stop the monitor."""
        self.running = False


def main():
    parser = argparse.ArgumentParser(
        description="NTREE Live Monitor - Real-time penetration test viewer"
    )
    parser.add_argument(
        "--assessment", "-e",
        help="Specific assessment ID to monitor (default: latest)"
    )
    parser.add_argument(
        "--home",
        help="NTREE home directory (default: ~/ntree or $NTREE_HOME)"
    )
    parser.add_argument(
        "--log-only", "-l",
        action="store_true",
        help="Only show log output, no findings/scans"
    )
    parser.add_argument(
        "--findings-only", "-f",
        action="store_true",
        help="Only show new findings"
    )
    parser.add_argument(
        "--no-follow",
        action="store_true",
        help="Don't auto-switch to new assessments"
    )

    args = parser.parse_args()

    print_banner()

    monitor = NTREEMonitor(
        ntree_home=args.home,
        assessment_id=args.assessment,
        follow_new=not args.no_follow
    )

    # Setup signal handler
    def signal_handler(sig, frame):
        print(colored("\n\n[*] Stopping monitor...", Colors.YELLOW))
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Try to setup assessment
    monitor.setup_assessment()

    # Run monitor
    try:
        asyncio.run(monitor.monitor_loop(
            log_only=args.log_only,
            findings_only=args.findings_only
        ))
    except KeyboardInterrupt:
        pass

    # Print final stats
    print(colored("\n\n[*] Final Statistics:", Colors.CYAN))
    print(f"  Iterations: {monitor.stats['iterations']}")
    print(f"  Findings:   {monitor.stats['findings']}")
    print(f"  Scans:      {monitor.stats['scans']}")
    print(f"  Hosts:      {monitor.stats['hosts']}")
    print(f"  Services:   {monitor.stats['services']}")

    if monitor.stats["start_time"]:
        elapsed = datetime.now() - monitor.stats["start_time"]
        print(f"  Duration:   {int(elapsed.total_seconds())}s")


if __name__ == "__main__":
    main()
