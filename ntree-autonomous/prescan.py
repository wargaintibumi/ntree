#!/usr/bin/env python3
"""
NTREE Prescan - Fast Network Discovery
Two-stage scanning: masscan for speed, nmap for accuracy.

Usage:
    # Standalone
    python prescan.py --scope ~/ntree/templates/scope_example.txt

    # As module
    from prescan import Prescan, PrescanConfig
    config = PrescanConfig(scope_file=Path("scope.txt"))
    scanner = Prescan(config)
    results = await scanner.run()
"""

import asyncio
import argparse
import json
import os
import sys
import shlex
import uuid
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "ntree-mcp-servers"))

from ntree_mcp.utils.scope_parser import ScopeValidator
from ntree_mcp.utils.nmap_parser import parse_nmap_xml

# Setup logging
import logging
log_dir = Path.home() / "ntree" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'prescan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('prescan')


# ============================================================================
# Configuration Constants
# ============================================================================

# Default port lists (balances speed vs coverage)
DEFAULT_PORTS_QUICK = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
DEFAULT_PORTS_STANDARD = "1-1024,1433,1521,2049,3306,3389,5432,5900,5985,6379,8000,8080,8443,9000,9200,27017"
DEFAULT_PORTS_FULL = "1-65535"

# Safe masscan rate defaults
RATE_STEALTH = 100      # Very slow, minimal network impact
RATE_NORMAL = 1000      # Balanced (default)
RATE_AGGRESSIVE = 10000 # Fast, may trigger IDS

# Timeouts
MASSCAN_TIMEOUT = 1800  # 30 minutes max
NMAP_TIMEOUT_PER_HOST = 300  # 5 minutes per host
NMAP_MAX_PARALLEL = 5   # Concurrent nmap scans


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class PrescanConfig:
    """Configuration for prescan operation."""
    scope_file: Path
    output_dir: Optional[Path] = None
    port_mode: str = "standard"  # quick, standard, full
    custom_ports: Optional[str] = None
    rate: int = RATE_NORMAL
    skip_nmap: bool = False
    nmap_scripts: bool = False  # Disable vuln scripts by default for speed
    verbose: bool = False


@dataclass
class ServiceInfo:
    """Service information for a port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    product: str = ""
    version: str = ""


@dataclass
class HostResult:
    """Results for a single host."""
    ip: str
    hostname: str = ""
    status: str = "up"
    os_guess: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)


@dataclass
class PrescanResult:
    """Complete prescan results."""
    status: str = "pending"
    scope_file: str = ""
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    # Stage 1: Masscan
    masscan_duration: float = 0.0
    masscan_hosts_found: int = 0
    masscan_ports_found: int = 0

    # Stage 2: Nmap
    nmap_duration: float = 0.0
    nmap_hosts_analyzed: int = 0
    nmap_services_identified: int = 0

    # Results
    hosts: List[HostResult] = field(default_factory=list)
    output_dir: str = ""
    live_targets_file: str = ""

    # Errors
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# Progress Callback
# ============================================================================

class ProgressReporter:
    """Reports progress during long-running scans."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stage = ""
        self.total = 0
        self.current = 0
        self.start_time = time.time()

    def set_stage(self, stage: str, total: int = 0):
        """Set current stage and total items."""
        self.stage = stage
        self.total = total
        self.current = 0
        self.start_time = time.time()
        print(f"\n{'='*60}")
        print(f"Stage: {stage}")
        if total > 0:
            print(f"Processing {total} items...")
        print(f"{'='*60}\n")

    def update(self, current: int = None, message: str = ""):
        """Update progress."""
        if current is not None:
            self.current = current
        else:
            self.current += 1

        elapsed = time.time() - self.start_time

        if self.total > 0:
            pct = (self.current / self.total) * 100
            eta = (elapsed / self.current) * (self.total - self.current) if self.current > 0 else 0
            print(f"[{self.current}/{self.total}] ({pct:.1f}%) ETA: {eta:.0f}s - {message}")
        elif self.verbose:
            print(f"[{self.current}] {elapsed:.1f}s - {message}")

    def complete(self, message: str = ""):
        """Mark stage complete."""
        elapsed = time.time() - self.start_time
        print(f"\n{self.stage} complete in {elapsed:.1f}s")
        if message:
            print(message)


# ============================================================================
# Main Prescan Class
# ============================================================================

class Prescan:
    """
    Two-stage network prescan for NTREE.

    Stage 1: Masscan for fast port discovery
    Stage 2: Nmap for service identification on discovered ports
    """

    def __init__(self, config: PrescanConfig):
        """
        Initialize prescan.

        Args:
            config: PrescanConfig with scan parameters
        """
        self.config = config
        self.scope = ScopeValidator(str(config.scope_file))
        self.progress = ProgressReporter(config.verbose)
        self.result = PrescanResult(
            status="pending",
            scope_file=str(config.scope_file),
            start_time=datetime.now().isoformat()
        )

        # Setup output directory
        if config.output_dir:
            self.output_dir = Path(config.output_dir)
        else:
            ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
            self.output_dir = ntree_home / "prescans" / datetime.now().strftime("%Y%m%d_%H%M%S")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.result.output_dir = str(self.output_dir)
        logger.info(f"Prescan output directory: {self.output_dir}")

    def _get_port_list(self) -> str:
        """Get port list based on configuration."""
        if self.config.custom_ports:
            return self.config.custom_ports

        port_map = {
            "quick": DEFAULT_PORTS_QUICK,
            "standard": DEFAULT_PORTS_STANDARD,
            "full": DEFAULT_PORTS_FULL
        }
        return port_map.get(self.config.port_mode, DEFAULT_PORTS_STANDARD)

    async def run(self) -> PrescanResult:
        """
        Execute prescan.

        Returns:
            PrescanResult with discovered hosts and services
        """
        start_time = time.time()

        try:
            # Get targets from scope
            targets = self._get_targets()
            if not targets:
                self.result.status = "error"
                self.result.errors.append("No valid targets in scope file")
                return self.result

            logger.info(f"Prescan targets: {targets}")

            # Stage 1: Masscan
            host_ports = await self._run_masscan(targets)

            if not host_ports:
                logger.info("No live hosts discovered by masscan")
                self.result.status = "success"
                self.result.warnings.append("No live hosts or open ports found")
                self._finalize_result(start_time)
                return self.result

            # Stage 2: Nmap (if not skipped)
            if not self.config.skip_nmap:
                await self._run_nmap(host_ports)
            else:
                # Just populate results from masscan
                for ip, ports in host_ports.items():
                    services = [ServiceInfo(port=p) for p in ports]
                    host = HostResult(ip=ip, open_ports=ports, services=services, status="up")
                    self.result.hosts.append(host)

            # Generate live targets file
            self._write_live_targets()

            # Write JSON results
            self._write_json_results()

            self.result.status = "success"

        except Exception as e:
            logger.error(f"Prescan failed: {e}", exc_info=True)
            self.result.status = "error"
            self.result.errors.append(str(e))

        self._finalize_result(start_time)
        return self.result

    def _get_targets(self) -> str:
        """Get comma-separated target list from scope."""
        targets = []

        # Add CIDR ranges
        for network in self.scope.included_ranges:
            targets.append(str(network))

        # Add individual IPs
        for ip in self.scope.included_ips:
            targets.append(str(ip))

        # Note: Domains not supported by masscan (would need DNS resolution)
        if self.scope.included_domains:
            self.result.warnings.append(
                f"Skipping {len(self.scope.included_domains)} domains (masscan requires IPs)"
            )

        return ",".join(targets)

    async def _run_masscan(self, targets: str) -> Dict[str, List[int]]:
        """
        Run masscan for fast port discovery.

        Args:
            targets: Comma-separated target IPs/CIDRs

        Returns:
            Dict mapping IP to list of open ports
        """
        self.progress.set_stage("Masscan Port Discovery")

        ports = self._get_port_list()
        rate = self.config.rate

        # Create unique output file
        output_file = self.output_dir / f"masscan_{uuid.uuid4()}.json"

        # Build command - masscan requires sudo for raw sockets
        cmd = f"sudo masscan {shlex.quote(targets)} -p{shlex.quote(ports)} --rate {rate} -oJ {shlex.quote(str(output_file))}"

        logger.info(f"Running: {cmd}")
        self.progress.update(message=f"Scanning ports (rate={rate} pps)...")

        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=MASSCAN_TIMEOUT
            )

            duration = time.time() - start_time
            self.result.masscan_duration = duration

            stderr_text = stderr.decode('utf-8', errors='replace')

            if process.returncode != 0:
                # Check for specific errors
                if "permission denied" in stderr_text.lower() or "must be root" in stderr_text.lower():
                    self.result.errors.append("Masscan requires root privileges. Run with sudo.")
                elif "network unreachable" in stderr_text.lower():
                    self.result.errors.append("Network unreachable. Check network connectivity.")
                else:
                    self.result.errors.append(f"Masscan error: {stderr_text[:200]}")
                logger.error(f"Masscan failed: {stderr_text}")
                return {}

            # Parse results
            host_ports = self._parse_masscan_output(output_file)

            self.result.masscan_hosts_found = len(host_ports)
            self.result.masscan_ports_found = sum(len(p) for p in host_ports.values())

            self.progress.complete(
                f"Found {len(host_ports)} hosts with {self.result.masscan_ports_found} open ports"
            )

            return host_ports

        except asyncio.TimeoutError:
            logger.error(f"Masscan timed out after {MASSCAN_TIMEOUT}s")
            self.result.errors.append(f"Masscan timeout ({MASSCAN_TIMEOUT}s)")
            return {}

        finally:
            # Cleanup temp file
            try:
                if output_file.exists():
                    # Keep a copy for debugging
                    pass
            except Exception:
                pass

    def _parse_masscan_output(self, output_file: Path) -> Dict[str, List[int]]:
        """Parse masscan JSON output."""
        host_ports: Dict[str, List[int]] = {}

        if not output_file.exists():
            return host_ports

        try:
            content = output_file.read_text()

            # Masscan JSON is newline-delimited with surrounding brackets
            for line in content.strip().split('\n'):
                line = line.strip().rstrip(',')
                if not line or line in ['[', ']']:
                    continue

                try:
                    entry = json.loads(line)
                    ip = entry.get('ip')
                    port_info = entry.get('ports', [])

                    if ip and port_info:
                        for p in port_info:
                            port = p.get('port')
                            if port:
                                if ip not in host_ports:
                                    host_ports[ip] = []
                                if port not in host_ports[ip]:
                                    host_ports[ip].append(port)
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            logger.error(f"Error parsing masscan output: {e}")

        return host_ports

    async def _run_nmap(self, host_ports: Dict[str, List[int]]):
        """
        Run nmap for service identification on discovered ports.

        Args:
            host_ports: Dict mapping IP to list of open ports
        """
        self.progress.set_stage("Nmap Service Identification", len(host_ports))

        start_time = time.time()

        # Semaphore for parallel execution
        semaphore = asyncio.Semaphore(NMAP_MAX_PARALLEL)

        async def scan_host(ip: str, ports: List[int]) -> HostResult:
            async with semaphore:
                return await self._nmap_single_host(ip, ports)

        # Run scans in parallel
        tasks = [scan_host(ip, ports) for ip, ports in host_ports.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Nmap task failed: {result}")
                self.result.warnings.append(f"Nmap error: {str(result)[:100]}")
            elif isinstance(result, HostResult):
                self.result.hosts.append(result)
                self.result.nmap_services_identified += len(result.services)

        self.result.nmap_duration = time.time() - start_time
        self.result.nmap_hosts_analyzed = len(self.result.hosts)

        self.progress.complete(
            f"Analyzed {self.result.nmap_hosts_analyzed} hosts, "
            f"identified {self.result.nmap_services_identified} services"
        )

    async def _nmap_single_host(self, ip: str, ports: List[int]) -> HostResult:
        """Run nmap on a single host."""
        result = HostResult(ip=ip, open_ports=ports, status="up")

        # Build port string
        port_str = ",".join(str(p) for p in sorted(ports))

        # Create temp file for XML output
        xml_file = self.output_dir / f"nmap_{ip.replace('.', '_')}_{uuid.uuid4()}.xml"

        # Build nmap command - service version detection and OS detection
        nmap_flags = "-sV -O --osscan-limit"
        if self.config.nmap_scripts:
            nmap_flags += " --script=default,vuln"

        cmd = f"sudo nmap {nmap_flags} -p {shlex.quote(port_str)} -oX {shlex.quote(str(xml_file))} {shlex.quote(ip)}"

        self.progress.update(message=f"Scanning {ip} ({len(ports)} ports)")

        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await asyncio.wait_for(
                process.communicate(),
                timeout=NMAP_TIMEOUT_PER_HOST
            )

            if xml_file.exists():
                # Parse nmap XML
                scan_data = parse_nmap_xml(str(xml_file))

                if scan_data.get('hosts'):
                    host_data = scan_data['hosts'][0]
                    result.hostname = host_data.get('hostname', '')
                    result.os_guess = host_data.get('os', '')

                    for svc in host_data.get('services', []):
                        port = svc.get('port')
                        if port:
                            service_info = ServiceInfo(
                                port=port,
                                protocol=svc.get('protocol', 'tcp'),
                                state=svc.get('state', 'open'),
                                service=svc.get('service', 'unknown'),
                                product=svc.get('product', ''),
                                version=svc.get('version', '')
                            )
                            result.services.append(service_info)

        except asyncio.TimeoutError:
            logger.warning(f"Nmap timeout for {ip}")
            result.status = "timeout"
            # Still include the host with masscan-discovered ports
            result.services = [ServiceInfo(port=p) for p in ports]

        except Exception as e:
            logger.error(f"Nmap error for {ip}: {e}")
            result.status = "error"
            result.services = [ServiceInfo(port=p) for p in ports]

        finally:
            # Cleanup XML file (keep for debugging if needed)
            try:
                if xml_file.exists():
                    xml_file.unlink()
            except Exception:
                pass

        return result

    def _write_live_targets(self):
        """Write discovered hosts to a live targets file."""
        live_targets_file = self.output_dir / "live_targets.txt"

        with open(live_targets_file, 'w') as f:
            f.write(f"# NTREE Prescan Results\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Source scope: {self.config.scope_file}\n")
            f.write(f"# Total hosts: {len(self.result.hosts)}\n")
            f.write(f"#\n")

            for host in self.result.hosts:
                # Write IP with comment showing ports/services
                ports_str = ",".join(str(p) for p in sorted(host.open_ports))
                services = [f"{s.port}:{s.service}" for s in host.services[:5]]

                f.write(f"{host.ip}  # ports: {ports_str}")
                if services:
                    f.write(f" | services: {', '.join(services)}")
                f.write("\n")

        self.result.live_targets_file = str(live_targets_file)
        logger.info(f"Live targets written to: {live_targets_file}")

    def _write_json_results(self):
        """Write full results to JSON file."""
        json_file = self.output_dir / "prescan_results.json"

        # Convert dataclasses to dicts
        def to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: to_dict(v) for k, v in asdict(obj).items()}
            elif isinstance(obj, list):
                return [to_dict(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: to_dict(v) for k, v in obj.items()}
            else:
                return obj

        result_dict = to_dict(self.result)

        with open(json_file, 'w') as f:
            json.dump(result_dict, f, indent=2)

        logger.info(f"Full results written to: {json_file}")

    def _finalize_result(self, start_time: float):
        """Finalize result with timing and summary."""
        self.result.end_time = datetime.now().isoformat()
        self.result.duration_seconds = time.time() - start_time

        # Write summary JSON
        summary_file = self.output_dir / "prescan_summary.json"
        summary = {
            "status": self.result.status,
            "scope_file": self.result.scope_file,
            "start_time": self.result.start_time,
            "end_time": self.result.end_time,
            "duration_seconds": self.result.duration_seconds,
            "output_dir": self.result.output_dir,
            "masscan": {
                "duration": self.result.masscan_duration,
                "hosts_found": self.result.masscan_hosts_found,
                "ports_found": self.result.masscan_ports_found
            },
            "nmap": {
                "duration": self.result.nmap_duration,
                "hosts_analyzed": self.result.nmap_hosts_analyzed,
                "services_identified": self.result.nmap_services_identified
            },
            "summary": {
                "total_hosts": len(self.result.hosts),
                "hosts_up": len([h for h in self.result.hosts if h.status == "up"]),
                "total_open_ports": self.result.masscan_ports_found
            },
            "live_targets_file": self.result.live_targets_file,
            "errors": self.result.errors,
            "warnings": self.result.warnings
        }

        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Prescan summary: {summary_file}")


# ============================================================================
# CLI Entry Point
# ============================================================================

async def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="NTREE Prescan - Fast Network Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan with default ports
  python prescan.py --scope ~/ntree/templates/scope_example.txt

  # Full port scan (slower but thorough)
  python prescan.py --scope scope.txt --ports full

  # Custom ports with aggressive rate
  python prescan.py --scope scope.txt --custom-ports "22,80,443,8080" --rate 10000

  # Skip nmap (masscan only)
  python prescan.py --scope scope.txt --skip-nmap

Port Modes:
  quick     - Common ports (~20 ports) - fastest
  standard  - Extended ports (~50 ports) - balanced (default)
  full      - All 65535 ports - thorough but slow

Rate Guidelines:
  100       - Stealth (slow, minimal detection)
  1000      - Normal (default, balanced)
  10000     - Aggressive (fast, may trigger IDS)
"""
    )

    parser.add_argument("--scope", "-s", required=True, help="Path to scope file")
    parser.add_argument("--output", "-o", help="Output directory (default: auto-generated)")
    parser.add_argument("--ports", "-p", choices=["quick", "standard", "full"], default="standard",
                        help="Port scan mode (default: standard)")
    parser.add_argument("--custom-ports", help="Custom port list (overrides --ports)")
    parser.add_argument("--rate", "-r", type=int, default=RATE_NORMAL,
                        help=f"Masscan packet rate (default: {RATE_NORMAL})")
    parser.add_argument("--skip-nmap", action="store_true",
                        help="Skip nmap stage (masscan only)")
    parser.add_argument("--nmap-scripts", action="store_true",
                        help="Enable nmap vulnerability scripts (slower)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    # Validate scope file
    scope_path = Path(args.scope).expanduser()
    if not scope_path.exists():
        print(f"Error: Scope file not found: {scope_path}")
        return 1

    # Create config
    config = PrescanConfig(
        scope_file=scope_path,
        output_dir=Path(args.output) if args.output else None,
        port_mode=args.ports,
        custom_ports=args.custom_ports,
        rate=args.rate,
        skip_nmap=args.skip_nmap,
        nmap_scripts=args.nmap_scripts,
        verbose=args.verbose
    )

    # Run prescan
    scanner = Prescan(config)
    result = await scanner.run()

    # Print summary
    print("\n" + "=" * 60)
    print("PRESCAN SUMMARY")
    print("=" * 60)
    print(f"Status: {result.status}")
    print(f"Duration: {result.duration_seconds:.1f}s")
    print(f"Live hosts: {len(result.hosts)}")
    print(f"Total open ports: {result.masscan_ports_found}")
    print(f"Services identified: {result.nmap_services_identified}")

    if result.live_targets_file:
        print(f"\nLive targets file: {result.live_targets_file}")

    if result.output_dir:
        print(f"Output directory: {result.output_dir}")

    if result.errors:
        print(f"\nErrors: {len(result.errors)}")
        for e in result.errors:
            print(f"  - {e}")

    if result.warnings:
        print(f"\nWarnings: {len(result.warnings)}")
        for w in result.warnings:
            print(f"  - {w}")

    print("=" * 60)

    return 0 if result.status == "success" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
