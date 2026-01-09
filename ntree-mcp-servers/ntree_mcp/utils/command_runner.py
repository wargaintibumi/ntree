"""
Safe command execution utilities
Provides secure subprocess execution with timeout and logging
"""

import asyncio
import shlex
import subprocess
from pathlib import Path
from typing import Tuple, Optional, List
from .logger import get_logger

logger = get_logger(__name__)


class CommandRunner:
    """Execute shell commands safely with logging and timeout."""

    def __init__(self, timeout: int = 300, max_output_size: int = 10_000_000):
        """
        Initialize command runner.

        Args:
            timeout: Maximum execution time in seconds (default 5 minutes)
            max_output_size: Maximum output size in bytes (default 10MB)
        """
        self.timeout = timeout
        self.max_output_size = max_output_size

    async def run_async(
        self,
        command: str,
        shell: bool = False,
        capture_output: bool = True,
        check: bool = False,
        cwd: Optional[Path] = None,
        env: Optional[dict] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a command asynchronously.

        Args:
            command: Command to execute
            shell: Whether to use shell (avoid when possible)
            capture_output: Capture stdout/stderr
            check: Raise exception on non-zero exit
            cwd: Working directory
            env: Environment variables

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        logger.debug(f"Executing command: {command}")

        try:
            if not shell:
                cmd_list = shlex.split(command)
            else:
                cmd_list = command

            # Use asyncio subprocess
            if isinstance(cmd_list, list):
                process = await asyncio.create_subprocess_exec(
                    *cmd_list,
                    stdout=asyncio.subprocess.PIPE if capture_output else None,
                    stderr=asyncio.subprocess.PIPE if capture_output else None,
                    cwd=cwd,
                    env=env,
                )
            else:
                process = await asyncio.create_subprocess_shell(
                    cmd_list,
                    stdout=asyncio.subprocess.PIPE if capture_output else None,
                    stderr=asyncio.subprocess.PIPE if capture_output else None,
                    cwd=cwd,
                    env=env,
                )

            # Wait for completion with timeout
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.error(f"Command timed out after {self.timeout}s: {command}")
                return -1, "", f"Command timed out after {self.timeout}s"

            # Decode output
            stdout = stdout_data.decode('utf-8', errors='replace') if stdout_data else ""
            stderr = stderr_data.decode('utf-8', errors='replace') if stderr_data else ""

            # Check output size
            if len(stdout) > self.max_output_size:
                logger.warning(f"stdout truncated (exceeded {self.max_output_size} bytes)")
                stdout = stdout[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            if len(stderr) > self.max_output_size:
                logger.warning(f"stderr truncated (exceeded {self.max_output_size} bytes)")
                stderr = stderr[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            returncode = process.returncode
            logger.debug(f"Command completed with returncode: {returncode}")

            if check and returncode != 0:
                raise subprocess.CalledProcessError(returncode, command, stdout, stderr)

            return returncode, stdout, stderr

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with returncode {e.returncode}: {command}")
            return e.returncode, e.stdout or "", e.stderr or ""

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return -1, "", str(e)

    def run_sync(
        self,
        command: str,
        shell: bool = False,
        capture_output: bool = True,
        check: bool = False,
        cwd: Optional[Path] = None,
        env: Optional[dict] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a command synchronously.

        Args:
            command: Command to execute
            shell: Whether to use shell
            capture_output: Capture stdout/stderr
            check: Raise exception on non-zero exit
            cwd: Working directory
            env: Environment variables

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        logger.debug(f"Executing command (sync): {command}")

        try:
            if not shell:
                cmd_list = shlex.split(command)
            else:
                cmd_list = command

            result = subprocess.run(
                cmd_list,
                shell=shell,
                capture_output=capture_output,
                text=True,
                timeout=self.timeout,
                check=check,
                cwd=cwd,
                env=env,
            )

            stdout = result.stdout or ""
            stderr = result.stderr or ""

            # Check output size
            if len(stdout) > self.max_output_size:
                logger.warning(f"stdout truncated (exceeded {self.max_output_size} bytes)")
                stdout = stdout[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            if len(stderr) > self.max_output_size:
                logger.warning(f"stderr truncated (exceeded {self.max_output_size} bytes)")
                stderr = stderr[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"

            logger.debug(f"Command completed with returncode: {result.returncode}")
            return result.returncode, stdout, stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.timeout}s: {command}")
            return -1, "", f"Command timed out after {self.timeout}s"

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with returncode {e.returncode}: {command}")
            return e.returncode, e.stdout or "", e.stderr or ""

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return -1, "", str(e)


# Convenience functions
async def run_command(
    command: str,
    timeout: int = 300,
    **kwargs
) -> Tuple[int, str, str]:
    """
    Convenience function to run a command asynchronously.

    Args:
        command: Command to execute
        timeout: Timeout in seconds
        **kwargs: Additional arguments for CommandRunner.run_async()

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    runner = CommandRunner(timeout=timeout)
    return await runner.run_async(command, **kwargs)


def run_command_sync(
    command: str,
    timeout: int = 300,
    **kwargs
) -> Tuple[int, str, str]:
    """
    Convenience function to run a command synchronously.

    Args:
        command: Command to execute
        timeout: Timeout in seconds
        **kwargs: Additional arguments for CommandRunner.run_sync()

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    runner = CommandRunner(timeout=timeout)
    return runner.run_sync(command, **kwargs)


# Security tool wrappers
class SecurityTools:
    """Wrappers for common security tools with safe defaults."""

    @staticmethod
    async def nmap(
        targets: str,
        ports: Optional[str] = None,
        scan_type: str = "-sV",
        output_file: Optional[Path] = None,
        extra_args: str = "",
        timeout: int = 600
    ) -> Tuple[int, str, str]:
        """
        Run nmap with safe defaults.

        Args:
            targets: Target IPs/ranges
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            scan_type: Scan type flags (default: -sV version detection)
            output_file: Output XML file path
            extra_args: Additional nmap arguments
            timeout: Command timeout

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        cmd_parts = ["sudo", "nmap", scan_type]

        if ports:
            cmd_parts.extend(["-p", ports])

        if output_file:
            cmd_parts.extend(["-oX", str(output_file)])

        if extra_args:
            cmd_parts.append(extra_args)

        cmd_parts.append(targets)

        command = " ".join(cmd_parts)
        return await run_command(command, timeout=timeout)

    @staticmethod
    async def enum4linux(
        target: str,
        output_file: Optional[Path] = None,
        timeout: int = 300
    ) -> Tuple[int, str, str]:
        """
        Run enum4linux for SMB enumeration.

        Args:
            target: Target IP address
            output_file: Output file path
            timeout: Command timeout

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        command = f"enum4linux -a {target}"

        returncode, stdout, stderr = await run_command(command, timeout=timeout)

        if output_file and stdout:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(stdout)

        return returncode, stdout, stderr

    @staticmethod
    async def nikto(
        url: str,
        output_file: Optional[Path] = None,
        timeout: int = 600
    ) -> Tuple[int, str, str]:
        """
        Run nikto web vulnerability scanner.

        Args:
            url: Target URL
            output_file: Output file path
            timeout: Command timeout

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        cmd_parts = ["nikto", "-h", url]

        if output_file:
            cmd_parts.extend(["-output", str(output_file)])

        command = " ".join(cmd_parts)
        return await run_command(command, timeout=timeout)
