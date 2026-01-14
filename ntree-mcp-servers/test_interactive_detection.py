#!/usr/bin/env python3
"""
Test Interactive Tools Detection System
Tests the interactive tool detection and manual review handling
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from ntree_mcp.utils.interactive_tools import (
    is_tool_interactive,
    detect_interactive_prompt,
    should_skip_command,
    get_safe_alternative,
    get_tool_name
)
from ntree_mcp.utils.command_runner import run_command


def test_tool_detection():
    """Test tool name detection."""
    print("\n=== Testing Tool Name Detection ===")

    test_cases = [
        ("rpcclient -U '' 192.168.1.10 -c 'enumdomusers'", "rpcclient"),
        ("sudo rpcclient -U '' 192.168.1.10 -c 'enumdomusers'", "rpcclient"),
        ("/usr/bin/smbclient -L //192.168.1.10/", "smbclient"),
        ("mysql -h localhost", "mysql"),
        ("ssh user@host", "ssh"),
        ("nmap -sV 192.168.1.0/24", None),  # nmap is not interactive
    ]

    for command, expected in test_cases:
        result = get_tool_name(command)
        status = "✓" if result == expected else "✗"
        print(f"{status} {command[:50]:<50} -> {result}")


def test_interactive_detection():
    """Test interactive tool detection."""
    print("\n=== Testing Interactive Tool Detection ===")

    test_cases = [
        # Should be detected as interactive
        ("rpcclient -U '' 192.168.1.10 -c 'enumdomusers'", True),
        ("smbclient -L //192.168.1.10/", True),
        ("mysql -h localhost -u root database", True),
        ("ssh user@host", True),
        ("telnet 192.168.1.10", True),

        # Should NOT be detected (has safe flags)
        ("rpcclient -N -U '' 192.168.1.10 -c 'enumdomusers'", False),
        ("smbclient -N -L //192.168.1.10/", False),
        ("mysql -h localhost -u root -pPassword123 database", False),
        ("ssh -o BatchMode=yes user@host", False),

        # Should NOT be detected (not interactive tools)
        ("nmap -sV 192.168.1.10", False),
        ("curl http://example.com", False),
    ]

    for command, should_be_interactive in test_cases:
        result = is_tool_interactive(command)
        is_interactive = result["is_interactive"]
        status = "✓" if is_interactive == should_be_interactive else "✗"

        print(f"{status} {command[:50]:<50} -> Interactive: {is_interactive}")
        if is_interactive:
            print(f"    Reason: {result['reason']}")
            print(f"    Recommendation: {result['recommendation']}")


def test_prompt_detection():
    """Test interactive prompt detection in output."""
    print("\n=== Testing Prompt Detection ===")

    test_cases = [
        ("Enter password: ", True),
        ("Username: ", True),
        ("[Y/n]? ", True),
        ("Are you sure you want to continue? ", True),
        ("Password for user@host: ", True),
        ("Normal output without prompts", False),
        ("Success! Operation completed.", False),
    ]

    for output, should_detect in test_cases:
        result = detect_interactive_prompt(output)
        detected = result is not None
        status = "✓" if detected == should_detect else "✗"

        print(f"{status} '{output[:40]:<40}' -> Detected: {detected}")
        if detected:
            print(f"    Pattern: {result['pattern']}")


def test_safe_alternatives():
    """Test safe alternative generation."""
    print("\n=== Testing Safe Alternative Generation ===")

    test_cases = [
        "rpcclient -U '' 192.168.1.10 -c 'enumdomusers'",
        "smbclient -L //192.168.1.10/",
        "ssh user@host",
        "mysql -h localhost",
        "nmap -sV 192.168.1.10",  # No alternative needed
    ]

    for command in test_cases:
        alternative = get_safe_alternative(command)
        print(f"Original:    {command}")
        print(f"Alternative: {alternative if alternative else 'N/A (not needed or not possible)'}")
        print()


async def test_command_execution():
    """Test command execution with interactive detection."""
    print("\n=== Testing Command Execution with Detection ===")

    # Test 1: Interactive command (should be caught before execution)
    print("\nTest 1: Interactive command without safe flags")
    print("Command: smbclient -L //192.168.1.10/")
    returncode, stdout, stderr = await run_command("smbclient -L //192.168.1.10/", timeout=5)

    if returncode == -2:
        print("✓ Command flagged for manual review")
        import json
        try:
            data = json.loads(stdout)
            print(f"  Status: {data.get('status')}")
            print(f"  Reason: {data.get('reason')}")
            print(f"  Recommendation: {data.get('recommendation')}")
        except:
            print(f"  Response: {stdout[:200]}")
    else:
        print(f"✗ Command executed with returncode: {returncode}")

    # Test 2: Safe command (should execute normally)
    print("\nTest 2: Safe command")
    print("Command: echo 'Hello World'")
    returncode, stdout, stderr = await run_command("echo 'Hello World'", timeout=5)

    if returncode == 0:
        print(f"✓ Command executed successfully")
        print(f"  Output: {stdout.strip()}")
    else:
        print(f"✗ Command failed with returncode: {returncode}")

    # Test 3: Interactive command with safe flags (should execute)
    print("\nTest 3: Interactive command WITH safe flags")
    print("Command: smbclient -N -L //192.168.1.10/")
    returncode, stdout, stderr = await run_command("smbclient -N -L //192.168.1.10/", timeout=5)

    if returncode == -2:
        print("✗ Command incorrectly flagged for manual review")
    else:
        print(f"✓ Command executed with returncode: {returncode}")
        print(f"  (Would normally complete if host responds)")


async def main():
    """Run all tests."""
    print("=" * 80)
    print("NTREE Interactive Tools Detection System - Test Suite")
    print("=" * 80)

    # Run synchronous tests
    test_tool_detection()
    test_interactive_detection()
    test_prompt_detection()
    test_safe_alternatives()

    # Run async tests
    await test_command_execution()

    print("\n" + "=" * 80)
    print("Test suite completed!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
