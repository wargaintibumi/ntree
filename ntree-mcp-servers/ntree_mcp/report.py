"""
NTREE Reporting MCP Server
Handles risk scoring, aggregation, and comprehensive report generation
"""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, List, Dict
from collections import defaultdict

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from .utils.logger import get_logger

logger = get_logger(__name__)

app = Server("ntree-report")


class ScoreRiskArgs(BaseModel):
    """Arguments for score_risk tool."""
    assessment_id: str = Field(description="Assessment ID to score")


class GenerateReportArgs(BaseModel):
    """Arguments for generate_report tool."""
    assessment_id: str = Field(description="Assessment ID to generate report for")
    format: str = Field(
        default="comprehensive",
        description="Report format: executive, technical, or comprehensive"
    )
    output_format: str = Field(
        default="markdown",
        description="Output format: markdown or html"
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available reporting tools."""
    return [
        Tool(
            name="score_risk",
            description="Calculate risk scores and aggregate findings from an assessment",
            inputSchema=ScoreRiskArgs.model_json_schema()
        ),
        Tool(
            name="generate_report",
            description="Generate comprehensive penetration test report with findings, evidence, and recommendations",
            inputSchema=GenerateReportArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool invocations."""
    try:
        if name == "score_risk":
            args = ScoreRiskArgs(**arguments)
            result = await score_risk(args.assessment_id)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "generate_report":
            args = GenerateReportArgs(**arguments)
            result = await generate_report(
                args.assessment_id,
                args.format,
                args.output_format
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            error_result = {"status": "error", "error": f"Unknown tool: {name}"}
            return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

    except Exception as e:
        logger.error(f"Error in call_tool({name}): {e}", exc_info=True)
        error_result = {"status": "error", "error": str(e)}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def score_risk(assessment_id: str) -> dict:
    """
    Calculate risk scores from assessment findings.

    Args:
        assessment_id: Assessment ID

    Returns:
        {
            "status": "success",
            "assessment_id": "assess_20250108_103045",
            "overall_risk": "critical",
            "risk_matrix": {
                "critical": 2,
                "high": 5,
                "medium": 8,
                "low": 12
            },
            "cvss_average": 7.8,
            "critical_paths": [...],
            "business_impact": "...",
            "metrics": {...}
        }
    """
    try:
        logger.info(f"Scoring risk for assessment {assessment_id}")

        # Get assessment directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / assessment_id

        if not assessment_dir.exists():
            return {
                "status": "error",
                "error": f"Assessment {assessment_id} not found"
            }

        # Load state file
        state_file = assessment_dir / "state.json"
        if not state_file.exists():
            return {
                "status": "error",
                "error": f"State file not found for assessment {assessment_id}"
            }

        state = json.loads(state_file.read_text())

        # Load all findings
        findings_dir = assessment_dir / "findings"
        findings = []

        if findings_dir.exists():
            for finding_file in findings_dir.glob("finding_*.json"):
                try:
                    finding = json.loads(finding_file.read_text())
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Error loading finding {finding_file}: {e}")

        # Calculate risk metrics
        risk_matrix = _calculate_risk_matrix(findings)
        overall_risk = _calculate_overall_risk(risk_matrix, findings)
        cvss_average = _calculate_cvss_average(findings)
        critical_paths = _identify_critical_paths(findings, state)
        business_impact = _assess_business_impact(risk_matrix, critical_paths)
        metrics = _calculate_metrics(findings, state)

        result = {
            "status": "success",
            "assessment_id": assessment_id,
            "overall_risk": overall_risk,
            "risk_matrix": risk_matrix,
            "cvss_average": cvss_average,
            "critical_paths": critical_paths,
            "business_impact": business_impact,
            "metrics": metrics,
            "total_findings": len(findings),
        }

        # Save risk assessment to state
        state['risk_assessment'] = result
        state['updated'] = datetime.now().isoformat()
        state_file.write_text(json.dumps(state, indent=2))

        logger.info(f"Risk scoring complete: {overall_risk} risk, {len(findings)} findings")

        return result

    except Exception as e:
        logger.error(f"Error scoring risk for {assessment_id}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def _calculate_risk_matrix(findings: List[dict]) -> dict:
    """Calculate risk matrix by severity."""
    matrix = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0
    }

    for finding in findings:
        severity = finding.get('severity', 'informational').lower()
        if severity in matrix:
            matrix[severity] += 1

    return matrix


def _calculate_overall_risk(risk_matrix: dict, findings: List[dict]) -> str:
    """Determine overall risk level."""
    if risk_matrix['critical'] > 0:
        return "critical"
    elif risk_matrix['high'] >= 3:
        return "high"
    elif risk_matrix['high'] > 0 or risk_matrix['medium'] >= 5:
        return "medium"
    elif risk_matrix['medium'] > 0:
        return "low"
    else:
        return "informational"


def _calculate_cvss_average(findings: List[dict]) -> float:
    """Calculate average CVSS score."""
    scores = []

    for finding in findings:
        cvss = finding.get('cvss_score', 0)
        if cvss > 0:
            scores.append(cvss)

    if scores:
        return round(sum(scores) / len(scores), 1)
    return 0.0


def _identify_critical_paths(findings: List[dict], state: dict) -> list:
    """Identify critical attack paths."""
    paths = []

    # Check for paths to domain admin
    has_domain_admin = any(
        'domain' in f.get('title', '').lower() and 'admin' in f.get('title', '').lower()
        for f in findings
    )

    if has_domain_admin:
        paths.append({
            "path": "Compromise → Domain Admin",
            "severity": "critical",
            "description": "Direct path to domain administrator privileges identified"
        })

    # Check for lateral movement chains
    credentials = state.get('discovered_assets', {}).get('credentials', [])
    if len(credentials) > 1:
        paths.append({
            "path": "Initial Access → Credential Reuse → Lateral Movement",
            "severity": "high",
            "description": f"Found {len(credentials)} sets of credentials enabling lateral movement"
        })

    # Check for privilege escalation
    has_privesc = any(
        'privilege' in f.get('title', '').lower() and 'escalation' in f.get('title', '').lower()
        for f in findings
    )

    if has_privesc:
        paths.append({
            "path": "User Access → Privilege Escalation → Admin",
            "severity": "high",
            "description": "Privilege escalation vulnerabilities identified"
        })

    return paths


def _assess_business_impact(risk_matrix: dict, critical_paths: list) -> str:
    """Assess business impact."""
    if risk_matrix['critical'] > 0:
        return "SEVERE: Critical vulnerabilities present immediate risk of complete system compromise"
    elif len(critical_paths) > 0:
        return "HIGH: Multiple attack paths enable unauthorized access to sensitive systems"
    elif risk_matrix['high'] > 0:
        return "MODERATE: Vulnerabilities could lead to data breach or service disruption"
    elif risk_matrix['medium'] > 0:
        return "LOW: Security weaknesses present but require additional exploitation"
    else:
        return "MINIMAL: Minor security issues with limited business impact"


def _calculate_metrics(findings: List[dict], state: dict) -> dict:
    """Calculate assessment metrics."""
    discovered_assets = state.get('discovered_assets', {})
    manual_review_items = state.get('manual_review_items', [])

    return {
        "hosts_discovered": len(discovered_assets.get('hosts', [])),
        "services_enumerated": len(discovered_assets.get('services', [])),
        "credentials_obtained": len(discovered_assets.get('credentials', [])),
        "total_findings": len(findings),
        "exploitable_vulns": sum(1 for f in findings if f.get('exploitable', False)),
        "duration_hours": _calculate_duration(state),
        "manual_review_items": len(manual_review_items),
    }


def _calculate_duration(state: dict) -> float:
    """Calculate assessment duration in hours."""
    try:
        created = datetime.fromisoformat(state.get('created', ''))
        updated = datetime.fromisoformat(state.get('updated', ''))
        duration = (updated - created).total_seconds() / 3600
        return round(duration, 1)
    except:
        return 0.0


async def generate_report(
    assessment_id: str,
    format: str = "comprehensive",
    output_format: str = "markdown"
) -> dict:
    """
    Generate penetration test report.

    Args:
        assessment_id: Assessment ID
        format: Report format (executive, technical, comprehensive)
        output_format: Output format (markdown, html)

    Returns:
        {
            "status": "success",
            "assessment_id": "assess_20250108_103045",
            "report_path": "/path/to/report.md",
            "format": "comprehensive",
            "findings_count": 27
        }
    """
    try:
        logger.info(f"Generating {format} report for assessment {assessment_id}")

        # Get assessment directory
        ntree_home = Path(os.getenv("NTREE_HOME", str(Path.home() / "ntree")))
        assessment_dir = ntree_home / "assessments" / assessment_id

        if not assessment_dir.exists():
            return {
                "status": "error",
                "error": f"Assessment {assessment_id} not found"
            }

        # Load state and findings
        state_file = assessment_dir / "state.json"
        state = json.loads(state_file.read_text())

        findings_dir = assessment_dir / "findings"
        findings = []

        if findings_dir.exists():
            for finding_file in sorted(findings_dir.glob("finding_*.json")):
                try:
                    finding = json.loads(finding_file.read_text())
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Error loading finding {finding_file}: {e}")

        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'low').lower(), 5))

        # Get or calculate risk assessment
        risk_assessment = state.get('risk_assessment', {})
        if not risk_assessment:
            risk_assessment = await score_risk(assessment_id)

        # Generate report based on format
        if format == "executive":
            content = _generate_executive_report(state, findings, risk_assessment)
        elif format == "technical":
            content = _generate_technical_report(state, findings, risk_assessment)
        else:  # comprehensive
            content = _generate_comprehensive_report(state, findings, risk_assessment)

        # Save report to assessment directory
        reports_dir = assessment_dir / "reports"
        reports_dir.mkdir(exist_ok=True)

        # Also save to centralized reports directory
        central_reports_dir = ntree_home / "reports" / assessment_id
        central_reports_dir.mkdir(exist_ok=True, parents=True)

        if output_format == "html":
            report_filename = f"{format}_report.html"
            report_path = reports_dir / report_filename
            central_report_path = central_reports_dir / report_filename

            # Convert markdown content to HTML
            content_html = _markdown_to_html(content)

            # Generate scope and tools lists
            scope_list_html = _generate_scope_list_html(assessment_dir)
            tools_list_html = _generate_tools_list_html(assessment_dir)

            # Render using template
            html_content = _render_html_template(
                title=f"{format.capitalize()} Report",
                assessment_id=assessment_id,
                test_date=state.get('created', 'Unknown'),
                duration=risk_assessment.get('metrics', {}).get('duration_hours', 0),
                overall_risk=risk_assessment.get('overall_risk', 'unknown'),
                content_html=content_html,
                scope_list=scope_list_html,
                tools_list=tools_list_html
            )

            # Save to both locations
            report_path.write_text(html_content)
            central_report_path.write_text(html_content)
            logger.info(f"Report saved to assessment: {report_path}")
            logger.info(f"Report saved to central repository: {central_report_path}")
        else:
            report_filename = f"{format}_report.md"
            report_path = reports_dir / report_filename
            central_report_path = central_reports_dir / report_filename

            # Save to both locations
            report_path.write_text(content)
            central_report_path.write_text(content)
            logger.info(f"Report saved to assessment: {report_path}")
            logger.info(f"Report saved to central repository: {central_report_path}")

        return {
            "status": "success",
            "assessment_id": assessment_id,
            "report_path": str(report_path),
            "format": format,
            "output_format": output_format,
            "findings_count": len(findings),
            "summary": f"Generated {format} report with {len(findings)} findings"
        }

    except Exception as e:
        logger.error(f"Error generating report for {assessment_id}: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }


def _generate_executive_report(state: dict, findings: List[dict], risk: dict) -> str:
    """Generate executive summary report."""

    # Calculate exploitation status breakdown
    exploitation_stats = {
        'CONFIRMED': 0,
        'NEEDS_VERIFICATION': 0,
        'REQUIRES_MANUAL_CHECK': 0,
        'UNKNOWN': 0
    }
    for finding in findings:
        status = finding.get('exploitation_status', 'UNKNOWN')
        exploitation_stats[status] = exploitation_stats.get(status, 0) + 1

    report = f"""# Penetration Test Executive Summary

## Assessment Information

**Assessment ID**: {state.get('assessment_id', 'Unknown')}
**Test Date**: {state.get('created', 'Unknown')}
**Duration**: {risk.get('metrics', {}).get('duration_hours', 0)} hours
**Overall Risk**: **{risk.get('overall_risk', 'Unknown').upper()}**

---

## Executive Summary

This penetration test was conducted to assess the security posture of the target environment. The assessment identified **{risk.get('total_findings', 0)}** security findings across {risk.get('metrics', {}).get('hosts_discovered', 0)} hosts.

### Risk Level: {risk.get('overall_risk', 'Unknown').upper()}

{risk.get('business_impact', 'Assessment complete.')}

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {risk.get('risk_matrix', {}).get('critical', 0)} |
| High | {risk.get('risk_matrix', {}).get('high', 0)} |
| Medium | {risk.get('risk_matrix', {}).get('medium', 0)} |
| Low | {risk.get('risk_matrix', {}).get('low', 0)} |

**Average CVSS Score**: {risk.get('cvss_average', 0)}

---

## Exploitation Status

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Confirmed | {exploitation_stats['CONFIRMED']} | Successfully exploited with proof |
| ⚠️ Needs Verification | {exploitation_stats['NEEDS_VERIFICATION']} | Evidence exists but requires manual testing |
| ❓ Requires Check | {exploitation_stats['REQUIRES_MANUAL_CHECK']} | Vulnerability detected, manual verification needed |

---

## Critical Findings

"""

    # Add top critical/high findings
    critical_findings = [f for f in findings if f.get('severity', '').lower() in ['critical', 'high']]

    for i, finding in enumerate(critical_findings[:5], 1):
        exploit_status = finding.get('exploitation_status', 'UNKNOWN')
        exploit_badge = {
            'CONFIRMED': '✅ Exploited',
            'NEEDS_VERIFICATION': '⚠️ Needs Manual Verification',
            'REQUIRES_MANUAL_CHECK': '❓ Requires Manual Check',
            'UNKNOWN': '❓ Unknown'
        }.get(exploit_status, exploit_status)

        report += f"""### {i}. {finding.get('title', 'Unknown Finding')}

**Severity**: {finding.get('severity', 'Unknown').upper()}
**CVSS Score**: {finding.get('cvss_score', 'N/A')}
**Exploitation Status**: {exploit_badge}

---

**Risk**: {finding.get('description', 'No description available')}

---

**Impact**: {finding.get('impact', 'This vulnerability could lead to unauthorized access, data breach, or service disruption.')}

---

**Recommendation**: {finding.get('remediation', 'Contact security team for guidance')}

---

"""

    # Critical attack paths
    if risk.get('critical_paths'):
        report += "## Critical Attack Paths\n\n"
        for path in risk['critical_paths']:
            report += f"- **{path['path']}**: {path['description']}\n"

    # Recommendations
    report += """

## Strategic Recommendations

1. **Immediate Actions** (0-30 days):
   - Address all Critical severity findings
   - Implement emergency patches for known CVEs
   - Review and restrict administrative access

2. **Short-term Actions** (1-3 months):
   - Remediate High severity findings
   - Implement security monitoring and alerting
   - Conduct security awareness training

3. **Long-term Improvements** (3-12 months):
   - Establish regular vulnerability scanning program
   - Implement defense-in-depth security controls
   - Conduct annual penetration testing

---

## Conclusion

This assessment identified significant security concerns that require immediate attention. Prioritizing the remediation of Critical and High severity findings will substantially improve the security posture.

---

*Generated by NTREE v2.0*
*Assessment ID: {state.get('assessment_id', 'Unknown')}*
"""

    return report


def _generate_technical_report(state: dict, findings: List[dict], risk: dict) -> str:
    """Generate technical findings report."""
    report = f"""# Penetration Test Technical Report

## Assessment Details

- **Assessment ID**: {state.get('assessment_id', 'Unknown')}
- **Scope**: {', '.join(state.get('scope', {}).get('targets', ['Unknown']))}
- **Start Date**: {state.get('created', 'Unknown')}
- **End Date**: {state.get('updated', 'Unknown')}
- **Methodology**: NTREE Automated Penetration Testing

---

## Technical Summary

### Assets Discovered

- **Hosts**: {risk.get('metrics', {}).get('hosts_discovered', 0)}
- **Services**: {risk.get('metrics', {}).get('services_enumerated', 0)}
- **Credentials**: {risk.get('metrics', {}).get('credentials_obtained', 0)}
- **Findings**: {risk.get('total_findings', 0)}

### Risk Distribution

"""

    # Add risk matrix
    matrix = risk.get('risk_matrix', {})
    for severity, count in matrix.items():
        if count > 0:
            report += f"- **{severity.capitalize()}**: {count}\n"

    report += "\n---\n\n## Detailed Findings\n\n"

    # Add all findings with technical details
    for i, finding in enumerate(findings, 1):
        severity = finding.get('severity', 'unknown').upper()
        exploit_status = finding.get('exploitation_status', 'UNKNOWN')
        exploit_badge = {
            'CONFIRMED': '✅ Exploited Successfully',
            'NEEDS_VERIFICATION': '⚠️ Needs Manual Verification',
            'REQUIRES_MANUAL_CHECK': '❓ Requires Manual Check',
            'UNKNOWN': '❓ Unknown'
        }.get(exploit_status, exploit_status)

        report += f"""### Finding #{i}: {finding.get('title', 'Unknown')}

**Severity**: {severity}
**CVSS Score**: {finding.get('cvss_score', 'N/A')}
**Exploitation Status**: {exploit_badge}
**Affected Hosts**: {', '.join(finding.get('affected_hosts', ['Unknown']))}

#### Description

{finding.get('description', 'No description available')}

---

#### Risk Assessment

**Risk Level**: {severity}

**Impact**: {finding.get('impact', 'Impact assessment not available')}

---

#### Evidence

```
{finding.get('evidence', 'No evidence available')}
```

{'**Note**: This finding requires manual verification. The evidence above shows the vulnerability exists but successful exploitation has not been confirmed.' if exploit_status in ['NEEDS_VERIFICATION', 'REQUIRES_MANUAL_CHECK'] else ''}

#### Technical Details

{finding.get('technical_details', 'See evidence above')}

---

#### Recommendations

{finding.get('remediation', 'Contact security team for specific remediation steps')}

---

#### References

{_format_references(finding.get('references', []))}

---

"""

    return report


def _generate_manual_review_section(state: dict) -> str:
    """Generate manual review items section."""
    manual_review_items = state.get('manual_review_items', [])

    if not manual_review_items:
        return ""

    section = f"""

---

# Manual Review Required

The following items require manual review due to interactive tool requirements:

"""

    for i, item in enumerate(manual_review_items, 1):
        section += f"""
## {i}. {item.get('operation', 'Operation')}

**Tool**: {item.get('tool', 'Unknown')}

**Reason**: {item.get('reason', 'Interactive tool detected')}

**Details**: {item.get('details', 'N/A')}

**Recommendation**: {item.get('recommendation', 'Manual execution required')}

"""
        if item.get('safe_alternative'):
            section += f"**Safe Alternative**: `{item.get('safe_alternative')}`\n\n"

        if item.get('original_command'):
            section += f"**Original Command**: `{item.get('original_command')}`\n\n"

    return section


def _generate_comprehensive_report(state: dict, findings: List[dict], risk: dict) -> str:
    """Generate comprehensive report with executive summary and technical details."""
    # Combine executive and technical reports
    exec_report = _generate_executive_report(state, findings, risk)
    tech_report = _generate_technical_report(state, findings, risk)

    # Add manual review section if items exist
    manual_review_section = _generate_manual_review_section(state)

    # Add methodology section
    methodology = f"""

---

# Appendix A: Methodology

## Testing Approach

NTREE follows a systematic penetration testing methodology:

1. **Reconnaissance**: Network discovery and host identification
2. **Enumeration**: Service detection and version identification
3. **Vulnerability Analysis**: Identification of security weaknesses
4. **Exploitation**: Validation of vulnerabilities (safe mode)
5. **Post-Exploitation**: Lateral movement and privilege escalation analysis
6. **Reporting**: Risk assessment and documentation

## Tools Used

- nmap: Network scanning and service detection
- Nikto: Web vulnerability scanning
- enum4linux: SMB enumeration
- crackmapexec: Credential validation and lateral movement
- nuclei: Modern vulnerability scanning
- searchsploit: Exploit database research
- Custom NTREE analysis tools

## Limitations

- Testing was conducted in safe mode to minimize impact
- Some vulnerabilities were validated but not exploited
- Results represent a point-in-time assessment
- Additional vulnerabilities may exist outside tested scope

---

# Appendix B: Attack Narrative

## Reconnaissance Phase

{risk.get('metrics', {}).get('hosts_discovered', 0)} live hosts were discovered on the network.

## Enumeration Phase

Detailed service enumeration revealed {risk.get('metrics', {}).get('services_enumerated', 0)} running services.

## Exploitation Phase

{risk.get('metrics', {}).get('exploitable_vulns', 0)} exploitable vulnerabilities were identified and validated.

## Post-Exploitation Phase

"""

    if risk.get('metrics', {}).get('credentials_obtained', 0) > 0:
        methodology += f"Credential reuse enabled access to {risk.get('metrics', {}).get('credentials_obtained', 0)} additional systems.\n\n"

    methodology += "---\n\n*End of Report*\n"

    # Combine all sections
    return exec_report + "\n" + tech_report + "\n" + manual_review_section + "\n" + methodology


def _format_references(references: list) -> str:
    """Format references section."""
    if not references:
        return "- No external references"

    formatted = ""
    for ref in references:
        if isinstance(ref, str):
            formatted += f"- {ref}\n"
        elif isinstance(ref, dict):
            formatted += f"- [{ref.get('title', 'Reference')}]({ref.get('url', '#')})\n"

    return formatted


def _generate_scope_list_html(assessment_dir: Path) -> str:
    """Generate HTML list of targets in scope."""
    try:
        scope_file = assessment_dir / "scope.txt"
        if not scope_file.exists():
            return "<li>Scope file not found</li>"

        scope_content = scope_file.read_text()
        targets = []

        for line in scope_content.split('\n'):
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            # Skip EXCLUDE lines
            if line.startswith('EXCLUDE'):
                continue
            targets.append(line)

        if not targets:
            return "<li>No targets defined</li>"

        html_items = [f"<li>{target}</li>" for target in targets]
        return "\n".join(html_items)

    except Exception as e:
        logger.error(f"Error generating scope list: {e}")
        return "<li>Error loading scope</li>"


def _generate_tools_list_html(assessment_dir: Path) -> str:
    """Generate HTML list of tools used in assessment."""
    try:
        # Base mandatory tools
        tools = {
            "nmap": "Network reconnaissance and port scanning",
            "nuclei": "Automated vulnerability scanning with templates"
        }

        # Check scans directory for evidence of other tools
        scans_dir = assessment_dir / "scans"
        if scans_dir.exists():
            # Check for masscan
            if list(scans_dir.glob("*masscan*")):
                tools["masscan"] = "High-speed TCP port scanner"

            # Check for nikto
            if list(scans_dir.glob("*nikto*")):
                tools["nikto"] = "Web server vulnerability scanner"

            # Check for enum4linux
            if list(scans_dir.glob("*enum4linux*")):
                tools["enum4linux"] = "SMB/Windows enumeration"

            # Check for crackmapexec
            if list(scans_dir.glob("*crackmapexec*")) or list(scans_dir.glob("*cme*")):
                tools["crackmapexec"] = "Network service exploitation and assessment"

            # Check for hydra
            if list(scans_dir.glob("*hydra*")):
                tools["hydra"] = "Network authentication cracking"

        # Generate HTML list items
        html_items = [
            f"<li><strong>{tool}</strong>: {description}</li>"
            for tool, description in tools.items()
        ]

        return "\n".join(html_items)

    except Exception as e:
        logger.error(f"Error generating tools list: {e}")
        return "<li>nmap: Network reconnaissance</li><li>nuclei: Vulnerability scanning</li>"


def _render_html_template(
    title: str,
    assessment_id: str,
    test_date: str,
    duration: float,
    overall_risk: str,
    content_html: str,
    scope_list: str = "",
    tools_list: str = ""
) -> str:
    """Render HTML report using template."""
    try:
        # Get template path
        template_path = Path(__file__).parent / "templates" / "report_template.html"

        if not template_path.exists():
            logger.warning(f"Template not found at {template_path}, using fallback")
            return _markdown_to_html_fallback(content_html)

        # Load template
        template = template_path.read_text()

        # Replace template variables
        html = template.replace("{{ title }}", title)
        html = html.replace("{{ assessment_id }}", assessment_id)
        html = html.replace("{{ test_date }}", test_date)
        html = html.replace("{{ duration }}", str(duration))
        html = html.replace("{{ overall_risk }}", overall_risk.lower())
        html = html.replace("{{ content }}", content_html)
        html = html.replace("{{ scope_list }}", scope_list)
        html = html.replace("{{ tools_list }}", tools_list)
        html = html.replace("{{ generation_date }}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        return html

    except Exception as e:
        logger.error(f"Error rendering template: {e}", exc_info=True)
        return _markdown_to_html_fallback(content_html)


def _markdown_to_html(markdown_content: str) -> str:
    """Convert markdown content to HTML with proper formatting."""
    # Convert markdown to HTML elements
    html = markdown_content

    # Convert headers
    html = _convert_markdown_headers(html)

    # Convert code blocks
    html = _convert_markdown_code_blocks(html)

    # Convert tables
    html = _convert_markdown_tables(html)

    # Convert lists
    html = _convert_markdown_lists(html)

    # Convert bold/italic
    html = _convert_markdown_emphasis(html)

    # Convert links
    html = _convert_markdown_links(html)

    # Add severity styling
    html = _add_severity_styling(html)

    # Wrap paragraphs
    html = _wrap_paragraphs(html)

    return html


def _convert_markdown_headers(text: str) -> str:
    """Convert markdown headers to HTML."""
    lines = text.split('\n')
    result = []

    for line in lines:
        if line.startswith('# '):
            result.append(f'<h1>{line[2:]}</h1>')
        elif line.startswith('## '):
            result.append(f'<h2>{line[3:]}</h2>')
        elif line.startswith('### '):
            result.append(f'<h3>{line[4:]}</h3>')
        elif line.startswith('#### '):
            result.append(f'<h4>{line[5:]}</h4>')
        else:
            result.append(line)

    return '\n'.join(result)


def _convert_markdown_code_blocks(text: str) -> str:
    """Convert markdown code blocks to HTML."""
    import re

    # Convert ``` code blocks
    text = re.sub(r'```([^\n]*)\n(.*?)```', r'<div class="evidence"><pre>\2</pre></div>', text, flags=re.DOTALL)

    # Convert inline code
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)

    return text


def _convert_markdown_tables(text: str) -> str:
    """Convert markdown tables to HTML."""
    lines = text.split('\n')
    result = []
    in_table = False

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check if this is a table row
        if '|' in line and line.strip().startswith('|'):
            if not in_table:
                result.append('<table class="risk-matrix">')
                in_table = True

                # First row is header
                cells = [c.strip() for c in line.split('|')[1:-1]]
                result.append('<thead><tr>')
                for cell in cells:
                    result.append(f'<th>{cell}</th>')
                result.append('</tr></thead><tbody>')

                # Skip separator line
                i += 1
                if i < len(lines) and '|' in lines[i] and '-' in lines[i]:
                    i += 1
                    continue
            else:
                # Data row
                cells = [c.strip() for c in line.split('|')[1:-1]]
                result.append('<tr>')
                for cell in cells:
                    result.append(f'<td>{cell}</td>')
                result.append('</tr>')
        else:
            if in_table:
                result.append('</tbody></table>')
                in_table = False
            result.append(line)

        i += 1

    if in_table:
        result.append('</tbody></table>')

    return '\n'.join(result)


def _convert_markdown_lists(text: str) -> str:
    """Convert markdown lists to HTML."""
    lines = text.split('\n')
    result = []
    in_list = False

    for line in lines:
        if line.strip().startswith('- ') or line.strip().startswith('* '):
            if not in_list:
                result.append('<ul>')
                in_list = True
            result.append(f'<li>{line.strip()[2:]}</li>')
        elif line.strip().startswith(tuple(f'{i}. ' for i in range(10))):
            if not in_list:
                result.append('<ol>')
                in_list = True
            # Extract text after number
            text_part = '. '.join(line.strip().split('. ')[1:])
            result.append(f'<li>{text_part}</li>')
        else:
            if in_list:
                result.append('</ul>')
                in_list = False
            result.append(line)

    if in_list:
        result.append('</ul>')

    return '\n'.join(result)


def _convert_markdown_emphasis(text: str) -> str:
    """Convert markdown bold/italic to HTML."""
    import re

    # Bold
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)

    # Italic
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)

    return text


def _convert_markdown_links(text: str) -> str:
    """Convert markdown links to HTML."""
    import re

    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)

    return text


def _add_severity_styling(text: str) -> str:
    """Add severity badge styling and exploitation status badges."""
    # Severity badges
    text = text.replace('CRITICAL', '<span class="severity-badge severity-critical">CRITICAL</span>')
    text = text.replace('HIGH', '<span class="severity-badge severity-high">HIGH</span>')
    text = text.replace('MEDIUM', '<span class="severity-badge severity-medium">MEDIUM</span>')
    text = text.replace('LOW', '<span class="severity-badge severity-low">LOW</span>')

    # Exploitation status badges
    text = text.replace('✅ Exploited Successfully', '<span class="exploit-status-badge exploit-confirmed">Confirmed</span>')
    text = text.replace('✅ Exploited', '<span class="exploit-status-badge exploit-confirmed">Confirmed</span>')
    text = text.replace('⚠️ Needs Manual Verification', '<span class="exploit-status-badge exploit-needs-verification">Needs Verification</span>')
    text = text.replace('❓ Requires Manual Check', '<span class="exploit-status-badge exploit-requires-check">Requires Check</span>')
    text = text.replace('❓ Unknown', '<span class="exploit-status-badge exploit-requires-check">Unknown</span>')

    # Verification notices
    if '**Note**: This finding requires manual verification' in text:
        text = text.replace('**Note**: This finding requires manual verification. The evidence above shows the vulnerability exists but successful exploitation has not been confirmed.',
                          '<div class="verification-notice"><strong>⚠️ Manual Verification Required</strong><p>The evidence above shows the vulnerability exists but successful exploitation has not been confirmed. Manual testing is recommended to validate exploitability.</p></div>')

    return text


def _wrap_paragraphs(text: str) -> str:
    """Wrap text in paragraph tags."""
    lines = text.split('\n')
    result = []
    in_tag = False

    for line in lines:
        stripped = line.strip()

        # Check if line is already in an HTML tag
        if stripped.startswith('<'):
            in_tag = True
            result.append(line)
            if '>' in stripped and not stripped.startswith('<!--'):
                # Check if tag closes on same line
                if stripped.count('<') == stripped.count('>'):
                    in_tag = False
        elif stripped.endswith('>'):
            result.append(line)
            in_tag = False
        elif not in_tag and stripped and not stripped.startswith('---'):
            result.append(f'<p>{line}</p>')
        else:
            result.append(line)

    return '\n'.join(result)


def _markdown_to_html_fallback(markdown_content: str) -> str:
    """Fallback HTML conversion (simple wrapper)."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NTREE Penetration Test Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; border-bottom: 2px solid #95a5a6; padding-bottom: 5px; }}
        h3 {{ color: #7f8c8d; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        code {{ background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #c0392b; font-weight: bold; }}
        .high {{ color: #e74c3c; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #3498db; font-weight: bold; }}
    </style>
</head>
<body>
{markdown_content}
</body>
</html>"""
    return html


def main():
    """Main entry point for report server."""
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("ntree-report v2.0.0")
            return
        elif sys.argv[1] == "--test":
            print("NTREE Reporting Server - Test Mode")
            return

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
