#!/usr/bin/env python3
"""
Generate multi-page HTML compliance reports from JSON compliance data.

Generates three interconnected HTML pages:
1. Summary Report - Controls grouped by control set with evidence source summaries
2. Evidence Sources - Config rules with resource compliance status
3. Resources - Resource configurations

Inputs:
1. Compliance report JSON (from generate_compliance_report.py)
2. Resource configurations JSON (from get_resource_configurations.py)

Output:
Three HTML files with hyperlinks between them.
"""

import argparse
import csv
import html
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


def load_json_file(file_path: str) -> dict:
    """Load and parse a JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def escape_html(text) -> str:
    """Escape HTML special characters."""
    if text is None:
        return ""
    return html.escape(str(text))


def make_anchor_id(text: str) -> str:
    """Create a valid HTML anchor ID from text."""
    # Replace special characters with underscores
    result = ""
    for c in text:
        if c.isalnum():
            result += c
        else:
            result += "_"
    return result


def load_framework_template_mapping(csv_path: str) -> dict:
    """
    Load the framework-to-conformance-pack-template mapping from CSV.

    Args:
        csv_path: Path to Framework-to-conformance-pack-template-mapping.csv

    Returns:
        Dict mapping framework name to template name(s)
    """
    mapping = {}
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                if len(row) >= 2:
                    framework = row[0].strip()
                    template = row[1].strip()
                    if framework and template and template != "-- No equivalent --":
                        mapping[framework] = template
    except FileNotFoundError:
        pass
    return mapping


def load_templates_to_yaml_mapping(csv_path: str) -> dict:
    """
    Load the template-to-YAML filename mapping from CSV.

    Args:
        csv_path: Path to Conformance pack templates.csv

    Returns:
        Dict mapping template name to YAML filename
    """
    mapping = {}
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                if len(row) >= 2:
                    template_name = row[0].strip()
                    yaml_file = row[1].strip()
                    if template_name and yaml_file:
                        mapping[template_name] = yaml_file
    except FileNotFoundError:
        pass
    return mapping


def find_matching_template(framework_name: str, mapping: dict) -> str:
    """
    Find the conformance pack template that matches the framework name.

    Args:
        framework_name: The framework name from the compliance report
        mapping: Dict from load_framework_template_mapping

    Returns:
        Template name or None if not found
    """
    # Try exact match first
    if framework_name in mapping:
        return mapping[framework_name]

    # Try partial match (framework name contains mapping key or vice versa)
    framework_lower = framework_name.lower()
    for key, template in mapping.items():
        if key.lower() in framework_lower or framework_lower in key.lower():
            return template

    # Try matching key patterns like "PCI DSS V4.0" in framework name
    for key, template in mapping.items():
        # Normalize both for comparison
        key_normalized = re.sub(r'[^a-z0-9]', '', key.lower())
        framework_normalized = re.sub(r'[^a-z0-9]', '', framework_lower)
        if key_normalized in framework_normalized or framework_normalized in key_normalized:
            return template

    return None


def count_config_rules_in_template(yaml_path: str) -> int:
    """
    Count the number of Config rules in a conformance pack YAML template.

    Args:
        yaml_path: Path to the YAML file

    Returns:
        Number of Config rules (AWS::Config::ConfigRule resources)
    """
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Count occurrences of "Type: AWS::Config::ConfigRule"
        return len(re.findall(r"Type:\s*AWS::Config::ConfigRule", content))
    except FileNotFoundError:
        return 0


def find_template_yaml_files(template_name: str, yaml_folder: str, templates_to_yaml: dict = None) -> list:
    """
    Find all YAML files that match a conformance pack template.

    Uses two-step lookup:
    1. First check templates_to_yaml mapping for direct YAML filename
    2. Fall back to fuzzy matching against filenames

    Args:
        template_name: The template name from the mapping
        yaml_folder: Folder containing YAML files
        templates_to_yaml: Dict mapping template name to YAML filename

    Returns:
        List of tuples (filename, path) for matching files
    """
    if not os.path.exists(yaml_folder):
        return []

    matches = []

    # Step 1: Try direct lookup in templates_to_yaml mapping
    if templates_to_yaml:
        # Try exact match
        if template_name in templates_to_yaml:
            yaml_file = templates_to_yaml[template_name]
            yaml_path = os.path.join(yaml_folder, yaml_file)
            if os.path.exists(yaml_path):
                matches.append((yaml_file.replace(".yaml", ""), yaml_path))
                return matches

        # Try normalized match
        template_normalized = re.sub(r'[^a-z0-9]', '', template_name.lower())
        for key, yaml_file in templates_to_yaml.items():
            key_normalized = re.sub(r'[^a-z0-9]', '', key.lower())
            if template_normalized in key_normalized or key_normalized in template_normalized:
                yaml_path = os.path.join(yaml_folder, yaml_file)
                if os.path.exists(yaml_path):
                    matches.append((yaml_file.replace(".yaml", ""), yaml_path))
                    return matches

    # Step 2: Fall back to fuzzy matching against YAML filenames
    template_normalized = re.sub(r'[^a-z0-9]', '', template_name.lower())

    for filename in os.listdir(yaml_folder):
        if filename.endswith(".yaml"):
            # Normalize filename for matching
            filename_normalized = re.sub(r'[^a-z0-9]', '', filename.lower().replace(".yaml", ""))
            # Check if template name is contained in filename or vice versa
            if template_normalized in filename_normalized or filename_normalized in template_normalized:
                matches.append((filename.replace(".yaml", ""), os.path.join(yaml_folder, filename)))

    return matches


def get_common_styles() -> str:
    """Return common CSS styles used across all pages."""
    return """
        * {
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        a {
            color: #2b6cb0;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .nav {
            background: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .nav a {
            margin-right: 20px;
            font-weight: 500;
        }
        .nav a.active {
            color: #1a365d;
            border-bottom: 2px solid #1a365d;
            padding-bottom: 2px;
        }
        .report-header {
            background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .report-header h1 {
            margin: 0 0 10px 0;
            font-size: 28px;
        }
        .report-header .meta {
            opacity: 0.9;
            font-size: 14px;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h3 {
            margin: 0 0 10px 0;
            font-size: 13px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .card .value {
            font-size: 28px;
            font-weight: bold;
            color: #1a365d;
        }
        .card.compliant .value {
            color: #22543d;
        }
        .card.non-compliant .value {
            color: #c53030;
        }
        .compliance-bar {
            height: 8px;
            background: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .compliance-bar .fill {
            height: 100%;
            background: linear-gradient(90deg, #48bb78 0%, #38a169 100%);
            border-radius: 4px;
        }
        .section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            margin: 0 0 20px 0;
            color: #1a365d;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        tr:hover {
            background: #f7fafc;
        }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge.compliant {
            background: #c6f6d5;
            color: #22543d;
        }
        .badge.non-compliant {
            background: #fed7d7;
            color: #c53030;
        }
        .badge.not-applicable {
            background: #e2e8f0;
            color: #718096;
        }
        .badge.missing {
            background: #feebc8;
            color: #c05621;
        }
        .count-compliant {
            color: #22543d;
            font-weight: 600;
        }
        .count-non-compliant {
            color: #c53030;
            font-weight: 600;
        }
        .control-set {
            margin-bottom: 30px;
        }
        .control-set-header {
            background: #edf2f7;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 15px;
        }
        .control-set-header h3 {
            margin: 0;
            font-size: 16px;
            color: #2d3748;
        }
        .control-set-header .stats {
            font-size: 14px;
            color: #718096;
            margin-top: 5px;
        }
        .mono {
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 13px;
        }
        .config-block {
            background: #1a202c;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 12px;
            line-height: 1.5;
            max-height: 400px;
            overflow-y: auto;
        }
        .config-block pre {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .resource-entry {
            margin-bottom: 30px;
            padding-bottom: 30px;
            border-bottom: 1px solid #e2e8f0;
        }
        .resource-entry:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        .resource-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }
        .resource-title {
            font-size: 16px;
            font-weight: 600;
            color: #2d3748;
        }
        .resource-type {
            font-size: 13px;
            color: #718096;
            margin-top: 4px;
        }
        .resource-meta {
            font-size: 13px;
            color: #718096;
            margin-bottom: 15px;
        }
        .resource-meta span {
            margin-right: 20px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #718096;
            font-size: 13px;
        }
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .nav {
                display: none;
            }
            .report-header {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }
    """


def generate_navigation(active_page: str, prefix: str, template_mode: bool = False) -> str:
    """Generate navigation bar HTML."""
    pages = [
        ("summary", "Summary Report"),
        ("evidence", "Evidence Sources"),
    ]
    # Only include Resources page if not in template mode
    if not template_mode:
        pages.append(("resources", "Resources"))
    # Always include Control Catalog
    pages.append(("control_catalog", "Control Catalog"))

    nav_items = []
    for page_id, page_name in pages:
        active_class = " active" if page_id == active_page else ""
        nav_items.append(f'<a href="{prefix}_{page_id}.html" class="{active_class}">{page_name}</a>')

    return f"""
    <nav class="nav">
        {" ".join(nav_items)}
    </nav>
    """


def generate_page_header(framework_name: str, conformance_pack: str, generated_at: str) -> str:
    """Generate the common page header."""
    return f"""
    <div class="report-header">
        <h1>{escape_html(framework_name)}</h1>
        <div class="meta">
            <div>Conformance Pack: {escape_html(conformance_pack)}</div>
            <div>Generated: {escape_html(generated_at)}</div>
        </div>
    </div>
    """


def build_evidence_source_data(compliance_report: dict) -> dict:
    """
    Build a dictionary of evidence sources with their resources.

    Returns:
        Dict mapping config rule name to evidence source data including resources
    """
    evidence_sources = {}

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") != "AWS_Config":
                    continue

                rule_name = source.get("configRuleName")
                if not rule_name:
                    continue

                if rule_name not in evidence_sources:
                    evidence_sources[rule_name] = {
                        "configRuleName": rule_name,
                        "sourceName": source.get("sourceName"),
                        "sourceDescription": source.get("sourceDescription"),
                        "keywordValue": source.get("keywordValue"),
                        "inConformancePack": source.get("inConformancePack", False),
                        "resources": {},
                        "complianceSummary": {
                            "compliant": 0,
                            "nonCompliant": 0,
                            "notApplicable": 0
                        }
                    }

                # Add resources (deduplicated by resourceKey)
                for result in source.get("evaluationResults", []):
                    resource_key = result.get("resourceKey")
                    if resource_key and resource_key not in evidence_sources[rule_name]["resources"]:
                        evidence_sources[rule_name]["resources"][resource_key] = {
                            "resourceKey": resource_key,
                            "resourceType": result.get("resourceType"),
                            "resourceId": result.get("resourceId"),
                            "complianceType": result.get("complianceType"),
                            "annotation": result.get("annotation"),
                            "resultRecordedTime": result.get("resultRecordedTime")
                        }

                        # Update counts
                        compliance_type = result.get("complianceType", "")
                        if compliance_type == "COMPLIANT":
                            evidence_sources[rule_name]["complianceSummary"]["compliant"] += 1
                        elif compliance_type == "NON_COMPLIANT":
                            evidence_sources[rule_name]["complianceSummary"]["nonCompliant"] += 1
                        else:
                            evidence_sources[rule_name]["complianceSummary"]["notApplicable"] += 1

    return evidence_sources


def count_mapped_rules(compliance_report: dict) -> int:
    """
    Count unique Config rules referenced in framework that are deployed in conformance pack.

    Returns count of unique rules by keyword value.
    """
    mapped_keywords = set()

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") == "AWS_Config" and source.get("inConformancePack", False):
                    keyword = source.get("keywordValue")
                    if keyword:
                        mapped_keywords.add(keyword)

    return len(mapped_keywords)


def count_unmapped_rules(compliance_report: dict) -> int:
    """
    Count unique Config rules referenced in framework but not in conformance pack.

    Returns count of unique rules by keyword value.
    """
    unmapped_keywords = set()

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") == "AWS_Config" and not source.get("inConformancePack", False):
                    keyword = source.get("keywordValue")
                    if keyword:
                        unmapped_keywords.add(keyword)

    return len(unmapped_keywords)


def generate_summary_page(
    compliance_report: dict,
    evidence_sources: dict,
    prefix: str,
    gap_report_link: str = None,
    extra_rules_report_link: str = None,
    matching_templates: list = None,
    template_mode: bool = False
) -> str:
    """Generate the summary report HTML page."""

    summary = compliance_report.get("summary", {})
    framework_name = compliance_report.get("frameworkName", "Unknown Framework")
    conformance_pack = compliance_report.get("conformancePackName", "Unknown")
    generated_at = compliance_report.get("reportGeneratedAt", "")

    # Count mapped and unmapped rules for the summary cards
    mapped_rules_count = count_mapped_rules(compliance_report)
    unmapped_rules_count = count_unmapped_rules(compliance_report)
    total_config_rules = mapped_rules_count + unmapped_rules_count

    # Count extra rules in conformance pack not in framework
    extra_rules_count = len(compliance_report.get("conformancePackRulesNotInFramework", []))

    # Total rules in conformance pack = mapped rules + extra rules
    rules_in_pack_count = mapped_rules_count + extra_rules_count

    # Calculate compliance percentage
    total_evaluated = (
        summary.get("compliantResources", 0) +
        summary.get("nonCompliantResources", 0)
    )
    compliance_pct = 0
    if total_evaluated > 0:
        compliance_pct = (summary.get("compliantResources", 0) / total_evaluated) * 100

    html_parts = []

    # HTML Header
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Summary - {escape_html(framework_name)}</title>
    <style>
        {get_common_styles()}
    </style>
</head>
<body>
    {generate_navigation("summary", prefix, template_mode)}
    {generate_page_header(framework_name, conformance_pack, generated_at)}
""")

    # Check if no template was available
    no_template_available = compliance_report.get("noTemplateAvailable", False)

    # Summary Cards - different layout for template mode
    if template_mode:
        if no_template_available:
            html_parts.append(f"""
    <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
        <strong style="color: #b45309;">No Conformance Pack Template Available</strong>
        <p style="color: #92400e; margin: 5px 0 0 0; font-size: 14px;">
            There is no conformance pack template associated with the <strong>{escape_html(framework_name)}</strong> framework.
            This report shows the Config rules referenced in the framework. Use the Control Catalog report to see detailed
            information about each rule. To deploy a conformance pack, you will need to create a custom template or use
            a related framework's template.
        </p>
    </div>""")
        else:
            html_parts.append(f"""
    <div style="background: #f0f9ff; border: 1px solid #0ea5e9; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
        <strong style="color: #0369a1;">Template Analysis Mode</strong>
        <p style="color: #0369a1; margin: 5px 0 0 0; font-size: 14px;">
            This report analyzes the framework against a conformance pack template. No deployed conformance pack was evaluated,
            so resource compliance data is not available. Deploy the conformance pack to see actual compliance results.
        </p>
    </div>""")
    <div class="summary-cards">
        <div class="card">
            <h3>Control Sets</h3>
            <div class="value">{summary.get('totalControlSets', 0)}</div>
        </div>
        <div class="card">
            <h3>Framework Controls</h3>
            <div class="value">{summary.get('totalControls', 0)}</div>
        </div>
    </div>
""")
    else:
        html_parts.append(f"""
    <div class="summary-cards">
        <div class="card">
            <h3>Control Sets</h3>
            <div class="value">{summary.get('totalControlSets', 0)}</div>
        </div>
        <div class="card">
            <h3>Framework Controls</h3>
            <div class="value">{summary.get('totalControls', 0)}</div>
        </div>
        <div class="card compliant">
            <h3>Compliant Resources</h3>
            <div class="value">{summary.get('compliantResources', 0):,}</div>
        </div>
        <div class="card non-compliant">
            <h3>Non-Compliant Resources</h3>
            <div class="value">{summary.get('nonCompliantResources', 0):,}</div>
        </div>
        <div class="card">
            <h3>Compliance Rate</h3>
            <div class="value">{compliance_pct:.1f}%</div>
            <div class="compliance-bar">
                <div class="fill" style="width: {compliance_pct}%"></div>
            </div>
        </div>
    </div>
""")

    # Evidence Sources Summary Card Row - different labels for template mode
    if template_mode:
        if no_template_available:
            # No template - just show framework rules count
            html_parts.append(f"""
    <div class="summary-cards">
        <div class="card">
            <h3>Config Rules in Framework</h3>
            <div class="value">{total_config_rules}</div>
        </div>
    </div>
""")
        else:
            html_parts.append(f"""
    <div class="summary-cards">
        <div class="card">
            <h3>Config Rules in Framework</h3>
            <div class="value">{total_config_rules}</div>
        </div>
        <div class="card">
            <h3>In Template</h3>
            <div class="value">{mapped_rules_count}</div>
        </div>
        <div class="card">
            <h3>Missing from Template</h3>
            <div class="value">{"<a href='" + gap_report_link + "'>" if gap_report_link else ""}{unmapped_rules_count}{"</a>" if gap_report_link else ""}</div>
        </div>
        <div class="card">
            <h3>Rules in Template</h3>
            <div class="value">{rules_in_pack_count}</div>
        </div>
        <div class="card">
            <h3>Extra Rules in Template</h3>
            <div class="value">{"<a href='" + extra_rules_report_link + "'>" if extra_rules_report_link else ""}{extra_rules_count}{"</a>" if extra_rules_report_link else ""}</div>
        </div>
    </div>
""")
    else:
        html_parts.append(f"""
    <div class="summary-cards">
        <div class="card">
            <h3>Config Rules in Framework</h3>
            <div class="value">{total_config_rules}</div>
        </div>
        <div class="card">
            <h3>Mapped to Pack</h3>
            <div class="value">{mapped_rules_count}</div>
        </div>
        <div class="card">
            <h3>Missing from Pack</h3>
            <div class="value">{"<a href='" + gap_report_link + "'>" if gap_report_link else ""}{unmapped_rules_count}{"</a>" if gap_report_link else ""}</div>
        </div>
        <div class="card">
            <h3>Rules in Pack</h3>
            <div class="value">{rules_in_pack_count}</div>
        </div>
        <div class="card">
            <h3>Extra Rules in Pack</h3>
            <div class="value">{"<a href='" + extra_rules_report_link + "'>" if extra_rules_report_link else ""}{extra_rules_count}{"</a>" if extra_rules_report_link else ""}</div>
        </div>
    </div>
""")

    # Conformance Pack Template Cross-Check
    if matching_templates:
        templates_html = ""
        for item in matching_templates:
            if len(item) == 3:
                template_name, rule_count, yaml_path = item
                templates_html += f'<li><a href="{escape_html(yaml_path)}"><strong>{escape_html(template_name)}</strong></a> — {rule_count} Config Rules</li>\n'
            else:
                template_name, rule_count = item
                templates_html += f"<li><strong>{escape_html(template_name)}</strong> — {rule_count} Config Rules</li>\n"

        html_parts.append(f"""
    <div class="section">
        <h3>Conformance Pack Template Cross-Check</h3>
        <p style="color: #718096; font-size: 14px; margin-bottom: 15px;">
            <em>Note: The AWS Config API does not indicate which template was used when a conformance pack was deployed.
            The following templates are associated with this framework and may have been used:</em>
        </p>
        <ul style="margin: 0; padding-left: 20px;">
            {templates_html}
        </ul>
    </div>
""")

    # Framework Controls by Control Set
    html_parts.append("""
    <div class="section">
        <h2>Framework Controls by Control Set</h2>
""")

    for control_set in compliance_report.get("controlSets", []):
        cs_name = escape_html(control_set.get("controlSetName", ""))
        cs_summary = control_set.get("summary", {})
        num_controls = cs_summary.get("totalControls", 0)

        # Count unique config rules with non-compliant resources
        rules_with_issues = set()
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") == "AWS_Config" and source.get("inConformancePack"):
                    if source.get("complianceSummary", {}).get("nonCompliant", 0) > 0:
                        rule_name = source.get("configRuleName")
                        if rule_name:
                            rules_with_issues.add(rule_name)

        num_rules_with_issues = len(rules_with_issues)
        issues_class = "count-non-compliant" if num_rules_with_issues > 0 else "count-compliant"

        # Count unique missing rules (Config rules not in conformance pack)
        missing_rules = set()
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") == "AWS_Config" and not source.get("inConformancePack"):
                    keyword = source.get("keywordValue") or source.get("configRuleName")
                    if keyword:
                        missing_rules.add(keyword)

        num_missing_rules = len(missing_rules)
        missing_class = "count-non-compliant" if num_missing_rules > 0 else "count-compliant"

        # Different table layout for template mode vs normal mode
        if template_mode:
            html_parts.append(f"""
        <div class="control-set">
            <div class="control-set-header">
                <h3>{cs_name}</h3>
                <div class="stats">
                    {num_controls} controls |
                    <span class="{missing_class}">{num_missing_rules} missing from template</span>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 40%">Framework Control</th>
                        <th style="width: 45%">Evidence Source (Config Rule)</th>
                        <th style="width: 15%; text-align: center;">In Template</th>
                    </tr>
                </thead>
                <tbody>
""")
        else:
            html_parts.append(f"""
        <div class="control-set">
            <div class="control-set-header">
                <h3>{cs_name}</h3>
                <div class="stats">
                    {num_controls} controls |
                    <span class="{issues_class}">{num_rules_with_issues} config rules with non-compliant resources</span> |
                    <span class="{missing_class}">{num_missing_rules} missing from pack</span>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 35%">Framework Control</th>
                        <th style="width: 35%">Evidence Source (Config Rule)</th>
                        <th style="width: 10%; text-align: center;">Compliant</th>
                        <th style="width: 10%; text-align: center;">Non-Compliant</th>
                        <th style="width: 10%; text-align: center;">Status</th>
                    </tr>
                </thead>
                <tbody>
""")

        for control in control_set.get("controls", []):
            ctrl_name = escape_html(control.get("controlName", ""))
            sources = control.get("evidenceSources", [])

            # Get all AWS_Config sources
            all_config_sources = [s for s in sources if s.get("sourceType") == "AWS_Config"]

            # Separate into mapped (in pack) and missing (not in pack)
            mapped_sources = [s for s in all_config_sources if s.get("inConformancePack")]
            missing_sources = [s for s in all_config_sources if not s.get("inConformancePack")]

            if not all_config_sources:
                # Show control with no Config rule references
                if template_mode:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_name}</td>
                        <td style="color: #718096; font-style: italic;">No Config rules referenced</td>
                        <td style="text-align: center;"><span class="badge not-applicable">N/A</span></td>
                    </tr>
""")
                else:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_name}</td>
                        <td style="color: #718096; font-style: italic;">No Config rules referenced</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;"><span class="badge not-applicable">N/A</span></td>
                    </tr>
""")
                continue

            # First source row includes control name
            first = True

            # Show mapped sources first (in template/pack)
            for source in mapped_sources:
                # Use sourceName, fall back to keywordValue or configRuleName
                source_name_raw = source.get("sourceName") or source.get("keywordValue") or source.get("configRuleName") or ""
                source_name = escape_html(source_name_raw)
                rule_name = source.get("configRuleName", "")
                rule_anchor = make_anchor_id(rule_name)

                ctrl_cell = ctrl_name if first else ""
                first = False

                if template_mode:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td><a href="{prefix}_evidence.html#{rule_anchor}">{source_name}</a></td>
                        <td style="text-align: center;"><span class="badge compliant">Yes</span></td>
                    </tr>
""")
                else:
                    comp_summary = source.get("complianceSummary", {})
                    compliant_count = comp_summary.get("compliant", 0)
                    non_compliant_count = comp_summary.get("nonCompliant", 0)

                    # Determine status badge
                    if non_compliant_count > 0:
                        status_badge = '<span class="badge non-compliant">Issues</span>'
                    elif compliant_count > 0:
                        status_badge = '<span class="badge compliant">Compliant</span>'
                    else:
                        status_badge = '<span class="badge not-applicable">N/A</span>'

                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td><a href="{prefix}_evidence.html#{rule_anchor}">{source_name}</a></td>
                        <td style="text-align: center;" class="count-compliant">{compliant_count}</td>
                        <td style="text-align: center;" class="count-non-compliant">{non_compliant_count}</td>
                        <td style="text-align: center;">{status_badge}</td>
                    </tr>
""")

            # Show missing sources (not in template/pack)
            for source in missing_sources:
                source_name_raw = source.get("sourceName") or source.get("keywordValue") or ""
                source_name = escape_html(source_name_raw)
                keyword = source.get("keywordValue", "")
                keyword_anchor = make_anchor_id(keyword)

                ctrl_cell = ctrl_name if first else ""
                first = False

                # Link to gap report if available
                if gap_report_link:
                    source_display = f'<a href="{gap_report_link}#{keyword_anchor}">{source_name}</a>'
                    status_badge = f'<a href="{gap_report_link}#{keyword_anchor}"><span class="badge missing">Missing</span></a>'
                else:
                    source_display = source_name
                    status_badge = '<span class="badge missing">Missing</span>'

                if template_mode:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td>{source_display}</td>
                        <td style="text-align: center;">{status_badge}</td>
                    </tr>
""")
                else:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td>{source_display}</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">{status_badge}</td>
                    </tr>
""")

        html_parts.append("""
                </tbody>
            </table>
        </div>
""")

    html_parts.append("""
    </div>

    <div class="footer">
        Generated by AWS Compliance Reporting Workflow
    </div>
</body>
</html>
""")

    return "".join(html_parts)


def generate_evidence_page(
    compliance_report: dict,
    evidence_sources: dict,
    prefix: str,
    control_catalog_link: str = None,
    template_mode: bool = False
) -> str:
    """Generate the evidence sources HTML page."""

    framework_name = compliance_report.get("frameworkName", "Unknown Framework")
    conformance_pack = compliance_report.get("conformancePackName", "Unknown")
    generated_at = compliance_report.get("reportGeneratedAt", "")

    html_parts = []

    # HTML Header
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Evidence Sources - {escape_html(framework_name)}</title>
    <style>
        {get_common_styles()}
        .evidence-entry {{
            margin-bottom: 30px;
            padding-bottom: 30px;
            border-bottom: 1px solid #e2e8f0;
        }}
        .evidence-entry:last-child {{
            border-bottom: none;
        }}
        .evidence-header {{
            margin-bottom: 15px;
        }}
        .evidence-title {{
            font-size: 18px;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 5px;
        }}
        .evidence-rule {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 13px;
            color: #718096;
        }}
        .evidence-stats {{
            display: flex;
            gap: 20px;
            margin: 15px 0;
        }}
        .evidence-stat {{
            padding: 10px 15px;
            background: #f7fafc;
            border-radius: 6px;
        }}
        .evidence-stat .label {{
            font-size: 12px;
            color: #718096;
            text-transform: uppercase;
        }}
        .evidence-stat .value {{
            font-size: 20px;
            font-weight: 600;
        }}
        .evidence-stat.compliant .value {{
            color: #22543d;
        }}
        .evidence-stat.non-compliant .value {{
            color: #c53030;
        }}
    </style>
</head>
<body>
    {generate_navigation("evidence", prefix, template_mode)}
    {generate_page_header(framework_name, conformance_pack, generated_at)}

    <div class="section">
        <h2>Evidence Sources (AWS Config Rules)</h2>
        <p style="color: #718096; margin-bottom: 20px;">
            {f"{len(evidence_sources)} Config rules mapped from the conformance pack template. This is a template analysis - no deployed conformance pack evaluations are available." if template_mode else f"{len(evidence_sources)} Config rules evaluated across the conformance pack. Click on a resource to view its configuration."}
        </p>
""")

    # Sort evidence sources by rule name
    for rule_name in sorted(evidence_sources.keys()):
        source = evidence_sources[rule_name]
        rule_anchor = make_anchor_id(rule_name)
        source_name = escape_html(source.get("sourceName", ""))
        source_description = escape_html(source.get("sourceDescription", "") or "")
        keyword = escape_html(source.get("keywordValue", ""))
        comp_summary = source.get("complianceSummary", {})
        compliant_count = comp_summary.get("compliant", 0)
        non_compliant_count = comp_summary.get("nonCompliant", 0)
        not_applicable_count = comp_summary.get("notApplicable", 0)

        # Build description HTML if present
        description_html = ""
        if source_description:
            description_html = f'<p style="color: #4a5568; margin: 10px 0 0 0; font-size: 14px;">{source_description}</p>'

        # Build catalog link for keyword
        keyword_raw = source.get("keywordValue", "")
        keyword_anchor = make_anchor_id(keyword_raw)
        keyword_link = f'<a href="{control_catalog_link}#{keyword_anchor}">{keyword}</a>' if control_catalog_link and keyword_raw else keyword

        # Build stats section (only show in non-template mode)
        if template_mode:
            stats_html = """
            <div style="background: #f7fafc; border-radius: 6px; padding: 15px; margin: 15px 0; color: #718096; font-style: italic;">
                Template mode: No resource evaluations available. Deploy this conformance pack to see compliance results.
            </div>
"""
        else:
            stats_html = f"""
            <div class="evidence-stats">
                <div class="evidence-stat compliant">
                    <div class="label">Compliant</div>
                    <div class="value">{compliant_count}</div>
                </div>
                <div class="evidence-stat non-compliant">
                    <div class="label">Non-Compliant</div>
                    <div class="value">{non_compliant_count}</div>
                </div>
                <div class="evidence-stat">
                    <div class="label">Not Applicable</div>
                    <div class="value" style="color: #718096;">{not_applicable_count}</div>
                </div>
            </div>
"""

        html_parts.append(f"""
        <div class="evidence-entry" id="{rule_anchor}">
            <div class="evidence-header">
                <div class="evidence-title">{source_name}</div>
                {description_html}
                <div class="evidence-rule" style="margin-top: 10px;">Rule: {escape_html(rule_name)}</div>
                <div class="evidence-rule">Keyword: {keyword_link}</div>
            </div>

            {stats_html}
""")

        # Resource table (only show in non-template mode)
        if not template_mode:
            html_parts.append("""
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%">Resource Type</th>
                        <th style="width: 35%">Resource ID</th>
                        <th style="width: 15%">Status</th>
                        <th style="width: 25%">Annotation</th>
                    </tr>
                </thead>
                <tbody>
""")

            # Sort resources: non-compliant first, then by resource type and ID
            resources = list(source.get("resources", {}).values())
            resources.sort(key=lambda r: (
                0 if r.get("complianceType") == "NON_COMPLIANT" else 1,
                r.get("resourceType", ""),
                r.get("resourceId", "")
            ))

            for resource in resources:
                resource_key = resource.get("resourceKey", "")
                resource_anchor = make_anchor_id(resource_key)
                resource_type = escape_html(resource.get("resourceType", ""))
                resource_id = escape_html(resource.get("resourceId", ""))
                compliance_type = resource.get("complianceType", "")
                annotation = escape_html(resource.get("annotation", "") or "")

                if len(annotation) > 100:
                    annotation = annotation[:100] + "..."

                if compliance_type == "COMPLIANT":
                    badge = '<span class="badge compliant">Compliant</span>'
                elif compliance_type == "NON_COMPLIANT":
                    badge = '<span class="badge non-compliant">Non-Compliant</span>'
                else:
                    badge = '<span class="badge not-applicable">N/A</span>'

                html_parts.append(f"""
                    <tr>
                        <td class="mono">{resource_type}</td>
                        <td class="mono"><a href="{prefix}_resources.html#{resource_anchor}">{resource_id}</a></td>
                        <td>{badge}</td>
                        <td style="font-size: 13px; color: #718096;">{annotation}</td>
                    </tr>
""")

            html_parts.append("""
                </tbody>
            </table>
""")

        html_parts.append("""
        </div>
""")

    html_parts.append("""
    </div>

    <div class="footer">
        Generated by AWS Compliance Reporting Workflow
    </div>
</body>
</html>
""")

    return "".join(html_parts)


def generate_resources_page(
    compliance_report: dict,
    configurations: dict,
    prefix: str
) -> str:
    """Generate the resources HTML page."""

    framework_name = compliance_report.get("frameworkName", "Unknown Framework")
    conformance_pack = compliance_report.get("conformancePackName", "Unknown")
    generated_at = compliance_report.get("reportGeneratedAt", "")

    # Get all configurations - handle both array format (resources) and dict format (configurations)
    if "configurations" in configurations:
        config_entries = configurations.get("configurations", {})
    elif "resources" in configurations:
        # Convert array to dict keyed by resourceKey
        config_entries = {}
        for resource in configurations.get("resources", []):
            resource_type = resource.get("resourceType", "")
            resource_id = resource.get("resourceId", "")
            resource_key = resource.get("resourceKey") or f"{resource_type}|{resource_id}"
            config_entries[resource_key] = {
                "resourceKey": resource_key,
                "resourceType": resource_type,
                "resourceId": resource_id,
                "configurationFound": resource.get("configurationFound", False),
                "configuration": resource.get("configuration")
            }
    else:
        config_entries = {}

    config_summary = configurations.get("summary", {})

    # Calculate stats from actual data if summary is incomplete
    total_resources = config_summary.get('totalResources') or len(config_entries)
    configs_retrieved = config_summary.get('configurationsRetrieved')
    configs_not_found = config_summary.get('configurationsNotFound')

    if configs_retrieved is None or configs_not_found is None:
        configs_retrieved = sum(1 for e in config_entries.values() if e.get("configurationFound"))
        configs_not_found = total_resources - configs_retrieved

    html_parts = []

    # HTML Header
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resources - {escape_html(framework_name)}</title>
    <style>
        {get_common_styles()}
    </style>
</head>
<body>
    {generate_navigation("resources", prefix)}
    {generate_page_header(framework_name, conformance_pack, generated_at)}

    <div class="summary-cards">
        <div class="card">
            <h3>Total Resources</h3>
            <div class="value">{total_resources}</div>
        </div>
        <div class="card compliant">
            <h3>Configs Retrieved</h3>
            <div class="value">{configs_retrieved}</div>
        </div>
        <div class="card">
            <h3>Configs Not Found</h3>
            <div class="value" style="color: #718096;">{configs_not_found}</div>
        </div>
    </div>

    <div class="section">
        <h2>Resource Configurations</h2>
        <p style="color: #718096; margin-bottom: 20px;">
            Configuration items for all evaluated resources.
        </p>
""")

    # Group resources by type
    resources_by_type = defaultdict(list)
    for resource_key, entry in config_entries.items():
        resource_type = entry.get("resourceType", "Unknown")
        resources_by_type[resource_type].append(entry)

    # Sort each group by resource ID
    for resource_type in resources_by_type:
        resources_by_type[resource_type].sort(key=lambda r: r.get("resourceId", ""))

    # Output resources grouped by type
    for resource_type in sorted(resources_by_type.keys()):
        entries = resources_by_type[resource_type]
        type_summary = config_summary.get("resourceTypes", {}).get(resource_type, {})
        total_count = type_summary.get("total") or len(entries)
        # Calculate found_count from actual data
        found_count = type_summary.get("configurationsFound")
        if found_count is None:
            found_count = sum(1 for e in entries if e.get("configurationFound"))

        html_parts.append(f"""
        <div class="control-set">
            <div class="control-set-header">
                <h3>{escape_html(resource_type)}</h3>
                <div class="stats">
                    {total_count} resources | {found_count} configurations found
                </div>
            </div>
""")

        for entry in entries:
            resource_key = entry.get("resourceKey", "")
            resource_anchor = make_anchor_id(resource_key)
            resource_id = escape_html(entry.get("resourceId", ""))
            config_found = entry.get("configurationFound", False)
            config_data = entry.get("configuration", {})

            html_parts.append(f"""
            <div class="resource-entry" id="{resource_anchor}">
                <div class="resource-header">
                    <div>
                        <div class="resource-title">{resource_id}</div>
                        <div class="resource-type">{escape_html(resource_type)}</div>
                    </div>
                    <div>
                        {"<span class='badge compliant'>Config Found</span>" if config_found else "<span class='badge not-applicable'>No Config</span>"}
                    </div>
                </div>
""")

            if config_found and config_data:
                # Show metadata
                arn = escape_html(config_data.get("arn", ""))
                region = escape_html(config_data.get("awsRegion", ""))
                captured = escape_html(config_data.get("configurationItemCaptureTime", ""))

                html_parts.append(f"""
                <div class="resource-meta">
                    <span><strong>ARN:</strong> {arn}</span>
                    <span><strong>Region:</strong> {region}</span>
                    <span><strong>Captured:</strong> {captured}</span>
                </div>
""")

                # Show configuration JSON
                config_json = config_data.get("configuration", {})
                if config_json:
                    formatted_json = json.dumps(config_json, indent=2, default=str)
                    html_parts.append(f"""
                <div class="config-block">
                    <pre>{escape_html(formatted_json)}</pre>
                </div>
""")

                # Show supplementary configuration if present
                supp_config = config_data.get("supplementaryConfiguration", {})
                if supp_config:
                    supp_json = json.dumps(supp_config, indent=2, default=str)
                    html_parts.append(f"""
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; color: #4a5568; font-weight: 500;">Supplementary Configuration</summary>
                    <div class="config-block" style="margin-top: 10px;">
                        <pre>{escape_html(supp_json)}</pre>
                    </div>
                </details>
""")

                # Show tags if present
                tags = config_data.get("tags", {})
                if tags:
                    html_parts.append("""
                <div style="margin-top: 15px;">
                    <strong style="color: #4a5568;">Tags:</strong>
                    <div style="margin-top: 8px;">
""")
                    for tag_key, tag_value in tags.items():
                        html_parts.append(f"""
                        <span style="display: inline-block; background: #edf2f7; padding: 4px 10px; border-radius: 4px; margin: 2px; font-size: 13px;">
                            <strong>{escape_html(tag_key)}:</strong> {escape_html(tag_value)}
                        </span>
""")
                    html_parts.append("""
                    </div>
                </div>
""")

            html_parts.append("""
            </div>
""")

        html_parts.append("""
        </div>
""")

    html_parts.append("""
    </div>

    <div class="footer">
        Generated by AWS Compliance Reporting Workflow
    </div>
</body>
</html>
""")

    return "".join(html_parts)


def main():
    parser = argparse.ArgumentParser(
        description="Generate multi-page HTML compliance report from JSON data"
    )
    parser.add_argument(
        "report_file",
        help="Path to compliance report JSON file (from generate_compliance_report.py)"
    )
    parser.add_argument(
        "configurations_file",
        nargs="?",
        help="Path to resource configurations JSON file (from get_resource_configurations.py)",
        default=None
    )
    parser.add_argument(
        "-o", "--output-prefix",
        help="Output file prefix (default: derived from report filename)",
        default=None
    )
    parser.add_argument(
        "--template-mode",
        action="store_true",
        help="Template mode: generate reports without resource configurations"
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.template_mode and not args.configurations_file:
        parser.error("configurations_file is required unless --template-mode is specified")

    try:
        # Load compliance report
        print(f"Loading compliance report: {args.report_file}")
        compliance_report = load_json_file(args.report_file)

        # Check if this is a template-mode report
        template_mode = args.template_mode or compliance_report.get("templateMode", False)

        # Load configurations (if not template mode)
        if template_mode:
            print("Running in template mode (no resource configurations)")
            configurations = {"configurations": {}}
        else:
            print(f"Loading resource configurations: {args.configurations_file}")
            configurations = load_json_file(args.configurations_file)

        # Determine output prefix
        output_prefix = args.output_prefix
        if not output_prefix:
            base_name = os.path.basename(args.report_file)
            output_prefix = base_name.rsplit(".", 1)[0]

        # Build evidence source data
        print("Building evidence source index...")
        evidence_sources = build_evidence_source_data(compliance_report)
        print(f"  Found {len(evidence_sources)} unique Config rules")

        # Generate pages
        print("Generating HTML pages...")

        # Use basename for HTML links (all files are in same directory)
        link_prefix = os.path.basename(output_prefix)
        gap_report_link = f"{link_prefix}_gaps.html"
        extra_rules_report_link = f"{link_prefix}_extra_rules.html"
        control_catalog_link = f"{link_prefix}_control_catalog.html"

        # Look up conformance pack templates for this framework using two-step CSV lookup
        matching_templates = []
        script_dir = os.path.dirname(os.path.abspath(__file__))
        framework_mapping_csv = os.path.join(script_dir, "conformance-packs", "Framework-to-conformance-pack-template-mapping.csv")
        templates_csv = os.path.join(script_dir, "conformance-packs", "Conformance pack templates.csv")
        yaml_folder = os.path.join(script_dir, "conformance-packs", "conformance-pack-yamls")

        if os.path.exists(framework_mapping_csv):
            framework_name = compliance_report.get("frameworkName", "")
            # Step 1: Load framework-to-template mapping
            framework_mapping = load_framework_template_mapping(framework_mapping_csv)
            template_name = find_matching_template(framework_name, framework_mapping)

            if template_name:
                # Step 2: Load template-to-YAML mapping
                templates_to_yaml = load_templates_to_yaml_mapping(templates_csv) if os.path.exists(templates_csv) else {}
                yaml_files = find_template_yaml_files(template_name, yaml_folder, templates_to_yaml)
                for name, path in yaml_files:
                    rule_count = count_config_rules_in_template(path)
                    # Store relative path for the hyperlink
                    rel_path = os.path.relpath(path, os.path.dirname(os.path.abspath(args.report_file)))
                    matching_templates.append((name, rule_count, rel_path))
                    print(f"  Template cross-check: {name} has {rule_count} rules")

        # Summary page
        summary_html = generate_summary_page(compliance_report, evidence_sources, link_prefix, gap_report_link, extra_rules_report_link, matching_templates, template_mode)
        summary_file = f"{output_prefix}_summary.html"
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write(summary_html)
        print(f"  Summary page: {summary_file}")

        # Evidence sources page
        evidence_html = generate_evidence_page(compliance_report, evidence_sources, link_prefix, control_catalog_link, template_mode)
        evidence_file = f"{output_prefix}_evidence.html"
        with open(evidence_file, "w", encoding="utf-8") as f:
            f.write(evidence_html)
        print(f"  Evidence sources page: {evidence_file}")

        # Resources page (skip in template mode)
        if template_mode:
            print(f"  Resources page: Skipped (template mode)")
            print(f"\nGenerated 2 HTML files with prefix: {output_prefix}")
        else:
            resources_html = generate_resources_page(compliance_report, configurations, link_prefix)
            resources_file = f"{output_prefix}_resources.html"
            with open(resources_file, "w", encoding="utf-8") as f:
                f.write(resources_html)
            print(f"  Resources page: {resources_file}")
            print(f"\nGenerated 3 HTML files with prefix: {output_prefix}")

        print(f"Open {summary_file} to start browsing the report.")

    except FileNotFoundError as e:
        print(f"Error: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
