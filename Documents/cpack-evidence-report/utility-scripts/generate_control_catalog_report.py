#!/usr/bin/env python3
"""
Generate an HTML report of AWS Control Catalog information for all Config rules
referenced in the framework or deployed in the conformance pack.
"""

import argparse
import html
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


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
    result = ""
    for c in text:
        if c.isalnum():
            result += c
        else:
            result += "_"
    return result


def normalize_security_hub_rule(rule_name: str) -> str:
    """
    Normalize a Security Hub config rule name to a standard identifier.

    Example: securityhub-vpc-sg-restricted-common-ports-b67e7a27 -> VPC_SG_RESTRICTED_COMMON_PORTS
    """
    if not rule_name:
        return ""

    name = rule_name.lower()

    # Strip 'securityhub-' prefix
    if name.startswith("securityhub-"):
        name = name[12:]

    # Strip trailing hash (8 hex characters after last hyphen)
    if len(name) > 9 and name[-9] == '-':
        suffix = name[-8:]
        if all(c in '0123456789abcdef' for c in suffix):
            name = name[:-9]

    # Convert hyphens to underscores and uppercase
    name = name.replace('-', '_').upper()

    return name


def load_security_hub_controls(security_hub_file: str) -> dict:
    """
    Load Security Hub control metadata and create lookup by normalized identifier.

    Args:
        security_hub_file: Path to Security Hub standard JSON file

    Returns:
        Dict mapping normalized identifier to control metadata
    """
    if not security_hub_file:
        return {}

    try:
        with open(security_hub_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        controls = {}
        for ctrl in data.get("controls", []):
            config_rule = ctrl.get("config_rule", "")
            if config_rule and config_rule.startswith("securityhub-"):
                normalized_id = normalize_security_hub_rule(config_rule)
                if normalized_id:
                    controls[normalized_id] = {
                        "control_id": ctrl.get("control_id", ""),
                        "title": ctrl.get("title", ""),
                        "description": ctrl.get("description", ""),
                        "severity": ctrl.get("severity_rating", ""),
                        "status": ctrl.get("control_status", ""),
                        "remediation_url": ctrl.get("remediation_url", ""),
                        "related_requirements": ctrl.get("related_requirements", []),
                        "config_rule": config_rule
                    }
        return controls
    except Exception as e:
        print(f"Warning: Could not load Security Hub file: {e}")
        return {}


def get_all_rule_identifiers(compliance_report: dict) -> set:
    """
    Extract all unique Config rule identifiers from the compliance report.

    This includes:
    - Rules referenced in the framework (keywordValue) for AWS_Config sources
    - Normalized identifiers derived from Security Hub config rules
    - Rules deployed in the conformance pack but not in framework

    Returns:
        Set of rule identifiers (e.g., ACCESS_KEYS_ROTATED)
    """
    identifiers = set()

    # Get identifiers from framework evidence sources
    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                source_type = source.get("sourceType")

                if source_type == "AWS_Config":
                    keyword = source.get("keywordValue")
                    if keyword:
                        identifiers.add(keyword)

                elif source_type == "AWS_Security_Hub":
                    # For Security Hub sources, derive identifier from config rule name
                    config_rule = source.get("configRuleName")
                    if config_rule and config_rule.startswith("securityhub-"):
                        normalized = normalize_security_hub_rule(config_rule)
                        if normalized:
                            identifiers.add(normalized)

    # Get identifiers from extra rules in conformance pack
    # These are stored as rule names, we need to extract the identifier
    # For now, we'll fetch these from the Config API later

    return identifiers


def get_all_control_mappings(client) -> dict:
    """
    Fetch all control mappings using ListControlMappings API.

    Args:
        client: boto3 controlcatalog client

    Returns:
        Dict mapping control ARN to list of framework mappings
    """
    mappings_by_arn = {}

    try:
        paginator = client.get_paginator("list_control_mappings")

        for page in paginator.paginate(MaxResults=100):
            for mapping in page.get("ControlMappings", []):
                control_arn = mapping.get("ControlArn", "")
                if not control_arn:
                    continue

                mapping_type = mapping.get("MappingType", "")
                mapping_data = mapping.get("Mapping", {})

                # Extract framework info
                if mapping_type == "FRAMEWORK" and "Framework" in mapping_data:
                    framework = mapping_data["Framework"]
                    mapping_info = {
                        "frameworkName": framework.get("Name", ""),
                        "item": framework.get("Item", "")
                    }

                    if control_arn not in mappings_by_arn:
                        mappings_by_arn[control_arn] = []
                    mappings_by_arn[control_arn].append(mapping_info)

    except Exception as e:
        print(f"  Warning: Could not fetch control mappings: {e}")

    return mappings_by_arn


def get_control_catalog_details(rule_identifiers: set, region: str = None) -> dict:
    """
    Fetch detailed control information from AWS Control Catalog API.

    Args:
        rule_identifiers: Set of Config rule identifiers to look up
        region: AWS region (optional)

    Returns:
        Dict mapping identifier to control details
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("controlcatalog", **client_kwargs)

    controls = {}

    print("Fetching control details from AWS Control Catalog...")
    try:
        paginator = client.get_paginator("list_controls")

        for page in paginator.paginate(MaxResults=100):
            for control in page.get("Controls", []):
                impl = control.get("Implementation", {})
                impl_type = impl.get("Type", "")
                identifier = impl.get("Identifier", "")

                # Only include Config rules
                if impl_type == "AWS::Config::ConfigRule" and identifier:
                    # Handle Behavior - API returns string directly (e.g., "DETECTIVE")
                    behavior_val = control.get("Behavior")
                    behavior_type = str(behavior_val) if behavior_val else "N/A"

                    # Handle Severity - API returns string directly (e.g., "MEDIUM")
                    severity_val = control.get("Severity")
                    severity_value = str(severity_val) if severity_val else "N/A"

                    # Handle GovernedResources - list of resource types
                    governed_resources = control.get("GovernedResources", [])
                    if isinstance(governed_resources, list):
                        governed_resources_list = governed_resources
                    else:
                        governed_resources_list = [str(governed_resources)] if governed_resources else []

                    controls[identifier] = {
                        "arn": control.get("Arn", ""),
                        "name": control.get("Name", ""),
                        "description": control.get("Description", ""),
                        "behavior": behavior_type,
                        "severity": severity_value,
                        "governedResources": governed_resources_list,
                        "implementationType": impl_type,
                        "identifier": identifier
                    }

        print(f"  Found {len(controls)} Config rule controls in catalog")

        # Fetch all control mappings
        print("  Fetching control mappings...")
        all_mappings = get_all_control_mappings(client)
        print(f"  Found mappings for {len(all_mappings)} controls")

        # Associate mappings with our controls
        for identifier, control_data in controls.items():
            arn = control_data.get("arn", "")
            if arn and arn in all_mappings:
                controls[identifier]["mappings"] = all_mappings[arn]

    except Exception as e:
        print(f"  Warning: Could not fetch from Controls Catalog: {e}")

    return controls


def get_extra_rule_identifiers(extra_rule_names: list, region: str = None) -> dict:
    """
    Get the source identifiers for extra rules in the conformance pack.

    Args:
        extra_rule_names: List of Config rule names
        region: AWS region (optional)

    Returns:
        Dict mapping rule name to source identifier
    """
    if not extra_rule_names:
        return {}

    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("config", **client_kwargs)

    rule_to_identifier = {}

    # Batch in groups of 25
    for i in range(0, len(extra_rule_names), 25):
        batch = extra_rule_names[i:i+25]
        try:
            response = client.describe_config_rules(ConfigRuleNames=batch)
            for rule in response.get("ConfigRules", []):
                rule_name = rule.get("ConfigRuleName", "")
                source_id = rule.get("Source", {}).get("SourceIdentifier", "")
                if source_id:
                    rule_to_identifier[rule_name] = source_id
        except ClientError:
            pass

    return rule_to_identifier


def generate_control_catalog_html(
    compliance_report: dict,
    catalog_controls: dict,
    extra_rule_identifiers: dict,
    summary_link: str = None,
    link_prefix: str = None,
    template_mode: bool = False,
    security_hub_controls: dict = None
) -> str:
    """
    Generate HTML report for Control Catalog information.

    Args:
        compliance_report: The compliance report data
        catalog_controls: Dict of control details from Control Catalog
        extra_rule_identifiers: Dict mapping extra rule names to identifiers
        summary_link: Link back to summary page (optional)
        link_prefix: Prefix for navigation links (optional)
        template_mode: Whether running in template mode
        security_hub_controls: Dict mapping normalized identifier to Security Hub metadata

    Returns:
        HTML string
    """
    if security_hub_controls is None:
        security_hub_controls = {}
    framework_name = escape_html(compliance_report.get("frameworkName", "Unknown Framework"))
    conformance_pack = escape_html(compliance_report.get("conformancePackName", "Unknown"))
    generated_at = escape_html(compliance_report.get("reportGeneratedAt", ""))

    # Normalize framework name for matching against mappings
    # Extract key identifiers like "PCI DSS" and version from the full name
    raw_framework_name = compliance_report.get("frameworkName", "")
    # Normalize by removing punctuation and spaces for fuzzy matching
    current_framework_normalized = raw_framework_name.upper()
    for char in "-. ()":
        current_framework_normalized = current_framework_normalized.replace(char, "")

    # Collect all identifiers and track their sources
    all_identifiers = set()
    identifiers_in_framework = set()
    identifiers_in_template = set()
    identifiers_in_standard = set(security_hub_controls.keys()) if security_hub_controls else set()
    has_security_standard = bool(security_hub_controls)
    identifier_to_rule_names = {}  # Map identifier to set of config rule names

    # From framework - track both identifier and whether it's in the conformance pack
    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                source_type = source.get("sourceType")

                if source_type == "AWS_Config":
                    keyword = source.get("keywordValue")
                    config_rule_name = source.get("configRuleName")
                    if keyword:
                        all_identifiers.add(keyword)
                        identifiers_in_framework.add(keyword)
                        # Track config rule name if available and different from keyword
                        if config_rule_name and config_rule_name != keyword:
                            if keyword not in identifier_to_rule_names:
                                identifier_to_rule_names[keyword] = set()
                            identifier_to_rule_names[keyword].add(config_rule_name)
                        # Check if this rule is in the conformance pack/template
                        if source.get("inConformancePack", False):
                            identifiers_in_template.add(keyword)

                elif source_type == "AWS_Security_Hub":
                    # For Security Hub sources, derive identifier from config rule name
                    config_rule_name = source.get("configRuleName")
                    if config_rule_name and config_rule_name.startswith("securityhub-"):
                        normalized_id = normalize_security_hub_rule(config_rule_name)
                        if normalized_id:
                            all_identifiers.add(normalized_id)
                            identifiers_in_framework.add(normalized_id)
                            # Track the Security Hub control ID as an alias
                            keyword = source.get("keywordValue")
                            if keyword:
                                if normalized_id not in identifier_to_rule_names:
                                    identifier_to_rule_names[normalized_id] = set()
                                identifier_to_rule_names[normalized_id].add(f"Security Hub: {keyword}")

    # From extra rules (in template but not in framework)
    # extra_rule_identifiers maps rule name -> identifier
    for rule_name, identifier in extra_rule_identifiers.items():
        all_identifiers.add(identifier)
        identifiers_in_template.add(identifier)
        # Track the rule name if different from identifier
        if rule_name != identifier:
            if identifier not in identifier_to_rule_names:
                identifier_to_rule_names[identifier] = set()
            identifier_to_rule_names[identifier].add(rule_name)

    # Build control name lookup (item number -> control name)
    # Control names are like "2.2.1: System components are configured..."
    control_name_lookup = {}
    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            control_name = control.get("controlName", "")
            # Extract item number (e.g., "2.2.1" from "2.2.1: Description...")
            if ":" in control_name:
                item_num = control_name.split(":")[0].strip()
                control_name_lookup[item_num] = control_name

    # Helper function to check if a mapping is for the current framework
    def is_current_framework(m):
        fw = m.get("frameworkName", "").upper()
        for char in "-. ()":
            fw = fw.replace(char, "")
        return current_framework_normalized in fw or fw in current_framework_normalized

    # Count rules not mapped to this framework (in catalog but no mapping for current framework)
    not_mapped_count = 0
    for identifier in all_identifiers:
        if identifier in catalog_controls:
            control = catalog_controls.get(identifier, {})
            mappings = control.get("mappings", [])
            if not any(is_current_framework(m) for m in mappings):
                not_mapped_count += 1

    # Compute counts for summary
    total_rules = len(all_identifiers)
    in_catalog_count = len([i for i in all_identifiers if i in catalog_controls])
    not_in_catalog_count = len([i for i in all_identifiers if i not in catalog_controls])

    # Build navigation bar
    nav_html = ""
    if link_prefix:
        nav_items = [
            ("summary", "Summary Report"),
            ("evidence", "Evidence Sources"),
        ]
        if not template_mode:
            nav_items.append(("resources", "Resources"))
        nav_items.append(("control_catalog", "Control Catalog"))

        nav_links = []
        for page_id, page_name in nav_items:
            active_class = ' class="active"' if page_id == "control_catalog" else ""
            nav_links.append(f'<a href="{link_prefix}_{page_id}.html"{active_class}>{page_name}</a>')

        nav_html = f"""
    <nav class="nav">
        {" ".join(nav_links)}
    </nav>
"""
    elif summary_link:
        nav_html = f"""
    <nav class="nav">
        <a href="{summary_link}">&larr; Back to Summary Report</a>
    </nav>
"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Control Catalog - {framework_name}</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        a {{
            color: #2b6cb0;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .nav {{
            background: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .report-header {{
            background: linear-gradient(135deg, #553c9a 0%, #805ad5 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .report-header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        .report-header .meta {{
            opacity: 0.9;
            font-size: 14px;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            margin: 0 0 10px 0;
            font-size: 13px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #553c9a;
        }}
        .section {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            margin: 0 0 20px 0;
            color: #553c9a;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }}
        .control-entry {{
            border-left: 4px solid #805ad5;
            padding: 20px;
            margin-bottom: 25px;
            background: #faf5ff;
            border-radius: 0 8px 8px 0;
        }}
        .control-entry h3 {{
            margin: 0 0 5px 0;
            color: #553c9a;
            font-size: 18px;
        }}
        .control-identifier {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 14px;
            color: #805ad5;
            background: #e9d8fd;
            padding: 3px 10px;
            border-radius: 4px;
            display: inline-block;
            margin-bottom: 15px;
        }}
        .control-rule-names {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 12px;
            color: #4a5568;
            margin: 10px 0;
            padding: 8px 12px;
            background: #edf2f7;
            border-radius: 4px;
            word-break: break-all;
        }}
        .control-rule-names strong {{
            color: #2d3748;
        }}
        .control-description {{
            color: #4a5568;
            margin: 15px 0;
            font-size: 15px;
            line-height: 1.7;
        }}
        .control-arn {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 11px;
            color: #718096;
            margin: 10px 0 15px 0;
            word-break: break-all;
        }}
        .control-mappings {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e2e8f0;
        }}
        .mappings-label {{
            color: #718096;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }}
        .mappings-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .mapping-item {{
            background: white;
            padding: 10px 15px;
            border-radius: 6px;
            border: 1px solid #e9d8fd;
        }}
        .mapping-framework {{
            font-weight: 600;
            color: #553c9a;
            display: block;
            font-size: 13px;
        }}
        .mapping-detail {{
            color: #718096;
            font-size: 12px;
            margin-top: 3px;
            display: block;
        }}
        .mapping-item.current-framework {{
            background: #faf5ff;
            border: 2px solid #805ad5;
            box-shadow: 0 2px 4px rgba(128, 90, 213, 0.2);
        }}
        .mapping-item.current-framework .mapping-framework {{
            color: #553c9a;
        }}
        .other-frameworks {{
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 12px 15px;
            margin-top: 8px;
        }}
        .other-frameworks-label {{
            font-size: 12px;
            color: #718096;
            margin-bottom: 8px;
            font-weight: 500;
        }}
        .other-frameworks-list {{
            font-size: 12px;
            color: #4a5568;
            line-height: 1.8;
        }}
        .other-frameworks-list span {{
            display: inline-block;
            background: #edf2f7;
            padding: 2px 8px;
            border-radius: 4px;
            margin: 2px 4px 2px 0;
        }}
        .control-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e2e8f0;
        }}
        .meta-item {{
            font-size: 13px;
        }}
        .meta-item .label {{
            color: #718096;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }}
        .meta-item .value {{
            color: #2d3748;
            font-weight: 500;
            margin-top: 3px;
        }}
        .source-badges {{
            display: flex;
            gap: 8px;
            margin: 10px 0 15px 0;
            flex-wrap: wrap;
        }}
        .source-badge {{
            font-size: 12px;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 500;
        }}
        .badge-framework {{
            background: #ebf8ff;
            color: #2b6cb0;
            border: 1px solid #90cdf4;
        }}
        .badge-template {{
            background: #f0fff4;
            color: #276749;
            border: 1px solid #9ae6b4;
        }}
        .badge-standard {{
            background: #faf5ff;
            color: #553c9a;
            border: 1px solid #d6bcfa;
        }}
        .badge-not-in {{
            background: #fff5f5;
            color: #c53030;
            border: 1px solid #feb2b2;
        }}
        .badge-catalog {{
            background: #e6fffa;
            color: #234e52;
            border: 1px solid #81e6d9;
        }}
        .control-meta {{
            display: flex;
            gap: 10px;
            margin: 10px 0;
            flex-wrap: wrap;
            align-items: center;
        }}
        .badge-critical {{
            background: #fed7d7;
            color: #c53030;
        }}
        .badge-high {{
            background: #feebc8;
            color: #c05621;
        }}
        .badge-medium {{
            background: #fefcbf;
            color: #975a16;
        }}
        .badge-low {{
            background: #c6f6d5;
            color: #276749;
        }}
        .badge-compliant {{
            background: #c6f6d5;
            color: #276749;
        }}
        .badge-non-compliant {{
            background: #fed7d7;
            color: #c53030;
        }}
        .control-remediation {{
            margin-top: 15px;
        }}
        .control-remediation a {{
            color: #4299e1;
            text-decoration: none;
        }}
        .control-remediation a:hover {{
            text-decoration: underline;
        }}
        .info-box {{
            background: #faf5ff;
            border: 1px solid #d6bcfa;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .info-box h3 {{
            margin: 0 0 10px 0;
            color: #553c9a;
            font-size: 16px;
        }}
        .info-box p {{
            margin: 0;
            color: #44337a;
            font-size: 14px;
        }}
        .warning-box {{
            background: #fffaf0;
            border: 1px solid #ed8936;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .warning-box h3 {{
            margin: 0 0 10px 0;
            color: #c05621;
            font-size: 16px;
        }}
        .warning-box p {{
            margin: 0;
            color: #744210;
            font-size: 14px;
        }}
        .toc {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .toc h3 {{
            margin: 0 0 15px 0;
            color: #553c9a;
        }}
        .toc-list {{
            column-count: 3;
            column-gap: 20px;
        }}
        .toc-list a {{
            display: block;
            padding: 3px 0;
            font-size: 13px;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
        }}
        .toc-list a.not-in-catalog {{
            color: #c53030;
        }}
        .toc-list a.not-mapped {{
            color: #805ad5;
        }}
        .toc-list a.mapped {{
            color: #38a169;
        }}
        @media (max-width: 900px) {{
            .toc-list {{
                column-count: 2;
            }}
        }}
        @media (max-width: 600px) {{
            .toc-list {{
                column-count: 1;
            }}
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #718096;
            font-size: 13px;
        }}
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .nav, .toc {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    {nav_html}
    <div class="report-header">
        <h1>Control Catalog Report</h1>
        <div class="meta">
            <div>Framework: {framework_name}</div>
            <div>Conformance Pack: {conformance_pack}</div>
            <div>Generated: {generated_at}</div>
        </div>
    </div>

    <div class="summary-cards">
        <div class="card">
            <h3>Total Rules</h3>
            <div class="value">{total_rules}</div>
        </div>
        <div class="card">
            <h3>In Catalog</h3>
            <div class="value">{in_catalog_count}</div>
        </div>
        <div class="card">
            <h3>Not In Catalog</h3>
            <div class="value">{not_in_catalog_count}</div>
        </div>
        <div class="card">
            <h3>Not Mapped to Framework</h3>
            <div class="value">{not_mapped_count}</div>
        </div>
    </div>

    <div class="info-box">
        <h3>What does this report show?</h3>
        <p>
            The AWS Control Catalog is a centralized repository of AWS-managed controls that provides detailed information
            about each Config rule, including its description, severity, behavior, and which compliance frameworks reference it.
            This report cross-references all Config rules from the selected Audit Manager framework and conformance pack
            against the Control Catalog to show you comprehensive details about each rule.
        </p>
        <p style="margin-top: 10px;">
            <strong>Summary:</strong> There are <strong>{total_rules}</strong> unique rules referenced in the framework
            and/or conformance pack. Of these, <strong>{in_catalog_count}</strong> have entries in the Control Catalog
            and <strong>{not_in_catalog_count}</strong> do not. Of the rules in the catalog,
            <strong>{not_mapped_count}</strong> are not mapped to this specific framework by AWS.
        </p>
        <p style="margin-top: 10px;">
            <strong>How to use this report:</strong> Use the Quick Navigation below to jump to any rule. Each entry shows
            the rule's description, ARN, severity level, and a list of all compliance frameworks that reference it
            according to AWS Control Catalog. Rules highlighted in green are mapped to the current framework,
            purple rules are in the catalog but mapped to other frameworks, and red rules are not found in the Control Catalog.
        </p>
    </div>

    <div class="toc">
        <h3>Quick Navigation</h3>
        <p style="font-size: 13px; color: #718096; margin: 0 0 15px 0;">
            Entries in Control Catalog that reference the framework are shown in <span style="color: #38a169; font-weight: 600;">green</span>.
            Entries in Control Catalog that do not reference the framework are shown in <span style="color: #805ad5; font-weight: 600;">purple</span>.
            Rules without an entry in Control Catalog are shown in <span style="color: #c53030; font-weight: 600;">Red</span>.
        </p>
        <div class="toc-list">
"""

    # Add table of contents with color coding
    for identifier in sorted(all_identifiers):
        anchor = make_anchor_id(identifier)
        if identifier not in catalog_controls:
            # Red - not in catalog
            html_content += f'            <a href="#{anchor}" class="not-in-catalog">{escape_html(identifier)}</a>\n'
        else:
            control = catalog_controls.get(identifier, {})
            mappings = control.get("mappings", [])
            if any(is_current_framework(m) for m in mappings):
                # Green - in catalog and mapped to this framework
                html_content += f'            <a href="#{anchor}" class="mapped">{escape_html(identifier)}</a>\n'
            else:
                # Orange - in catalog but not mapped to this framework
                html_content += f'            <a href="#{anchor}" class="not-mapped">{escape_html(identifier)}</a>\n'

    html_content += """
        </div>
    </div>
"""

    # Check if any controls have current framework mappings
    has_current_framework_mappings = False
    for identifier in all_identifiers:
        control = catalog_controls.get(identifier, {})
        mappings = control.get("mappings", [])
        if any(is_current_framework(m) for m in mappings):
            has_current_framework_mappings = True
            break

    # Show warning if no current framework mappings found
    if not has_current_framework_mappings:
        html_content += f"""
    <div class="warning-box">
        <h3>Framework Not in Control Catalog Mappings</h3>
        <p>
            The AWS Control Catalog does not include control mappings for the <strong>{framework_name}</strong> framework.
            The Control Catalog currently provides framework mappings for select compliance standards such as PCI-DSS, NIST, ISO 27001, and FedRAMP.
            While detailed rule information is shown below, specific control mappings for this framework are not available from the Control Catalog API.
        </p>
    </div>
"""

    html_content += """
    <div class="section">
        <h2>Config Rule Details</h2>
"""

    # Add control entries
    for identifier in sorted(all_identifiers):
        anchor = make_anchor_id(identifier)
        control = catalog_controls.get(identifier, {})

        if control:
            name = escape_html(control.get("name", identifier))
            description = escape_html(control.get("description", "No description available"))
            behavior = escape_html(control.get("behavior", "N/A"))
            severity = escape_html(control.get("severity", "N/A")) or "N/A"
            governed_resources = control.get("governedResources", [])
            governed_resources_html = ", ".join([escape_html(r) for r in governed_resources]) if governed_resources else "N/A"
            arn = escape_html(control.get("arn", ""))
            mappings = control.get("mappings", [])

            # Check if mapped to current framework
            current_mappings = [m for m in mappings if is_current_framework(m)]
            other_mappings = [m for m in mappings if not is_current_framework(m)]
            entry_class = "control-entry"

            # Build mappings HTML
            mappings_html = ""
            if mappings:

                mappings_html = """
            <div class="control-mappings">
                <div class="mappings-label">Control Mappings</div>
                <div class="mappings-list">
"""
                # Show current framework mappings as individual cards
                if current_mappings:
                    for mapping in current_mappings:
                        framework_name_val = escape_html(mapping.get("frameworkName", ""))
                        item_raw = mapping.get("item", "")
                        item = escape_html(item_raw)
                        # Look up the full control name
                        control_name_full = control_name_lookup.get(item_raw, "")
                        if control_name_full:
                            control_display = escape_html(control_name_full)
                        else:
                            control_display = item
                        if framework_name_val:
                            mappings_html += f"""
                    <div class="mapping-item current-framework">
                        <span class="mapping-framework">{framework_name_val}</span>
                        <span class="mapping-detail">{control_display}</span>
                    </div>
"""
                else:
                    # No mapping for current framework
                    mappings_html += f"""
                    <div class="mapping-item" style="background: #fff5f5; border: 1px solid #feb2b2;">
                        <span class="mapping-detail" style="color: #c53030;">Control Catalog does not contain mapping for {framework_name}</span>
                    </div>
"""
                # Show other frameworks as a single grouped list
                if other_mappings:
                    # Get unique framework names
                    other_framework_names = sorted(set(m.get("frameworkName", "") for m in other_mappings if m.get("frameworkName")))
                    if other_framework_names:
                        frameworks_spans = "".join(f"<span>{escape_html(fw)}</span>" for fw in other_framework_names)
                        mappings_html += f"""
                    <div class="other-frameworks">
                        <div class="other-frameworks-label">Other Frameworks</div>
                        <div class="other-frameworks-list">{frameworks_spans}</div>
                    </div>
"""
                mappings_html += """
                </div>
            </div>
"""

                # Build source badges HTML
            in_framework = identifier in identifiers_in_framework
            in_template = identifier in identifiers_in_template
            in_standard = identifier in identifiers_in_standard
            badges_html = '<div class="source-badges">'
            badges_html += '<span class="source-badge badge-catalog">In Control Catalog</span>'
            if in_framework:
                badges_html += '<span class="source-badge badge-framework">In Framework</span>'
            else:
                badges_html += '<span class="source-badge badge-not-in">Not in Framework</span>'
            if in_template:
                badges_html += '<span class="source-badge badge-template">In Conformance Pack Template</span>'
            else:
                badges_html += '<span class="source-badge badge-not-in">Not in Conformance Pack Template</span>'
            if has_security_standard:
                if in_standard:
                    badges_html += '<span class="source-badge badge-standard">In Security Standard</span>'
                else:
                    badges_html += '<span class="source-badge badge-not-in">Not in Security Standard</span>'
            badges_html += '</div>'

            # Build config rule names HTML if available
            rule_names = identifier_to_rule_names.get(identifier, set())
            rule_names_html = ""
            if rule_names:
                rule_names_list = ", ".join(sorted(escape_html(rn) for rn in rule_names))
                rule_names_html = f'<div class="control-rule-names"><strong>Config Rule Name(s):</strong> {rule_names_list}</div>'

            html_content += f"""
        <div class="{entry_class}" id="{anchor}">
            <h3>{name}</h3>
            <div class="control-identifier">{escape_html(identifier)}</div>
            {badges_html}
            {rule_names_html}
            <div class="control-description">{description}</div>
            <div class="control-arn">ARN: {arn}</div>
            <div class="control-meta">
                <div class="meta-item">
                    <div class="label">Severity</div>
                    <div class="value">{severity}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Behavior</div>
                    <div class="value">{behavior}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Governed Resources</div>
                    <div class="value" style="font-size: 12px;">{governed_resources_html}</div>
                </div>
            </div>
            {mappings_html}
        </div>
"""
        else:
            # Build source badges HTML for not-in-catalog entries
            in_framework = identifier in identifiers_in_framework
            in_template = identifier in identifiers_in_template
            in_standard = identifier in identifiers_in_standard
            badges_html = '<div class="source-badges">'
            badges_html += '<span class="source-badge badge-not-in">Not in Control Catalog</span>'
            if in_framework:
                badges_html += '<span class="source-badge badge-framework">In Framework</span>'
            else:
                badges_html += '<span class="source-badge badge-not-in">Not in Framework</span>'
            if in_template:
                badges_html += '<span class="source-badge badge-template">In Conformance Pack Template</span>'
            else:
                badges_html += '<span class="source-badge badge-not-in">Not in Conformance Pack Template</span>'
            if has_security_standard:
                if in_standard:
                    badges_html += '<span class="source-badge badge-standard">In Security Standard</span>'
                else:
                    badges_html += '<span class="source-badge badge-not-in">Not in Security Standard</span>'
            badges_html += '</div>'

            # Build config rule names HTML if available
            rule_names = identifier_to_rule_names.get(identifier, set())
            rule_names_html = ""
            if rule_names:
                rule_names_list = ", ".join(sorted(escape_html(rn) for rn in rule_names))
                rule_names_html = f'<div class="control-rule-names"><strong>Config Rule Name(s):</strong> {rule_names_list}</div>'

            # Check if this is a Security Hub-derived identifier with metadata
            sh_control = security_hub_controls.get(identifier, {})
            if sh_control:
                # Use Security Hub metadata
                sh_title = escape_html(sh_control.get("title", identifier))
                sh_description = escape_html(sh_control.get("description", ""))
                sh_severity = escape_html(sh_control.get("severity", ""))
                sh_status = escape_html(sh_control.get("status", ""))
                sh_control_id = escape_html(sh_control.get("control_id", ""))
                sh_remediation = sh_control.get("remediation_url", "")

                # Build severity badge
                severity_class = sh_severity.lower() if sh_severity else ""
                severity_badge = f'<span class="badge badge-{severity_class}">{sh_severity}</span>' if sh_severity else ""

                # Build status badge
                status_class = "compliant" if sh_status == "ENABLED" else "non-compliant"
                status_badge = f'<span class="badge badge-{status_class}">{sh_status}</span>' if sh_status else ""

                # Build remediation link
                remediation_html = ""
                if sh_remediation:
                    remediation_html = f'<div class="control-remediation"><a href="{escape_html(sh_remediation)}" target="_blank">Remediation Guide</a></div>'

                html_content += f"""
        <div class="control-entry" id="{anchor}">
            <h3>{sh_title}</h3>
            <div class="control-identifier">{escape_html(identifier)}</div>
            <div class="control-meta">
                <span class="source-badge" style="background: #e9d8fd; color: #553c9a;">Security Hub: {sh_control_id}</span>
                {severity_badge}
                {status_badge}
            </div>
            {badges_html}
            {rule_names_html}
            <div class="control-description">
                {sh_description}
            </div>
            {remediation_html}
        </div>
"""
            else:
                html_content += f"""
        <div class="control-entry" id="{anchor}">
            <h3>{escape_html(identifier)}</h3>
            <div class="control-identifier">{escape_html(identifier)}</div>
            {badges_html}
            {rule_names_html}
            <div class="control-description">
                This rule identifier was not found in the AWS Control Catalog.
                It may be a custom rule or a rule that has been deprecated.
            </div>
        </div>
"""

    html_content += """
    </div>

    <div class="footer">
        Generated by AWS Compliance Reporting Workflow
    </div>
</body>
</html>
"""

    return html_content


def main():
    parser = argparse.ArgumentParser(
        description="Generate Control Catalog report for Config rules"
    )
    parser.add_argument(
        "report_file",
        help="Path to compliance report JSON file"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output HTML file path",
        default=None
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region (uses default region if not specified)",
        default=None
    )
    parser.add_argument(
        "--summary-link",
        help="Link back to summary page (used if --link-prefix not provided)",
        default=None
    )
    parser.add_argument(
        "--link-prefix",
        help="Prefix for navigation links (enables full navigation bar)",
        default=None
    )
    parser.add_argument(
        "--catalog-file",
        help="Path to Control Catalog JSON file (output when fetching, input when using --skip-fetch)",
        default=None
    )
    parser.add_argument(
        "--skip-fetch",
        action="store_true",
        help="Skip fetching from Control Catalog API and use existing --catalog-file"
    )
    parser.add_argument(
        "--security-hub-file",
        help="Path to Security Hub standard JSON file (for Security Hub control metadata)",
        default=None
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print HTML to stdout instead of file"
    )

    args = parser.parse_args()

    # Validate skip-fetch requires catalog-file
    if args.skip_fetch and not args.catalog_file:
        parser.error("--catalog-file is required when using --skip-fetch")

    try:
        # Load compliance report
        print(f"Loading compliance report: {args.report_file}")
        compliance_report = load_json_file(args.report_file)

        # Determine catalog file path
        if args.catalog_file:
            catalog_file = args.catalog_file
        else:
            # Default to same directory as report file
            base_name = args.report_file.rsplit(".", 1)[0]
            catalog_file = f"{base_name}_control_catalog.json"

        if args.skip_fetch:
            # Load existing Control Catalog data
            print(f"Loading Control Catalog data: {catalog_file}")
            catalog_data = load_json_file(catalog_file)
            catalog_controls = catalog_data.get("controls", {})
            print(f"  Loaded {len(catalog_controls)} controls from catalog file")

            # Get extra rule identifiers - may need to compute if not in cached file
            extra_rule_identifiers = catalog_data.get("extraRuleIdentifiers", {})
            if not extra_rule_identifiers:
                # Global catalog doesn't have extraRuleIdentifiers, compute from compliance report
                extra_rules = compliance_report.get("conformancePackRulesNotInFramework", [])
                template_mode = compliance_report.get("templateMode", False)
                if extra_rules:
                    if template_mode:
                        # In template mode, extra_rules already contains identifiers
                        print(f"  Found {len(extra_rules)} extra rule identifiers in template")
                        extra_rule_identifiers = {rule: rule for rule in extra_rules}
                    else:
                        # In normal mode, extra_rules contains rule names - look up identifiers
                        print(f"  Looking up identifiers for {len(extra_rules)} extra rules...")
                        extra_rule_identifiers = get_extra_rule_identifiers(extra_rules, args.region)
                        print(f"  Found identifiers for {len(extra_rule_identifiers)} extra rules")
        else:
            # Get all rule identifiers from framework
            framework_identifiers = get_all_rule_identifiers(compliance_report)
            print(f"  Found {len(framework_identifiers)} unique rule identifiers in framework")

            # Get identifiers for extra rules in conformance pack/template
            extra_rules = compliance_report.get("conformancePackRulesNotInFramework", [])
            extra_rule_identifiers = {}
            template_mode = compliance_report.get("templateMode", False)

            if extra_rules:
                if template_mode:
                    # In template mode, extra_rules already contains identifiers
                    print(f"  Found {len(extra_rules)} extra rule identifiers in template")
                    extra_rule_identifiers = {rule: rule for rule in extra_rules}
                else:
                    # In normal mode, extra_rules contains rule names - look up identifiers
                    print(f"  Looking up identifiers for {len(extra_rules)} extra rules...")
                    extra_rule_identifiers = get_extra_rule_identifiers(extra_rules, args.region)
                    print(f"  Found identifiers for {len(extra_rule_identifiers)} extra rules")

            # Get Control Catalog details
            catalog_controls = get_control_catalog_details(
                framework_identifiers | set(extra_rule_identifiers.values()),
                args.region
            )

            # Save Control Catalog data to JSON
            catalog_data = {
                "generatedAt": compliance_report.get("reportGeneratedAt", ""),
                "frameworkName": compliance_report.get("frameworkName", ""),
                "conformancePackName": compliance_report.get("conformancePackName", ""),
                "controls": catalog_controls,
                "extraRuleIdentifiers": extra_rule_identifiers
            }
            with open(catalog_file, "w", encoding="utf-8") as f:
                json.dump(catalog_data, f, indent=2)
            print(f"Control Catalog data written to: {catalog_file}")

        # Load Security Hub controls if file provided
        security_hub_controls = {}
        if args.security_hub_file:
            print(f"Loading Security Hub controls: {args.security_hub_file}")
            security_hub_controls = load_security_hub_controls(args.security_hub_file)
            print(f"  Loaded {len(security_hub_controls)} Security Hub control mappings")

        # Generate HTML
        template_mode = compliance_report.get("templateMode", False)
        html_content = generate_control_catalog_html(
            compliance_report,
            catalog_controls,
            extra_rule_identifiers,
            args.summary_link,
            args.link_prefix,
            template_mode,
            security_hub_controls
        )

        if args.stdout:
            print(html_content)
        else:
            output_file = args.output
            if not output_file:
                base_name = args.report_file.rsplit(".", 1)[0]
                output_file = f"{base_name}_control_catalog.html"

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            print(f"Control catalog report written to: {output_file}")

    except FileNotFoundError as e:
        print(f"Error: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except NoCredentialsError:
        print("Error: AWS credentials not found. Please configure your AWS credentials.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
