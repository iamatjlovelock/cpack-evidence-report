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


def get_all_rule_identifiers(compliance_report: dict) -> set:
    """
    Extract all unique Config rule identifiers from the compliance report.

    This includes:
    - Rules referenced in the framework (keywordValue)
    - Rules deployed in the conformance pack but not in framework

    Returns:
        Set of rule identifiers (e.g., ACCESS_KEYS_ROTATED)
    """
    identifiers = set()

    # Get identifiers from framework evidence sources
    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") == "AWS_Config":
                    keyword = source.get("keywordValue")
                    if keyword:
                        identifiers.add(keyword)

    # Get identifiers from extra rules in conformance pack
    # These are stored as rule names, we need to extract the identifier
    # For now, we'll fetch these from the Config API later

    return identifiers


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
                    controls[identifier] = {
                        "arn": control.get("Arn", ""),
                        "name": control.get("Name", ""),
                        "description": control.get("Description", ""),
                        "behavior": control.get("Behavior", {}).get("Type", ""),
                        "regionConfiguration": control.get("RegionConfiguration", {}).get("Scope", ""),
                        "implementationType": impl_type,
                        "identifier": identifier
                    }

        print(f"  Found {len(controls)} Config rule controls in catalog")

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
    summary_link: str = None
) -> str:
    """
    Generate HTML report for Control Catalog information.

    Args:
        compliance_report: The compliance report data
        catalog_controls: Dict of control details from Control Catalog
        extra_rule_identifiers: Dict mapping extra rule names to identifiers
        summary_link: Link back to summary page (optional)

    Returns:
        HTML string
    """
    framework_name = escape_html(compliance_report.get("frameworkName", "Unknown Framework"))
    conformance_pack = escape_html(compliance_report.get("conformancePackName", "Unknown"))
    generated_at = escape_html(compliance_report.get("reportGeneratedAt", ""))

    # Collect all identifiers we need
    all_identifiers = set()

    # From framework
    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") == "AWS_Config":
                    keyword = source.get("keywordValue")
                    if keyword:
                        all_identifiers.add(keyword)

    # From extra rules
    for identifier in extra_rule_identifiers.values():
        all_identifiers.add(identifier)

    # Build navigation
    nav_html = ""
    if summary_link:
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
        .control-description {{
            color: #4a5568;
            margin: 15px 0;
            font-size: 15px;
            line-height: 1.7;
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
        .not-in-catalog {{
            background: #fff5f5;
            border-left-color: #fc8181;
        }}
        .not-in-catalog h3 {{
            color: #c53030;
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
            <div class="value">{len(all_identifiers)}</div>
        </div>
        <div class="card">
            <h3>In Catalog</h3>
            <div class="value">{len([i for i in all_identifiers if i in catalog_controls])}</div>
        </div>
        <div class="card">
            <h3>Not In Catalog</h3>
            <div class="value">{len([i for i in all_identifiers if i not in catalog_controls])}</div>
        </div>
    </div>

    <div class="info-box">
        <h3>What does this report show?</h3>
        <p>
            This report contains detailed information from the AWS Control Catalog for each Config rule
            referenced in the {framework_name} framework or deployed in the <strong>{conformance_pack}</strong>
            conformance pack. The Control Catalog provides authoritative descriptions and metadata for AWS managed rules.
        </p>
    </div>

    <div class="toc">
        <h3>Quick Navigation</h3>
        <div class="toc-list">
"""

    # Add table of contents
    for identifier in sorted(all_identifiers):
        anchor = make_anchor_id(identifier)
        html_content += f'            <a href="#{anchor}">{escape_html(identifier)}</a>\n'

    html_content += """
        </div>
    </div>

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
            region_config = escape_html(control.get("regionConfiguration", "N/A"))
            arn = escape_html(control.get("arn", ""))

            html_content += f"""
        <div class="control-entry" id="{anchor}">
            <h3>{name}</h3>
            <div class="control-identifier">{escape_html(identifier)}</div>
            <div class="control-description">{description}</div>
            <div class="control-meta">
                <div class="meta-item">
                    <div class="label">Behavior</div>
                    <div class="value">{behavior}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Region Scope</div>
                    <div class="value">{region_config}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Control ARN</div>
                    <div class="value" style="font-size: 11px; word-break: break-all;">{arn}</div>
                </div>
            </div>
        </div>
"""
        else:
            html_content += f"""
        <div class="control-entry not-in-catalog" id="{anchor}">
            <h3>{escape_html(identifier)}</h3>
            <div class="control-identifier">{escape_html(identifier)}</div>
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
        help="Link back to summary page",
        default=None
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print HTML to stdout instead of file"
    )

    args = parser.parse_args()

    try:
        # Load compliance report
        print(f"Loading compliance report: {args.report_file}")
        compliance_report = load_json_file(args.report_file)

        # Get all rule identifiers from framework
        framework_identifiers = get_all_rule_identifiers(compliance_report)
        print(f"  Found {len(framework_identifiers)} unique rule identifiers in framework")

        # Get identifiers for extra rules in conformance pack
        extra_rule_names = compliance_report.get("conformancePackRulesNotInFramework", [])
        extra_rule_identifiers = {}
        if extra_rule_names:
            print(f"  Looking up identifiers for {len(extra_rule_names)} extra rules...")
            extra_rule_identifiers = get_extra_rule_identifiers(extra_rule_names, args.region)
            print(f"  Found identifiers for {len(extra_rule_identifiers)} extra rules")

        # Get Control Catalog details
        catalog_controls = get_control_catalog_details(
            framework_identifiers | set(extra_rule_identifiers.values()),
            args.region
        )

        # Generate HTML
        html_content = generate_control_catalog_html(
            compliance_report,
            catalog_controls,
            extra_rule_identifiers,
            args.summary_link
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
