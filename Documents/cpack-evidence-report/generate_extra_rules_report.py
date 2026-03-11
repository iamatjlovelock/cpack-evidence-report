#!/usr/bin/env python3
"""
Generate an HTML report of Config rules deployed in the conformance pack
but not referenced by the framework.
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


def get_rule_details(rule_names: list, region: str = None) -> dict:
    """
    Get details for Config rules from the AWS Config API.

    Args:
        rule_names: List of Config rule names
        region: AWS region (optional)

    Returns:
        Dict mapping rule name to rule details
    """
    if not rule_names:
        return {}

    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("config", **client_kwargs)
    rule_details = {}

    # Batch in groups of 25 (API limit)
    for i in range(0, len(rule_names), 25):
        batch = rule_names[i:i+25]
        try:
            response = client.describe_config_rules(ConfigRuleNames=batch)
            for rule in response.get("ConfigRules", []):
                rule_name = rule.get("ConfigRuleName")
                rule_details[rule_name] = {
                    "configRuleName": rule_name,
                    "description": rule.get("Description", ""),
                    "sourceIdentifier": rule.get("Source", {}).get("SourceIdentifier", ""),
                    "sourceOwner": rule.get("Source", {}).get("Owner", ""),
                    "configRuleArn": rule.get("ConfigRuleArn", ""),
                    "configRuleState": rule.get("ConfigRuleState", "")
                }
        except ClientError as e:
            print(f"Warning: Could not get details for some rules: {e}", file=sys.stderr)

    return rule_details


def generate_extra_rules_report_html(
    compliance_report: dict,
    rule_details: dict,
    summary_link: str = None
) -> str:
    """
    Generate HTML report for extra rules in conformance pack.

    Args:
        compliance_report: The compliance report data
        rule_details: Dict of rule details from AWS Config API
        summary_link: Link back to summary page (optional)

    Returns:
        HTML string
    """
    framework_name = escape_html(compliance_report.get("frameworkName", "Unknown Framework"))
    conformance_pack = escape_html(compliance_report.get("conformancePackName", "Unknown"))
    generated_at = escape_html(compliance_report.get("reportGeneratedAt", ""))

    extra_rules = compliance_report.get("conformancePackRulesNotInFramework", [])
    total_rules = len(extra_rules)

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
    <title>Extra Rules Report - {framework_name}</title>
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
            background: linear-gradient(135deg, #2c5282 0%, #4299e1 100%);
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
            color: #2c5282;
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
            color: #2c5282;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }}
        .rule-entry {{
            border-left: 4px solid #4299e1;
            padding: 15px;
            margin-bottom: 20px;
            background: #ebf8ff;
            border-radius: 0 8px 8px 0;
        }}
        .rule-entry h3 {{
            margin: 0 0 10px 0;
            color: #2c5282;
            font-size: 16px;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
        }}
        .rule-identifier {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 13px;
            color: #666;
            background: #edf2f7;
            padding: 2px 8px;
            border-radius: 4px;
        }}
        .rule-description {{
            color: #4a5568;
            margin: 10px 0;
            font-size: 14px;
        }}
        .rule-meta {{
            font-size: 13px;
            color: #718096;
            margin-top: 10px;
        }}
        .rule-meta span {{
            margin-right: 15px;
        }}
        .info-box {{
            background: #ebf8ff;
            border: 1px solid #90cdf4;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .info-box h3 {{
            margin: 0 0 10px 0;
            color: #2c5282;
            font-size: 16px;
        }}
        .info-box p {{
            margin: 0;
            color: #2a4365;
            font-size: 14px;
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
            .nav {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    {nav_html}
    <div class="report-header">
        <h1>Extra Rules Report</h1>
        <div class="meta">
            <div>Framework: {framework_name}</div>
            <div>Conformance Pack: {conformance_pack}</div>
            <div>Generated: {generated_at}</div>
        </div>
    </div>

    <div class="summary-cards">
        <div class="card">
            <h3>Extra Rules in Pack</h3>
            <div class="value">{total_rules}</div>
        </div>
    </div>

    <div class="info-box">
        <h3>What does this report show?</h3>
        <p>
            This report lists AWS Config rules that are deployed in the <strong>{conformance_pack}</strong> conformance pack
            but are not referenced by the {framework_name} framework.
            These rules provide additional compliance coverage beyond what the framework requires.
        </p>
    </div>

    <div class="section">
        <h2>Extra Config Rules ({total_rules})</h2>
"""

    # Sort rules alphabetically
    for rule_name in sorted(extra_rules):
        details = rule_details.get(rule_name, {})
        description = escape_html(details.get("description", "") or "No description available")
        source_identifier = escape_html(details.get("sourceIdentifier", ""))
        source_owner = escape_html(details.get("sourceOwner", ""))

        html_content += f"""
        <div class="rule-entry">
            <h3>{escape_html(rule_name)}</h3>
            <div><span class="rule-identifier">{source_identifier}</span></div>
            <div class="rule-description">{description}</div>
            <div class="rule-meta">
                <span><strong>Owner:</strong> {source_owner}</span>
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
        description="Generate report of Config rules in conformance pack but not in framework"
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

        # Get extra rules
        extra_rules = compliance_report.get("conformancePackRulesNotInFramework", [])
        print(f"  Found {len(extra_rules)} extra rules in conformance pack")

        # Get rule details from AWS Config API
        print("Fetching rule details from AWS Config...")
        rule_details = get_rule_details(extra_rules, args.region)
        print(f"  Retrieved details for {len(rule_details)} rules")

        # Generate HTML
        html_content = generate_extra_rules_report_html(
            compliance_report,
            rule_details,
            args.summary_link
        )

        if args.stdout:
            print(html_content)
        else:
            output_file = args.output
            if not output_file:
                base_name = args.report_file.rsplit(".", 1)[0]
                output_file = f"{base_name}_extra_rules.html"

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            print(f"Extra rules report written to: {output_file}")

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
