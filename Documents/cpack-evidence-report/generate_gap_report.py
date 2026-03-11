#!/usr/bin/env python3
"""
Generate an HTML report of Config rules referenced in the framework
but not deployed in the conformance pack.
"""

import argparse
import html
import json
import os
import sys
from collections import defaultdict


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


def extract_unmapped_sources(compliance_report: dict) -> list:
    """
    Extract evidence sources that are not mapped to the conformance pack.

    Returns:
        List of unmapped evidence sources with control context
    """
    unmapped = []

    for control_set in compliance_report.get("controlSets", []):
        control_set_name = control_set.get("controlSetName", "")

        for control in control_set.get("controls", []):
            control_name = control.get("controlName", "")
            control_id = control.get("controlId", "")

            for source in control.get("evidenceSources", []):
                # Only include AWS_Config sources that are NOT in the conformance pack
                if source.get("sourceType") == "AWS_Config" and not source.get("inConformancePack", False):
                    unmapped.append({
                        "controlSetName": control_set_name,
                        "controlName": control_name,
                        "controlId": control_id,
                        "sourceName": source.get("sourceName"),
                        "sourceDescription": source.get("sourceDescription"),
                        "keywordValue": source.get("keywordValue"),
                        "configRuleName": source.get("configRuleName")
                    })

    return unmapped


def generate_gap_report_html(
    compliance_report: dict,
    unmapped_sources: list,
    summary_link: str = None,
    control_catalog_link: str = None,
    catalog_controls: dict = None
) -> str:
    """
    Generate HTML gap report.

    Args:
        compliance_report: The compliance report data
        unmapped_sources: List of unmapped evidence sources
        summary_link: Link back to summary page (optional)
        control_catalog_link: Link to control catalog report (optional)
        catalog_controls: Dict of control details from Control Catalog (optional)

    Returns:
        HTML string
    """
    framework_name = escape_html(compliance_report.get("frameworkName", "Unknown Framework"))
    conformance_pack = escape_html(compliance_report.get("conformancePackName", "Unknown"))
    generated_at = escape_html(compliance_report.get("reportGeneratedAt", ""))

    # Group by keyword value to show unique rules
    by_keyword = defaultdict(list)
    for source in unmapped_sources:
        keyword = source.get("keywordValue", "Unknown")
        by_keyword[keyword].append(source)

    unique_rules = len(by_keyword)
    total_references = len(unmapped_sources)

    # Build navigation
    nav_html = ""
    if summary_link:
        nav_html = f"""
    <nav class="nav">
        <a href="{summary_link}">← Back to Summary Report</a>
    </nav>
"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gap Analysis - {framework_name}</title>
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
            background: linear-gradient(135deg, #744210 0%, #975a16 100%);
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
            color: #744210;
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
            color: #744210;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }}
        .rule-entry {{
            border-left: 4px solid #ed8936;
            padding: 15px;
            margin-bottom: 20px;
            background: #fffaf0;
            border-radius: 0 8px 8px 0;
        }}
        .rule-entry h3 {{
            margin: 0 0 10px 0;
            color: #744210;
            font-size: 16px;
        }}
        .rule-keyword {{
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
        .controls-list {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e2e8f0;
        }}
        .controls-list h4 {{
            margin: 0 0 10px 0;
            font-size: 13px;
            color: #666;
            text-transform: uppercase;
        }}
        .control-item {{
            padding: 8px 12px;
            background: white;
            border-radius: 6px;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        .control-set {{
            font-size: 12px;
            color: #718096;
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
        <h1>Gap Analysis Report</h1>
        <div class="meta">
            <div>Framework: {framework_name}</div>
            <div>Conformance Pack: {conformance_pack}</div>
            <div>Generated: {generated_at}</div>
        </div>
    </div>

    <div class="summary-cards">
        <div class="card">
            <h3>Unmapped Rules</h3>
            <div class="value">{unique_rules}</div>
        </div>
        <div class="card">
            <h3>Total References</h3>
            <div class="value">{total_references}</div>
        </div>
    </div>

    <div class="info-box">
        <h3>What does this report show?</h3>
        <p>
            This report lists AWS Config rules that are referenced by the {framework_name} framework
            but are not deployed as part of the <strong>{conformance_pack}</strong> conformance pack.
            These rules cannot be evaluated for compliance until they are added to the conformance pack
            or deployed separately in your account.
        </p>
    </div>

    <div class="section">
        <h2>Unmapped Config Rules ({unique_rules})</h2>
"""

    # Sort by keyword
    for keyword in sorted(by_keyword.keys()):
        sources = by_keyword[keyword]
        first_source = sources[0]
        source_name = escape_html(first_source.get("sourceName", ""))

        # Get description from Control Catalog if available, otherwise use framework source
        if catalog_controls and keyword in catalog_controls:
            description = escape_html(catalog_controls[keyword].get("description", "") or "No description available")
        else:
            description = escape_html(first_source.get("sourceDescription", "") or "No description available")

        # Build link to control catalog
        keyword_anchor = make_anchor_id(keyword)
        keyword_display = escape_html(keyword)
        if control_catalog_link:
            keyword_display = f'<a href="{control_catalog_link}#{keyword_anchor}">{keyword_display}</a>'

        html_content += f"""
        <div class="rule-entry" id="{keyword_anchor}">
            <h3>{source_name}</h3>
            <div><span class="rule-keyword">{keyword_display}</span></div>
            <div class="rule-description">{description}</div>
            <div class="controls-list">
                <h4>Referenced by {len(sources)} control(s):</h4>
"""
        # Show controls that reference this rule
        for source in sources:
            control_name = escape_html(source.get("controlName", ""))
            control_set = escape_html(source.get("controlSetName", ""))
            html_content += f"""
                <div class="control-item">
                    <div>{control_name}</div>
                    <div class="control-set">{control_set}</div>
                </div>
"""

        html_content += """
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
        description="Generate gap analysis report for unmapped Config rules"
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
        "--summary-link",
        help="Link back to summary page",
        default=None
    )
    parser.add_argument(
        "--control-catalog-link",
        help="Link to control catalog report",
        default=None
    )
    parser.add_argument(
        "--catalog-file",
        help="Path to cached Control Catalog JSON file for rule descriptions",
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

        # Load Control Catalog if provided
        catalog_controls = None
        if args.catalog_file:
            print(f"Loading Control Catalog: {args.catalog_file}")
            catalog_data = load_json_file(args.catalog_file)
            catalog_controls = catalog_data.get("controls", {})
            print(f"  Loaded {len(catalog_controls)} controls from catalog")

        # Extract unmapped sources
        print("Analyzing unmapped evidence sources...")
        unmapped_sources = extract_unmapped_sources(compliance_report)

        # Group by keyword for count
        by_keyword = defaultdict(list)
        for source in unmapped_sources:
            by_keyword[source.get("keywordValue", "Unknown")].append(source)

        print(f"  Found {len(by_keyword)} unique unmapped rules")
        print(f"  Total references: {len(unmapped_sources)}")

        # Generate HTML
        html_content = generate_gap_report_html(
            compliance_report,
            unmapped_sources,
            args.summary_link,
            args.control_catalog_link,
            catalog_controls
        )

        if args.stdout:
            print(html_content)
        else:
            output_file = args.output
            if not output_file:
                base_name = args.report_file.rsplit(".", 1)[0]
                output_file = f"{base_name}_gaps.html"

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            print(f"Gap report written to: {output_file}")

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
