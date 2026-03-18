#!/usr/bin/env python3
"""
Generate an HTML index page listing all frameworks from Frameworks.xlsx.

The index page contains a table with:
- Framework name (hyperlinked to summary report)
- Conformance Pack Template (if any)
- Security Standard (if any)

Usage:
    python generate_index_page.py [-o OUTPUT_FILE]
"""

import argparse
import html
import os
import re
import sys
from datetime import datetime, timezone

import pandas as pd


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    return html.escape(str(text))


def normalize_for_matching(name: str) -> str:
    """Normalize a name for fuzzy matching (remove all non-alphanumeric, lowercase)."""
    return re.sub(r'[^a-z0-9]', '', name.lower())


def load_frameworks(excel_path: str) -> list:
    """
    Load framework data from Frameworks.xlsx.

    Returns list of dicts with:
        - name: Framework name
        - id: Framework ID
        - template: Conformance Pack Template name (or None)
        - standard: Security Standard file name (or None)
    """
    frameworks = []

    df = pd.read_excel(excel_path)

    for _, row in df.iterrows():
        name = str(row.get('S Audit Manager Framework', '')).strip()
        framework_id = str(row.get('Framework ID', '')).strip()
        template = row.get('Conformance Pack Template name', '')
        standard = row.get('Security Standard File', '')

        if not name or not framework_id:
            continue

        # Handle NaN values
        if pd.isna(template) or not template:
            template = None
        else:
            template = str(template).strip()

        if pd.isna(standard) or not standard:
            standard = None
        else:
            standard = str(standard).strip()

        frameworks.append({
            'name': name,
            'id': framework_id,
            'template': template,
            'standard': standard
        })

    return frameworks


def build_folder_mapping(dashboards_dir: str, frameworks: list) -> dict:
    """
    Build a mapping of framework names to folder paths.

    Each folder is assigned to exactly one framework - the one with the
    shortest normalized name that still matches the folder prefix.
    This ensures truncated folders match the most specific framework.

    Returns dict: framework_name -> (folder_name, summary_file_path)
    """
    mapping = {}

    if not os.path.exists(dashboards_dir):
        return mapping

    # First, collect all folders with summary files
    folders = {}
    for folder_name in os.listdir(dashboards_dir):
        folder_path = os.path.join(dashboards_dir, folder_name)
        if not os.path.isdir(folder_path):
            continue

        # Find summary file
        summary_file = None
        for filename in os.listdir(folder_path):
            if filename.endswith('_summary.html'):
                summary_file = filename
                break

        if summary_file:
            normalized = normalize_for_matching(folder_name)
            folders[normalized] = (folder_name, summary_file)

    # For each folder, find the best matching framework
    # (shortest framework name that starts with the folder prefix)
    folder_to_framework = {}

    for folder_normalized, folder_info in folders.items():
        best_framework = None
        best_len = float('inf')

        for framework in frameworks:
            fw_normalized = normalize_for_matching(framework['name'])

            # Check if framework matches this folder
            if fw_normalized == folder_normalized or fw_normalized.startswith(folder_normalized):
                # Prefer shorter framework names (more specific match)
                if len(fw_normalized) < best_len:
                    best_framework = framework['name']
                    best_len = len(fw_normalized)

        if best_framework:
            folder_to_framework[folder_normalized] = best_framework
            mapping[best_framework] = folder_info

    return mapping


def check_summary_report_exists(framework_name: str, folder_mapping: dict) -> str:
    """
    Check if a summary report exists for a framework.

    Uses the pre-built folder mapping to find the assigned folder.
    Returns the relative path to the summary report if it exists, None otherwise.
    """
    if not folder_mapping:
        return None

    folder_info = folder_mapping.get(framework_name)
    if folder_info:
        folder_name, summary_file = folder_info
        return f"compliance-dashboards/{folder_name}/{summary_file}"

    return None


def generate_index_html(frameworks: list, folder_mapping: dict) -> str:
    """Generate the HTML index page."""

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count frameworks with reports
    frameworks_with_reports = sum(
        1 for f in frameworks
        if check_summary_report_exists(f['name'], folder_mapping)
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Frameworks Index</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f7fafc;
            color: #2d3748;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        h1 {{
            color: #1a202c;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #718096;
            margin-bottom: 20px;
            font-size: 14px;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 15px 25px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            color: #2b6cb0;
        }}
        .stat-label {{
            font-size: 12px;
            color: #718096;
            text-transform: uppercase;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        th {{
            background: #2d3748;
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 14px;
        }}
        tr:hover {{
            background: #f7fafc;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        a {{
            color: #2b6cb0;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .no-report {{
            color: #a0aec0;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }}
        .badge-template {{
            background: #c6f6d5;
            color: #276749;
        }}
        .badge-standard {{
            background: #e9d8fd;
            color: #553c9a;
        }}
        .badge-none {{
            background: #edf2f7;
            color: #a0aec0;
        }}
        .search-box {{
            width: 100%;
            max-width: 400px;
            padding: 10px 15px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            font-size: 14px;
            margin-bottom: 20px;
        }}
        .search-box:focus {{
            outline: none;
            border-color: #4299e1;
            box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.2);
        }}
        .links {{
            margin-bottom: 20px;
        }}
        .links a {{
            display: inline-block;
            padding: 8px 16px;
            background: #2b6cb0;
            color: white;
            border-radius: 6px;
            margin-right: 10px;
            font-size: 14px;
        }}
        .links a:hover {{
            background: #2c5282;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Frameworks Index</h1>
        <p class="subtitle">Generated: {generated_at}</p>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{len(frameworks)}</div>
                <div class="stat-label">Total Frameworks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{frameworks_with_reports}</div>
                <div class="stat-label">With Reports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{sum(1 for f in frameworks if f['template'])}</div>
                <div class="stat-label">With Templates</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{sum(1 for f in frameworks if f['standard'])}</div>
                <div class="stat-label">With Standards</div>
            </div>
        </div>

        <div class="links">
            <a href="rule-manifest/rule_manifest.html">Rules Manifest</a>
        </div>

        <input type="text" class="search-box" id="searchBox" placeholder="Search frameworks..." onkeyup="filterTable()">

        <table>
            <thead>
                <tr>
                    <th style="width: 40%">Framework</th>
                    <th style="width: 30%">Conformance Pack Template</th>
                    <th style="width: 30%">Security Standard</th>
                </tr>
            </thead>
            <tbody id="frameworksTable">
"""

    for framework in sorted(frameworks, key=lambda f: f['name'].lower()):
        name = framework['name']
        template = framework['template']
        standard = framework['standard']

        # Check if summary report exists
        report_path = check_summary_report_exists(name, folder_mapping)

        # Framework name cell (with link if report exists)
        if report_path:
            name_cell = f'<a href="{escape_html(report_path)}">{escape_html(name)}</a>'
        else:
            name_cell = f'<span class="no-report">{escape_html(name)}</span>'

        # Template cell
        if template:
            template_cell = f'<span class="badge badge-template">{escape_html(template)}</span>'
        else:
            template_cell = '<span class="badge badge-none">None</span>'

        # Standard cell
        if standard:
            # Make standard name more readable (remove file extension style)
            standard_display = standard.replace('-', ' ').replace('_', ' ').title()
            template_cell_std = f'<span class="badge badge-standard">{escape_html(standard_display)}</span>'
        else:
            template_cell_std = '<span class="badge badge-none">None</span>'

        html_content += f"""                <tr data-search="{escape_html(name.lower())} {escape_html((template or '').lower())} {escape_html((standard or '').lower())}">
                    <td>{name_cell}</td>
                    <td>{template_cell}</td>
                    <td>{template_cell_std}</td>
                </tr>
"""

    html_content += """            </tbody>
        </table>
    </div>

    <script>
        function filterTable() {
            const searchText = document.getElementById('searchBox').value.toLowerCase();
            const rows = document.querySelectorAll('#frameworksTable tr');

            rows.forEach(row => {
                const searchData = row.dataset.search || '';
                if (searchText && !searchData.includes(searchText)) {
                    row.style.display = 'none';
                } else {
                    row.style.display = '';
                }
            });
        }
    </script>
</body>
</html>
"""

    return html_content


def main():
    parser = argparse.ArgumentParser(
        description="Generate an HTML index page for compliance frameworks"
    )
    parser.add_argument(
        "-o", "--output",
        default="index.html",
        help="Output HTML file path (default: index.html)"
    )
    parser.add_argument(
        "--excel-file",
        default=None,
        help="Path to Frameworks.xlsx (default: auto-detect)"
    )

    args = parser.parse_args()

    # Determine paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)

    excel_path = args.excel_file or os.path.join(project_dir, "Frameworks.xlsx")
    dashboards_dir = os.path.join(project_dir, "compliance-dashboards")
    output_path = os.path.join(project_dir, args.output)

    # Validate inputs
    if not os.path.exists(excel_path):
        print(f"Error: Frameworks.xlsx not found at {excel_path}", file=sys.stderr)
        return 1

    if not os.path.exists(dashboards_dir):
        print(f"Warning: compliance-dashboards directory not found at {dashboards_dir}")
        print("  Summary report links will be disabled.")

    # Load frameworks
    print(f"Loading frameworks from {excel_path}...")
    frameworks = load_frameworks(excel_path)
    print(f"  Found {len(frameworks)} frameworks")

    # Build folder mapping (assigns each folder to one framework)
    folder_mapping = build_folder_mapping(dashboards_dir, frameworks)
    print(f"  Matched {len(folder_mapping)} frameworks to dashboard folders")

    # Generate HTML
    print("Generating index page...")
    html_content = generate_index_html(frameworks, folder_mapping)

    # Write output
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Index page written to: {output_path}")

    # Summary
    with_templates = sum(1 for f in frameworks if f['template'])
    with_standards = sum(1 for f in frameworks if f['standard'])
    with_reports = sum(1 for f in frameworks if check_summary_report_exists(f['name'], folder_mapping))

    print(f"\nSummary:")
    print(f"  Total frameworks: {len(frameworks)}")
    print(f"  With conformance pack templates: {with_templates}")
    print(f"  With security standards: {with_standards}")
    print(f"  With summary reports: {with_reports}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
