#!/usr/bin/env python3
"""
Validate framework summary reports against the Rules Manifest.

This script:
1. Reads each framework's summary report to extract Venn diagram values
2. Parses the Rules Manifest to get rule data
3. Applies the same filtering logic as the JavaScript
4. Compares expected vs actual counts
5. Reports any discrepancies

Usage:
    python framework_report_validation.py [--verbose]
"""

import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote
from bs4 import BeautifulSoup


def normalize_template_name(name: str) -> str:
    """Normalize template name for matching (mirrors JavaScript logic)."""
    return re.sub(r'[()\s.\-]+', '', name.lower())


def templates_match(stored: str, url_param: str) -> bool:
    """Check if two template names match after normalization."""
    if not stored or not url_param:
        return False
    return normalize_template_name(stored) == normalize_template_name(url_param)


def parse_summary_report(html_path: str) -> dict:
    """
    Parse a summary report HTML to extract Venn diagram values and URL parameters.

    Returns dict with:
        - framework_name: str
        - url_framework: str
        - url_standard: str
        - url_template: str
        - venn_segments: dict with keys f, t, s, ft, fs, ts, fts
        - framework_total: int
        - template_total: int
        - standard_total: int
    """
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()

    soup = BeautifulSoup(content, 'html.parser')
    result = {
        'framework_name': '',
        'url_framework': '',
        'url_standard': '',
        'url_template': '',
        'venn_segments': {},
        'framework_total': 0,
        'template_total': 0,
        'standard_total': 0,
        'has_venn': False
    }

    # Extract framework name from title
    title = soup.find('title')
    if title:
        match = re.search(r'Compliance Summary - (.+)', title.text)
        if match:
            result['framework_name'] = match.group(1)

    # Find the Rules Manifest link to extract URL parameters
    manifest_link = soup.find('a', href=re.compile(r'rule_manifest\.html\?'))
    if manifest_link:
        href = manifest_link['href']
        # Parse URL parameters
        if 'framework=' in href:
            match = re.search(r'framework=([^&]+)', href)
            if match:
                result['url_framework'] = unquote(match.group(1))
        if 'standard=' in href:
            match = re.search(r'standard=([^&]+)', href)
            if match:
                result['url_standard'] = unquote(match.group(1))
        if 'template=' in href:
            match = re.search(r'template=([^&]+)', href)
            if match:
                result['url_template'] = unquote(match.group(1))

    # Extract Venn segment values from links
    venn_pattern = r'venn=([a-z]+)"[^>]*><text[^>]*>(\d+)</text>'
    venn_matches = re.findall(venn_pattern, content)

    if venn_matches:
        result['has_venn'] = True
        for segment, count in venn_matches:
            result['venn_segments'][segment] = int(count)

    # Extract totals from venn-title elements (e.g., "(202 rules)")
    total_pattern = r'class="venn-title"[^>]*>\((\d+) rules\)'
    total_matches = re.findall(total_pattern, content)

    # The order in SVG is: Framework, Template, Standard
    if len(total_matches) >= 3:
        result['framework_total'] = int(total_matches[0])
        result['template_total'] = int(total_matches[1])
        result['standard_total'] = int(total_matches[2])

    return result


def parse_rules_manifest(html_path: str) -> list:
    """
    Parse the Rules Manifest HTML to extract rule data.

    Returns list of dicts with:
        - identifier: str
        - frameworks: list of str (lowercase)
        - standards: list of str (lowercase)
        - templates: list of str (lowercase)
    """
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()

    soup = BeautifulSoup(content, 'html.parser')
    rules = []

    for row in soup.find_all('tr', {'data-frameworks': True}):
        rule = {
            'identifier': '',
            'frameworks': [],
            'standards': [],
            'templates': []
        }

        # Get identifier from the link
        link = row.find('a', class_='rule-id')
        if link:
            rule['identifier'] = link.text.strip()

        # Get data attributes
        frameworks = row.get('data-frameworks', '')
        standards = row.get('data-standards', '')
        templates = row.get('data-templates', '')

        if frameworks:
            rule['frameworks'] = [f.strip() for f in frameworks.split('|') if f.strip()]
        if standards:
            rule['standards'] = [s.strip() for s in standards.split('|') if s.strip()]
        if templates:
            rule['templates'] = [t.strip() for t in templates.split('|') if t.strip()]

        rules.append(rule)

    return rules


def filter_rules(rules: list, url_framework: str, url_standard: str, url_template: str) -> dict:
    """
    Apply URL filtering logic to rules and compute counts.

    Returns dict with:
        - visible_rules: list of matching rules
        - total: int
        - in_framework: int
        - in_standard: int
        - in_template: int
        - venn_segments: dict with counts for f, t, s, ft, fs, ts, fts
    """
    result = {
        'visible_rules': [],
        'total': 0,
        'in_framework': 0,
        'in_standard': 0,
        'in_template': 0,
        'venn_segments': {'f': 0, 't': 0, 's': 0, 'ft': 0, 'fs': 0, 'ts': 0, 'fts': 0}
    }

    normalized_url_framework = url_framework.lower() if url_framework else ''
    normalized_url_standard = url_standard.lower() if url_standard else ''

    for rule in rules:
        # Check if rule matches URL filters
        matches_framework = normalized_url_framework and normalized_url_framework in rule['frameworks']
        matches_standard = normalized_url_standard and normalized_url_standard in rule['standards']
        matches_template = url_template and any(templates_match(t, url_template) for t in rule['templates'])

        # URL filter: show if matches ANY of the specified sources
        if url_framework or url_standard or url_template:
            if not (matches_framework or matches_standard or matches_template):
                continue

        # Rule is visible
        result['visible_rules'].append(rule)
        result['total'] += 1

        # Count matches for each source
        if matches_framework:
            result['in_framework'] += 1
        if matches_standard:
            result['in_standard'] += 1
        if matches_template:
            result['in_template'] += 1

        # Compute Venn segment for this rule
        f = matches_framework
        t = matches_template
        s = matches_standard

        if f and t and s:
            result['venn_segments']['fts'] += 1
        elif f and t:
            result['venn_segments']['ft'] += 1
        elif f and s:
            result['venn_segments']['fs'] += 1
        elif t and s:
            result['venn_segments']['ts'] += 1
        elif f:
            result['venn_segments']['f'] += 1
        elif t:
            result['venn_segments']['t'] += 1
        elif s:
            result['venn_segments']['s'] += 1

    return result


def validate_framework(summary_path: str, rules: list, verbose: bool = False) -> dict:
    """
    Validate a single framework's summary report against the rules manifest.

    Returns dict with validation results.
    """
    result = {
        'summary_path': summary_path,
        'framework_name': '',
        'has_venn': False,
        'issues': [],
        'expected': {},
        'actual': {}
    }

    # Parse summary report
    summary = parse_summary_report(summary_path)
    result['framework_name'] = summary['framework_name']
    result['has_venn'] = summary['has_venn']

    if not summary['has_venn']:
        return result

    # Filter rules using URL parameters from summary
    filtered = filter_rules(
        rules,
        summary['url_framework'],
        summary['url_standard'],
        summary['url_template']
    )

    # Store expected (from summary) and actual (from filtering)
    result['expected'] = {
        'framework_total': summary['framework_total'],
        'template_total': summary['template_total'],
        'standard_total': summary['standard_total'],
        'venn_segments': summary['venn_segments']
    }

    result['actual'] = {
        'total': filtered['total'],
        'in_framework': filtered['in_framework'],
        'in_template': filtered['in_template'],
        'in_standard': filtered['in_standard'],
        'venn_segments': filtered['venn_segments']
    }

    # Compare and find issues
    # Check totals
    if summary['framework_total'] != filtered['in_framework']:
        result['issues'].append(
            f"Framework total mismatch: expected {summary['framework_total']}, got {filtered['in_framework']}"
        )

    if summary['template_total'] != filtered['in_template']:
        result['issues'].append(
            f"Template total mismatch: expected {summary['template_total']}, got {filtered['in_template']}"
        )

    if summary['standard_total'] != filtered['in_standard']:
        result['issues'].append(
            f"Standard total mismatch: expected {summary['standard_total']}, got {filtered['in_standard']}"
        )

    # Check Venn segments
    for segment in ['f', 't', 's', 'ft', 'fs', 'ts', 'fts']:
        expected = summary['venn_segments'].get(segment, 0)
        actual = filtered['venn_segments'].get(segment, 0)
        if expected != actual:
            segment_names = {
                'f': 'Framework only',
                't': 'Template only',
                's': 'Standard only',
                'ft': 'Framework & Template',
                'fs': 'Framework & Standard',
                'ts': 'Template & Standard',
                'fts': 'All three'
            }
            result['issues'].append(
                f"Venn segment '{segment_names[segment]}' mismatch: expected {expected}, got {actual}"
            )

    # Check that Venn segment sum equals total
    expected_total = sum(summary['venn_segments'].values())
    if expected_total != filtered['total']:
        result['issues'].append(
            f"Total rules mismatch: Venn sum {expected_total}, filtered total {filtered['total']}"
        )

    return result


def find_summary_reports(dashboards_dir: str) -> list:
    """Find all summary report HTML files."""
    reports = []
    for folder in os.listdir(dashboards_dir):
        folder_path = os.path.join(dashboards_dir, folder)
        if os.path.isdir(folder_path):
            for filename in os.listdir(folder_path):
                if filename.endswith('_summary.html'):
                    reports.append(os.path.join(folder_path, filename))
    return sorted(reports)


def main():
    parser = argparse.ArgumentParser(
        description="Validate framework summary reports against the Rules Manifest"
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed output for each framework'
    )
    parser.add_argument(
        '--dashboards-dir',
        default='compliance-dashboards',
        help='Path to compliance dashboards directory'
    )
    parser.add_argument(
        '--manifest-path',
        default='rule-manifest/rule_manifest.html',
        help='Path to rules manifest HTML'
    )

    args = parser.parse_args()

    # Check paths exist
    if not os.path.exists(args.dashboards_dir):
        print(f"Error: Dashboards directory not found: {args.dashboards_dir}", file=sys.stderr)
        return 1

    if not os.path.exists(args.manifest_path):
        print(f"Error: Rules manifest not found: {args.manifest_path}", file=sys.stderr)
        return 1

    # Parse rules manifest once
    print("Loading Rules Manifest...")
    rules = parse_rules_manifest(args.manifest_path)
    print(f"  Loaded {len(rules)} rules")

    # Find all summary reports
    print(f"\nScanning {args.dashboards_dir} for summary reports...")
    summary_reports = find_summary_reports(args.dashboards_dir)
    print(f"  Found {len(summary_reports)} summary reports")

    # Validate each report
    print("\n" + "=" * 80)
    print("VALIDATION RESULTS")
    print("=" * 80)

    all_results = []
    frameworks_with_issues = 0
    frameworks_without_venn = 0

    for report_path in summary_reports:
        result = validate_framework(report_path, rules, args.verbose)
        all_results.append(result)

        if not result['has_venn']:
            frameworks_without_venn += 1
            if args.verbose:
                print(f"\n[SKIP] {result['framework_name']}")
                print("  No Venn diagram in this report")
            continue

        if result['issues']:
            frameworks_with_issues += 1
            print(f"\n[FAIL] {result['framework_name']}")
            for issue in result['issues']:
                print(f"  - {issue}")
            if args.verbose:
                print(f"  URL params: framework={result['expected'].get('url_framework', 'N/A')}")
                print(f"              standard={result['expected'].get('url_standard', 'N/A')}")
                print(f"              template={result['expected'].get('url_template', 'N/A')}")
        else:
            if args.verbose:
                print(f"\n[PASS] {result['framework_name']}")
                print(f"  Total: {result['actual']['total']}, F: {result['actual']['in_framework']}, "
                      f"T: {result['actual']['in_template']}, S: {result['actual']['in_standard']}")

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total frameworks validated: {len(summary_reports)}")
    print(f"Frameworks without Venn diagram: {frameworks_without_venn}")
    print(f"Frameworks with issues: {frameworks_with_issues}")
    print(f"Frameworks passing: {len(summary_reports) - frameworks_without_venn - frameworks_with_issues}")

    if frameworks_with_issues > 0:
        print("\n" + "-" * 80)
        print("FRAMEWORKS WITH ISSUES:")
        print("-" * 80)
        for result in all_results:
            if result['issues']:
                print(f"\n{result['framework_name']}")
                print(f"  Report: {result['summary_path']}")
                print("  Issues:")
                for issue in result['issues']:
                    print(f"    - {issue}")
                print("  Expected (from Venn):")
                print(f"    Framework: {result['expected']['framework_total']}, "
                      f"Template: {result['expected']['template_total']}, "
                      f"Standard: {result['expected']['standard_total']}")
                print("  Actual (from filtering):")
                print(f"    Framework: {result['actual']['in_framework']}, "
                      f"Template: {result['actual']['in_template']}, "
                      f"Standard: {result['actual']['in_standard']}")

    return 1 if frameworks_with_issues > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
