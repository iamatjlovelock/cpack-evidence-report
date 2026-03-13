#!/usr/bin/env python3
"""
Extract controls for all enabled AWS Security Hub security standards.

This script first refreshes the list of Security Hub standards by calling
list_security_hub_standards.py, then runs get_standard_controls.py for each
enabled standard to extract detailed control information including AWS Config
rule mappings.

Prerequisites:
    - AWS credentials configured with permissions for:
        - securityhub:DescribeStandards
        - securityhub:GetEnabledStandards
        - securityhub:DescribeStandardsControls
        - securityhub:GetFindings

Usage:
    # Extract controls for all enabled standards (skips existing files)
    python security-standard-controls/get_all_enabled_standard_controls.py

    # Force refresh all control files
    python security-standard-controls/get_all_enabled_standard_controls.py --refresh

Output:
    Creates JSON files in security-standard-controls/ for each enabled standard:
    - aws-foundational-security-best-practices-v100.json
    - cis-aws-foundations-benchmark-v120.json
    - pci-dss-v401.json
    (filenames depend on which standards are enabled)

Arguments:
    --refresh    Regenerate output files even if they already exist
"""

import argparse
import json
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(
        description='Extract controls for all enabled Security Hub security standards'
    )
    parser.add_argument(
        '--refresh',
        action='store_true',
        help='Refresh output files even if they already exist'
    )
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    standards_file = os.path.join(script_dir, 'security_hub_standards.json')

    # First, refresh the list of Security Hub standards
    print("Refreshing Security Hub standards list...")
    list_standards_script = os.path.join(script_dir, 'list_security_hub_standards.py')
    result = subprocess.run([sys.executable, list_standards_script], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error refreshing standards list: {result.stderr}")
        sys.exit(1)
    print(result.stdout.strip())
    print()

    # Check if standards file exists
    if not os.path.exists(standards_file):
        print(f"Error: {standards_file} not found.")
        sys.exit(1)

    # Load standards
    with open(standards_file, 'r') as f:
        data = json.load(f)

    standards = data.get('standards', [])
    enabled_standards = [s for s in standards if s.get('enabled')]

    print(f"Found {len(enabled_standards)} enabled standards")
    print()

    # Path to the single-standard script (in same folder)
    single_script = os.path.join(script_dir, 'get_standard_controls.py')

    for standard in enabled_standards:
        name = standard.get('name', '')
        subscription_arn = standard.get('standards_subscription_arn', '')
        standards_arn = standard.get('standards_arn', '')
        description = standard.get('description', '')

        if not subscription_arn:
            print(f"SKIPPED: {name} (no subscription ARN)")
            continue

        print(f"Processing: {name}...")

        cmd = [
            sys.executable,
            single_script,
            '--subscription-arn', subscription_arn,
            '--name', name,
            '--standards-arn', standards_arn,
            '--description', description
        ]

        if args.refresh:
            cmd.append('--refresh')

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"  ERROR: {result.stderr}")
        else:
            print(f"  {result.stdout.strip()}")

    print()
    print("Done!")


if __name__ == '__main__':
    main()
