#!/usr/bin/env python3
"""
Extract controls for a single AWS Security Hub security standard.

This script retrieves all controls for a specified Security Hub standard and
enriches each control with:
    - security_control_id: The underlying Security Hub control ID (e.g., IAM.16)
    - config_rule: The AWS Config rule name that evaluates the control

The Config rule mapping is obtained by querying Security Hub findings to find
the related AWS Config rule for each security control.

Prerequisites:
    - The standard must be enabled in your Security Hub account
    - AWS credentials configured with permissions for:
        - securityhub:DescribeStandardsControls
        - securityhub:GetFindings

Usage:
    # Typically called by get_all_enabled_standard_controls.py, but can be run directly:
    python security-standard-controls/get_standard_controls.py \\
        --subscription-arn "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0" \\
        --name "CIS AWS Foundations Benchmark v1.2.0" \\
        --standards-arn "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"

    # Force refresh even if file exists
    python security-standard-controls/get_standard_controls.py ... --refresh

Output JSON structure:
    {
        "standard_name": "CIS AWS Foundations Benchmark v1.2.0",
        "standard_description": "...",
        "standards_arn": "arn:aws:securityhub:...",
        "standards_subscription_arn": "arn:aws:securityhub:...",
        "total_controls": 42,
        "controls": [
            {
                "control_id": "CIS.1.10",
                "title": "Ensure IAM password policy prevents password reuse",
                "description": "...",
                "severity_rating": "LOW",
                "control_status": "ENABLED",
                "control_status_updated_at": "2025-05-12T18:21:02.288000+00:00",
                "remediation_url": "https://docs.aws.amazon.com/...",
                "related_requirements": ["CIS AWS Foundations 1.10"],
                "security_control_id": "IAM.16",
                "config_rule": "securityhub-iam-password-policy-prevent-reuse-check-abc123"
            },
            ...
        ]
    }

Arguments:
    --subscription-arn  The standards subscription ARN (required)
    --name              The standard name, used for output filename (required)
    --standards-arn     The standards ARN (required)
    --description       The standard description (optional)
    -o, --output-dir    Output directory (default: security-standard-controls)
    --refresh           Regenerate output file even if it already exists
"""

import argparse
import boto3
import json
import os
import re
import sys


def get_standards_controls(standards_subscription_arn):
    """Get all controls for a given security standard."""
    client = boto3.client('securityhub')

    controls = []
    next_token = None

    while True:
        if next_token:
            response = client.describe_standards_controls(
                StandardsSubscriptionArn=standards_subscription_arn,
                NextToken=next_token
            )
        else:
            response = client.describe_standards_controls(
                StandardsSubscriptionArn=standards_subscription_arn
            )

        controls.extend(response.get('Controls', []))
        next_token = response.get('NextToken')

        if not next_token:
            break

    return controls


def extract_security_control_id(remediation_url):
    """Extract the security control ID from the remediation URL."""
    if not remediation_url:
        return None
    # URL format: https://docs.aws.amazon.com/console/securityhub/IAM.16/remediation
    match = re.search(r'/securityhub/([A-Za-z0-9.]+)/remediation', remediation_url)
    if match:
        return match.group(1)
    return None


def get_config_rule_for_security_control(client, security_control_id):
    """Get the AWS Config rule name for a security control by querying findings."""
    if not security_control_id:
        return None

    try:
        response = client.get_findings(
            Filters={
                'ComplianceSecurityControlId': [
                    {'Value': security_control_id, 'Comparison': 'EQUALS'}
                ]
            },
            MaxResults=1
        )

        findings = response.get('Findings', [])
        if findings:
            product_fields = findings[0].get('ProductFields', {})
            config_rule = product_fields.get('RelatedAWSResources:0/name')
            config_rule_type = product_fields.get('RelatedAWSResources:0/type')

            if config_rule_type == 'AWS::Config::ConfigRule':
                return config_rule

    except Exception:
        pass

    return None


def build_config_rule_mapping(controls):
    """Build a mapping of control IDs to Config rules and security control IDs."""
    client = boto3.client('securityhub')
    mapping = {}

    for control in controls:
        control_id = control.get('ControlId', '')
        remediation_url = control.get('RemediationUrl', '')
        security_control_id = extract_security_control_id(remediation_url)
        config_rule = get_config_rule_for_security_control(client, security_control_id)

        mapping[control_id] = {
            'security_control_id': security_control_id,
            'config_rule': config_rule
        }

    return mapping


def sanitize_filename(name):
    """Convert standard name to a safe filename."""
    name = re.sub(r'[^\w\s-]', '', name)
    name = re.sub(r'\s+', '-', name)
    return name.lower()


def main():
    parser = argparse.ArgumentParser(
        description='Extract controls for a single Security Hub security standard'
    )
    parser.add_argument(
        '--subscription-arn',
        required=True,
        help='The standards subscription ARN'
    )
    parser.add_argument(
        '--name',
        required=True,
        help='The standard name (used for output filename)'
    )
    parser.add_argument(
        '--standards-arn',
        required=True,
        help='The standards ARN'
    )
    parser.add_argument(
        '--description',
        default='',
        help='The standard description'
    )
    parser.add_argument(
        '-o', '--output-dir',
        help='Output directory (default: security-standard-controls)',
        default=None
    )
    parser.add_argument(
        '--refresh',
        action='store_true',
        help='Refresh the output file even if it already exists'
    )

    args = parser.parse_args()

    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(script_dir)
        output_dir = os.path.join(project_dir, 'security-standard-controls')

    os.makedirs(output_dir, exist_ok=True)

    # Check if output file already exists
    filename = sanitize_filename(args.name) + '.json'
    output_file = os.path.join(output_dir, filename)

    if os.path.exists(output_file) and not args.refresh:
        print(f"Skipped {args.name} (file exists, use --refresh to update)")
        return

    # Get controls
    controls = get_standards_controls(args.subscription_arn)

    # Build Config rule mapping
    print(f"  Fetching Config rule mappings for {len(controls)} controls...")
    config_rule_mapping = build_config_rule_mapping(controls)

    # Build output structure
    output = {
        'standard_name': args.name,
        'standard_description': args.description,
        'standards_arn': args.standards_arn,
        'standards_subscription_arn': args.subscription_arn,
        'total_controls': len(controls),
        'controls': []
    }

    for control in controls:
        control_id = control.get('ControlId', '')
        mapping = config_rule_mapping.get(control_id, {})
        control_data = {
            'control_id': control_id,
            'title': control.get('Title', ''),
            'description': control.get('Description', ''),
            'severity_rating': control.get('SeverityRating', ''),
            'control_status': control.get('ControlStatus', ''),
            'control_status_updated_at': control.get('ControlStatusUpdatedAt', '').isoformat() if control.get('ControlStatusUpdatedAt') else '',
            'remediation_url': control.get('RemediationUrl', ''),
            'related_requirements': control.get('RelatedRequirements', []),
            'security_control_id': mapping.get('security_control_id'),
            'config_rule': mapping.get('config_rule')
        }
        output['controls'].append(control_data)

    # Write to file
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Saved {len(controls)} controls to {output_file}")


if __name__ == '__main__':
    main()
