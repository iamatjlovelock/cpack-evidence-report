import boto3
import json
import os
from datetime import datetime, timezone


def list_all_standards():
    """List all available security standards from AWS Security Hub."""
    client = boto3.client('securityhub')

    standards = []
    next_token = None

    while True:
        if next_token:
            response = client.describe_standards(NextToken=next_token)
        else:
            response = client.describe_standards()

        standards.extend(response.get('Standards', []))
        next_token = response.get('NextToken')

        if not next_token:
            break

    return standards


def list_enabled_standards():
    """List all enabled security standards in AWS Security Hub."""
    client = boto3.client('securityhub')

    standards = []
    next_token = None

    while True:
        if next_token:
            response = client.get_enabled_standards(NextToken=next_token)
        else:
            response = client.get_enabled_standards()

        standards.extend(response.get('StandardsSubscriptions', []))
        next_token = response.get('NextToken')

        if not next_token:
            break

    return standards


def extract_standard_id(standards_arn):
    """Extract a readable ID from the standards ARN."""
    parts = standards_arn.split('/')
    if len(parts) >= 2:
        return '/'.join(parts[1:])
    return standards_arn


def extract_version(standards_arn):
    """Extract version number from standards ARN."""
    parts = standards_arn.split('/v/')
    if len(parts) >= 2:
        return parts[-1]
    return None


def extract_standard_family(name):
    """Extract the standard family (e.g., 'CIS', 'PCI DSS', 'NIST')."""
    name_lower = name.lower()
    if 'cis' in name_lower:
        return 'CIS'
    elif 'pci' in name_lower:
        return 'PCI DSS'
    elif '800-53' in name_lower:
        return 'NIST 800-53'
    elif '800-171' in name_lower:
        return 'NIST 800-171'
    elif 'foundational security' in name_lower:
        return 'AWS FSBP'
    elif 'tagging' in name_lower:
        return 'AWS Tagging'
    return 'Other'


def main():
    all_standards = list_all_standards()
    enabled_standards = list_enabled_standards()

    # Create mapping from ARN to enabled standard details
    enabled_map = {s.get('StandardsArn'): s for s in enabled_standards}

    standards_list = []

    for standard in all_standards:
        arn = standard.get('StandardsArn', '')
        name = standard.get('Name', '')
        is_enabled = arn in enabled_map
        enabled_info = enabled_map.get(arn, {})

        standard_data = {
            'id': extract_standard_id(arn),
            'name': name,
            'description': standard.get('Description', ''),
            'standards_arn': arn,
            'version': extract_version(arn),
            'standard_family': extract_standard_family(name),
            'enabled_by_default': standard.get('EnabledByDefault', False),
            'standards_managed_by': standard.get('StandardsManagedBy', {}),
            'enabled': is_enabled,
            'standards_subscription_arn': enabled_info.get('StandardsSubscriptionArn'),
            'standards_status': enabled_info.get('StandardsStatus'),
            'standards_status_reason': enabled_info.get('StandardsStatusReason')
        }

        standards_list.append(standard_data)

    output = {
        'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'total_available': len(all_standards),
        'total_enabled': len(enabled_standards),
        'standards': standards_list
    }

    # Write to JSON file (same folder as this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, 'security_hub_standards.json')

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Generated {output_file}")
    print(f"Found {len(all_standards)} available standards, {len(enabled_standards)} enabled")


if __name__ == '__main__':
    main()
