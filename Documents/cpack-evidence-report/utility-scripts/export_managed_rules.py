#!/usr/bin/env python3
"""
Export all AWS Config managed rule identifiers.

This script fetches the list of all available AWS Config managed rules
by querying the Config service for rule definitions. It combines:
1. Rules from deployed conformance packs in the account
2. Rules from the Control Catalog
3. Rules from Security Hub standards

The output is used by generate_rule_manifest.py to show all managed rules,
including those not referenced by any compliance source.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_managed_rules_from_config(session, region: str) -> dict:
    """
    Fetch all Config rules deployed in the account and extract unique managed rule identifiers.
    """
    config = session.client("config", region_name=region)
    managed_rules = {}

    try:
        paginator = config.get_paginator("describe_config_rules")
        for page in paginator.paginate():
            for rule in page.get("ConfigRules", []):
                source = rule.get("Source", {})
                owner = source.get("Owner", "")
                identifier = source.get("SourceIdentifier", "")

                # Only include AWS managed rules
                if owner == "AWS" and identifier:
                    identifier_upper = identifier.upper()
                    if identifier_upper not in managed_rules:
                        managed_rules[identifier_upper] = {
                            "identifier": identifier_upper,
                            "description": rule.get("Description", ""),
                            "source": "AWS Config (deployed)"
                        }
                    elif not managed_rules[identifier_upper].get("description") and rule.get("Description"):
                        managed_rules[identifier_upper]["description"] = rule.get("Description")

    except ClientError as e:
        print(f"  Warning: Could not fetch Config rules: {e}", file=sys.stderr)

    return managed_rules


def get_managed_rules_from_control_catalog(session, region: str) -> dict:
    """
    Fetch all Config rules from the Control Catalog.
    """
    catalog = session.client("controlcatalog", region_name=region)
    managed_rules = {}

    try:
        paginator = catalog.get_paginator("list_controls")
        for page in paginator.paginate(MaxResults=100):
            for control in page.get("Controls", []):
                behavior = control.get("Behavior", "")
                # Behavior can be a string like "DETECTIVE" or a dict with "Type"
                behavior_type = behavior.get("Type") if isinstance(behavior, dict) else behavior
                if behavior_type != "DETECTIVE":
                    continue

                # Extract rule identifier from the control
                arn = control.get("Arn", "")
                # Control ARN format: arn:aws:controlcatalog:::control/{identifier}
                match = re.search(r'/([A-Z0-9_]+)$', arn)
                if match:
                    identifier = match.group(1).upper()
                    if identifier not in managed_rules:
                        managed_rules[identifier] = {
                            "identifier": identifier,
                            "name": control.get("Name", ""),
                            "description": control.get("Description", ""),
                            "source": "Control Catalog"
                        }

    except ClientError as e:
        print(f"  Warning: Could not fetch Control Catalog: {e}", file=sys.stderr)

    return managed_rules


def get_managed_rules_from_templates(project_dir: str) -> dict:
    """
    Extract all unique rule identifiers from conformance pack templates.
    """
    templates_dir = os.path.join(project_dir, "conformance-packs", "conformance-pack-yamls")
    managed_rules = {}

    if not os.path.exists(templates_dir):
        return managed_rules

    try:
        import yaml
    except ImportError:
        print("  Warning: PyYAML not installed", file=sys.stderr)
        return managed_rules

    for filename in os.listdir(templates_dir):
        if not filename.endswith((".yaml", ".yml")):
            continue

        filepath = os.path.join(templates_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            resources = data.get("Resources", {}) if data else {}
            for resource_name, resource_def in resources.items():
                if not isinstance(resource_def, dict):
                    continue
                if resource_def.get("Type") == "AWS::Config::ConfigRule":
                    props = resource_def.get("Properties", {})
                    source = props.get("Source", {})
                    identifier = source.get("SourceIdentifier", "")

                    if isinstance(identifier, str) and identifier:
                        identifier_upper = identifier.upper()
                        if identifier_upper not in managed_rules:
                            managed_rules[identifier_upper] = {
                                "identifier": identifier_upper,
                                "description": props.get("Description", ""),
                                "source": "Conformance Pack Template"
                            }

        except Exception as e:
            print(f"  Warning: Could not parse {filename}: {e}", file=sys.stderr)

    return managed_rules


def merge_rules(*rule_dicts) -> dict:
    """
    Merge multiple rule dictionaries, preferring entries with descriptions.
    """
    merged = {}

    for rules in rule_dicts:
        for identifier, info in rules.items():
            if identifier not in merged:
                merged[identifier] = info.copy()
            else:
                # Prefer entry with description
                if not merged[identifier].get("description") and info.get("description"):
                    merged[identifier]["description"] = info["description"]
                # Prefer entry with name
                if not merged[identifier].get("name") and info.get("name"):
                    merged[identifier]["name"] = info["name"]

    return merged


def main():
    parser = argparse.ArgumentParser(
        description="Export all AWS Config managed rule identifiers"
    )
    parser.add_argument(
        "-o", "--output",
        default="control-catalog/managed-rules.json",
        help="Output JSON file path (default: control-catalog/managed-rules.json)"
    )
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Project directory (default: current directory)"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name"
    )

    args = parser.parse_args()
    project_dir = os.path.abspath(args.project_dir)

    print("Fetching AWS Config managed rules...")

    # Create boto3 session
    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)

    # Fetch from multiple sources
    print("  Fetching from deployed Config rules...")
    config_rules = get_managed_rules_from_config(session, args.region)
    print(f"    Found {len(config_rules)} unique identifiers")

    print("  Fetching from Control Catalog...")
    catalog_rules = get_managed_rules_from_control_catalog(session, args.region)
    print(f"    Found {len(catalog_rules)} unique identifiers")

    print("  Extracting from conformance pack templates...")
    template_rules = get_managed_rules_from_templates(project_dir)
    print(f"    Found {len(template_rules)} unique identifiers")

    # Merge all sources
    print("\nMerging sources...")
    all_rules = merge_rules(catalog_rules, config_rules, template_rules)
    print(f"  Total unique managed rule identifiers: {len(all_rules)}")

    # Sort and prepare output
    sorted_rules = dict(sorted(all_rules.items()))

    output_data = {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "totalRules": len(sorted_rules),
        "rules": sorted_rules
    }

    # Write output
    output_path = os.path.join(project_dir, args.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"\nManaged rules exported to: {output_path}")


if __name__ == "__main__":
    main()
