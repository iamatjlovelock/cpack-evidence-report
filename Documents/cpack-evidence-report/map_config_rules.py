#!/usr/bin/env python3
"""
Script to map AWS Audit Manager evidence sources to AWS Config rules.
Takes a framework JSON file (from get_framework_controls.py) and maps
AWS_Config evidence sources to actual Config rules in your account.
"""

import argparse
import json
import sys
from collections import defaultdict

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def load_catalog_descriptions_from_file(catalog_file: str) -> dict:
    """
    Load control descriptions from a cached Control Catalog JSON file.

    Args:
        catalog_file: Path to the cached catalog file (from export_control_catalog.py)

    Returns:
        Dictionary mapping Config rule identifier to description
    """
    descriptions = {}

    try:
        print(f"Loading control descriptions from cached catalog: {catalog_file}")
        with open(catalog_file, "r", encoding="utf-8") as f:
            catalog_data = json.load(f)

        controls = catalog_data.get("controls", {})
        for identifier, control in controls.items():
            if control.get("description"):
                descriptions[identifier] = control["description"]

        print(f"  Found descriptions for {len(descriptions)} Config rule identifiers")

    except FileNotFoundError:
        print(f"  Warning: Catalog file not found: {catalog_file}")
    except Exception as e:
        print(f"  Warning: Could not load catalog file: {e}")

    return descriptions


def get_control_catalog_descriptions(region: str = None) -> dict:
    """
    Fetch control descriptions from the AWS Controls Catalog API.

    Args:
        region: AWS region (optional)

    Returns:
        Dictionary mapping Config rule identifier to description
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("controlcatalog", **client_kwargs)

    descriptions = {}

    print("Fetching control descriptions from Controls Catalog...")
    try:
        paginator = client.get_paginator("list_controls")

        for page in paginator.paginate(MaxResults=100):
            for control in page.get("Controls", []):
                impl = control.get("Implementation", {})
                impl_type = impl.get("Type", "")
                identifier = impl.get("Identifier", "")

                # Only get descriptions for Config rules
                if impl_type == "AWS::Config::ConfigRule" and identifier:
                    descriptions[identifier] = control.get("Description", "")

        print(f"  Found descriptions for {len(descriptions)} Config rule identifiers")

    except Exception as e:
        print(f"  Warning: Could not fetch from Controls Catalog: {e}")

    return descriptions


def get_all_config_rules(region: str = None, catalog_descriptions: dict = None) -> dict:
    """
    Retrieve all Config rules and index them by SourceIdentifier.

    Args:
        region: AWS region (optional)
        catalog_descriptions: Descriptions from Controls Catalog (optional)

    Returns:
        Dictionary mapping SourceIdentifier to list of Config rules
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("config", **client_kwargs)

    rules_by_identifier = defaultdict(list)
    catalog_descriptions = catalog_descriptions or {}

    print("Fetching AWS Config rules...")
    paginator = client.get_paginator("describe_config_rules")

    for page in paginator.paginate():
        for rule in page["ConfigRules"]:
            source = rule.get("Source", {})
            source_identifier = source.get("SourceIdentifier", "")

            if source_identifier:
                # Prefer Controls Catalog description, fall back to API description
                description = catalog_descriptions.get(source_identifier) or rule.get("Description", "")

                rules_by_identifier[source_identifier].append({
                    "ConfigRuleName": rule["ConfigRuleName"],
                    "SourceIdentifier": source_identifier,
                    "SourceOwner": source.get("Owner"),
                    "Description": description,
                    "ConfigRuleState": rule.get("ConfigRuleState"),
                    "ConfigRuleArn": rule.get("ConfigRuleArn")
                })

    print(f"  Found {sum(len(v) for v in rules_by_identifier.values())} Config rules")
    print(f"  Covering {len(rules_by_identifier)} unique managed rule identifiers")

    return dict(rules_by_identifier)


def extract_config_evidence_sources(framework_data: dict) -> dict:
    """
    Extract all AWS_Config evidence sources from framework data.

    Args:
        framework_data: Framework JSON from get_framework_controls.py

    Returns:
        Dictionary mapping keywordValue to list of controls using it
    """
    config_sources = defaultdict(list)

    for control_set in framework_data.get("controlSets", []):
        for control in control_set.get("controls", []):
            control_info = {
                "controlId": control.get("controlId"),
                "controlName": control.get("controlName"),
                "controlSetName": control_set.get("controlSetName")
            }

            for mapping_source in control.get("controlMappingSources", []):
                # Check direct AWS_Config sources
                if mapping_source.get("sourceType") == "AWS_Config":
                    keyword = mapping_source.get("sourceKeyword", {})
                    keyword_value = keyword.get("keywordValue")
                    if keyword_value:
                        config_sources[keyword_value].append({
                            **control_info,
                            "sourceName": mapping_source.get("sourceName"),
                            "sourceLevel": "direct"
                        })

                # Check Core Control evidence sources
                for evidence_source in mapping_source.get("coreControlEvidenceSources", []):
                    if evidence_source.get("sourceType") == "AWS_Config":
                        keyword = evidence_source.get("sourceKeyword", {})
                        keyword_value = keyword.get("keywordValue")
                        if keyword_value:
                            config_sources[keyword_value].append({
                                **control_info,
                                "sourceName": mapping_source.get("sourceName"),
                                "coreControlSourceName": evidence_source.get("sourceName"),
                                "sourceLevel": "coreControl"
                            })

    return dict(config_sources)


def map_evidence_to_rules(framework_file: str, region: str = None, catalog_file: str = None) -> dict:
    """
    Map framework evidence sources to Config rules.

    Args:
        framework_file: Path to framework JSON file
        region: AWS region (optional)
        catalog_file: Path to cached Control Catalog file (optional, avoids API calls)

    Returns:
        Mapping result dictionary
    """
    # Load framework data
    print(f"Loading framework from: {framework_file}")
    with open(framework_file, "r", encoding="utf-8") as f:
        framework_data = json.load(f)

    framework_name = framework_data.get("frameworkName", "Unknown")
    print(f"Framework: {framework_name}")

    # Extract Config evidence sources
    print("\nExtracting AWS_Config evidence sources from framework...")
    config_sources = extract_config_evidence_sources(framework_data)
    print(f"  Found {len(config_sources)} unique Config rule identifiers referenced")

    # Get control descriptions - prefer cached file over API call
    print()
    if catalog_file:
        catalog_descriptions = load_catalog_descriptions_from_file(catalog_file)
    else:
        catalog_descriptions = get_control_catalog_descriptions(region)

    # Get Config rules from AWS
    print()
    config_rules = get_all_config_rules(region, catalog_descriptions)

    # Build mapping
    print("\nMapping evidence sources to Config rules...")

    mapping_result = {
        "frameworkName": framework_name,
        "frameworkId": framework_data.get("frameworkId"),
        "mappings": [],
        "summary": {
            "totalEvidenceSourceIdentifiers": len(config_sources),
            "mappedToConfigRules": 0,
            "notMappedToConfigRules": 0,
            "totalConfigRulesMatched": 0
        }
    }

    mapped_count = 0
    not_mapped_count = 0
    total_rules_matched = 0

    for keyword_value, controls in sorted(config_sources.items()):
        matching_rules = config_rules.get(keyword_value, [])

        mapping_entry = {
            "managedRuleIdentifier": keyword_value,
            "controlsUsingThis": controls,
            "configRulesInAccount": matching_rules,
            "isMapped": len(matching_rules) > 0
        }

        mapping_result["mappings"].append(mapping_entry)

        if matching_rules:
            mapped_count += 1
            total_rules_matched += len(matching_rules)
        else:
            not_mapped_count += 1

    mapping_result["summary"]["mappedToConfigRules"] = mapped_count
    mapping_result["summary"]["notMappedToConfigRules"] = not_mapped_count
    mapping_result["summary"]["totalConfigRulesMatched"] = total_rules_matched

    return mapping_result


def print_summary(mapping_result: dict):
    """Print a human-readable summary of the mapping."""
    summary = mapping_result["summary"]

    print("\n" + "=" * 80)
    print("MAPPING SUMMARY")
    print("=" * 80)
    print(f"Framework: {mapping_result['frameworkName']}")
    print(f"Total evidence source identifiers: {summary['totalEvidenceSourceIdentifiers']}")
    print(f"Mapped to Config rules: {summary['mappedToConfigRules']}")
    print(f"NOT mapped (no matching rules): {summary['notMappedToConfigRules']}")
    print(f"Total Config rules matched: {summary['totalConfigRulesMatched']}")

    # Show unmapped identifiers
    unmapped = [m for m in mapping_result["mappings"] if not m["isMapped"]]
    if unmapped:
        print(f"\n{'=' * 80}")
        print("UNMAPPED IDENTIFIERS (no Config rules found in account)")
        print("=" * 80)
        for m in unmapped:
            print(f"  - {m['managedRuleIdentifier']}")

    # Show mapped identifiers with their rules
    mapped = [m for m in mapping_result["mappings"] if m["isMapped"]]
    if mapped:
        print(f"\n{'=' * 80}")
        print("MAPPED IDENTIFIERS")
        print("=" * 80)
        for m in mapped[:10]:  # Show first 10
            print(f"\n  {m['managedRuleIdentifier']}:")
            for rule in m["configRulesInAccount"]:
                print(f"    -> {rule['ConfigRuleName']}")

        if len(mapped) > 10:
            print(f"\n  ... and {len(mapped) - 10} more (see output file for full list)")


def main():
    parser = argparse.ArgumentParser(
        description="Map AWS Audit Manager evidence sources to AWS Config rules"
    )
    parser.add_argument(
        "framework_file",
        help="Path to framework JSON file (output from get_framework_controls.py)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <framework_file>_config_mapping.json)",
        default=None
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region (uses default region if not specified)",
        default=None
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print full JSON to stdout instead of file"
    )
    parser.add_argument(
        "--catalog-file",
        help="Path to cached Control Catalog JSON file (avoids API calls)",
        default=None
    )

    args = parser.parse_args()

    try:
        mapping_result = map_evidence_to_rules(args.framework_file, args.region, args.catalog_file)

        if args.stdout:
            print(json.dumps(mapping_result, indent=2))
        else:
            output_file = args.output
            if not output_file:
                base_name = args.framework_file.rsplit(".", 1)[0]
                output_file = f"{base_name}_config_mapping.json"

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(mapping_result, f, indent=2)

            print_summary(mapping_result)
            print(f"\nFull mapping written to: {output_file}")

    except FileNotFoundError:
        print(f"Error: Framework file not found: {args.framework_file}", file=sys.stderr)
        sys.exit(1)
    except NoCredentialsError:
        print("Error: AWS credentials not found. Please configure your AWS credentials.", file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        print(f"AWS API Error ({error_code}): {error_message}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
