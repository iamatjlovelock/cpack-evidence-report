#!/usr/bin/env python3
"""
Extract Config rules from conformance pack YAML templates.

This script parses YAML files from the conformance-packs/conformance-pack-yamls folder and
creates CSV files listing the Config rules defined in each conformance pack.
"""

import argparse
import csv
import os
import sys

import yaml


def parse_conformance_pack_yaml(yaml_path: str) -> list:
    """
    Parse a conformance pack YAML file and extract Config rules.

    Args:
        yaml_path: Path to the YAML file

    Returns:
        List of dicts with ConfigRuleName and SourceIdentifier
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = []
    resources = data.get("Resources", {})

    for resource_name, resource_def in resources.items():
        if resource_def.get("Type") == "AWS::Config::ConfigRule":
            properties = resource_def.get("Properties", {})
            config_rule_name = properties.get("ConfigRuleName", "")
            source = properties.get("Source", {})
            source_identifier = source.get("SourceIdentifier", "")

            rules.append({
                "ConfigRuleName": config_rule_name,
                "SourceIdentifier": source_identifier
            })

    return rules


def write_csv(rules: list, output_path: str) -> None:
    """
    Write Config rules to a CSV file.

    Args:
        rules: List of rule dicts
        output_path: Path to output CSV file
    """
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ConfigRuleName", "SourceIdentifier"])
        writer.writeheader()
        writer.writerows(rules)


def process_yaml_file(yaml_path: str, output_folder: str) -> tuple:
    """
    Process a single YAML file and create corresponding CSV.

    Args:
        yaml_path: Path to the YAML file
        output_folder: Folder to write CSV output

    Returns:
        Tuple of (yaml_name, rule_count, success, error)
    """
    yaml_name = os.path.basename(yaml_path)

    try:
        rules = parse_conformance_pack_yaml(yaml_path)

        # Create CSV filename from YAML filename
        csv_name = yaml_name.replace(".yaml", ".csv")
        csv_path = os.path.join(output_folder, csv_name)

        write_csv(rules, csv_path)

        return (yaml_name, len(rules), True, None)
    except Exception as e:
        return (yaml_name, 0, False, str(e))


def main():
    parser = argparse.ArgumentParser(
        description="Extract Config rules from conformance pack YAML templates"
    )
    parser.add_argument(
        "yaml_file",
        nargs="?",
        help="Specific YAML file to process (processes all if not specified)"
    )
    parser.add_argument(
        "-i", "--input-folder",
        help="Input folder containing YAML files (default: conformance-packs/conformance-pack-yamls)",
        default="conformance-packs/conformance-pack-yamls"
    )
    parser.add_argument(
        "-o", "--output-folder",
        help="Output folder for CSV files (default: conformance-packs/conformance-pack-rules)",
        default="conformance-packs/conformance-pack-rules"
    )

    args = parser.parse_args()

    # Validate input folder exists
    if not os.path.exists(args.input_folder):
        print(f"Error: Input folder not found: {args.input_folder}", file=sys.stderr)
        return 1

    # Create output folder if needed
    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder)
        print(f"Created output folder: {args.output_folder}")

    # Determine which files to process
    if args.yaml_file:
        # Process specific file
        if os.path.isabs(args.yaml_file):
            yaml_path = args.yaml_file
        else:
            yaml_path = os.path.join(args.input_folder, args.yaml_file)

        if not os.path.exists(yaml_path):
            print(f"Error: YAML file not found: {yaml_path}", file=sys.stderr)
            return 1

        yaml_files = [yaml_path]
    else:
        # Process all YAML files in folder
        yaml_files = [
            os.path.join(args.input_folder, f)
            for f in os.listdir(args.input_folder)
            if f.endswith(".yaml")
        ]
        yaml_files.sort()

    if not yaml_files:
        print("No YAML files found to process.")
        return 1

    print(f"Processing {len(yaml_files)} YAML file(s)...\n")

    success_count = 0
    fail_count = 0
    total_rules = 0

    for yaml_path in yaml_files:
        yaml_name, rule_count, success, error = process_yaml_file(yaml_path, args.output_folder)

        if success:
            success_count += 1
            total_rules += rule_count
            print(f"  {yaml_name}: {rule_count} rules")
        else:
            fail_count += 1
            print(f"  {yaml_name}: FAILED - {error}", file=sys.stderr)

    print(f"\nProcessing complete:")
    print(f"  Files processed: {success_count}")
    print(f"  Files failed: {fail_count}")
    print(f"  Total rules extracted: {total_rules}")
    print(f"  Output folder: {os.path.abspath(args.output_folder)}")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
