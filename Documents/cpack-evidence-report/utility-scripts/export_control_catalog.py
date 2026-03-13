#!/usr/bin/env python3
"""
Export all Config rules from AWS Control Catalog to a JSON file.

This script fetches all detective controls (Config rules) from the Control Catalog API
and caches them locally for use by other scripts in the workflow.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_all_control_mappings(client) -> dict:
    """
    Fetch all control mappings using ListControlMappings API.

    Args:
        client: boto3 controlcatalog client

    Returns:
        Dict mapping control ARN to list of framework mappings
    """
    mappings_by_arn = {}

    try:
        paginator = client.get_paginator("list_control_mappings")

        for page in paginator.paginate(MaxResults=100):
            for mapping in page.get("ControlMappings", []):
                control_arn = mapping.get("ControlArn", "")
                if not control_arn:
                    continue

                mapping_type = mapping.get("MappingType", "")
                mapping_data = mapping.get("Mapping", {})

                # Extract framework info
                if mapping_type == "FRAMEWORK" and "Framework" in mapping_data:
                    framework = mapping_data["Framework"]
                    mapping_info = {
                        "frameworkName": framework.get("Name", ""),
                        "item": framework.get("Item", "")
                    }

                    if control_arn not in mappings_by_arn:
                        mappings_by_arn[control_arn] = []
                    mappings_by_arn[control_arn].append(mapping_info)

    except Exception as e:
        print(f"  Warning: Could not fetch control mappings: {e}", file=sys.stderr)

    return mappings_by_arn


def export_control_catalog(region: str = None) -> dict:
    """
    Export all Config rules from AWS Control Catalog.

    Args:
        region: AWS region (optional)

    Returns:
        Dict containing all controls and metadata
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("controlcatalog", **client_kwargs)

    controls = {}

    print("Fetching all Config rules from AWS Control Catalog...")
    try:
        paginator = client.get_paginator("list_controls")

        for page in paginator.paginate(MaxResults=100):
            for control in page.get("Controls", []):
                impl = control.get("Implementation", {})
                impl_type = impl.get("Type", "")
                identifier = impl.get("Identifier", "")

                # Only include Config rules
                if impl_type == "AWS::Config::ConfigRule" and identifier:
                    # Handle Behavior - API returns string directly
                    behavior_val = control.get("Behavior")
                    behavior_type = str(behavior_val) if behavior_val else "N/A"

                    # Handle Severity - API returns string directly
                    severity_val = control.get("Severity")
                    severity_value = str(severity_val) if severity_val else "N/A"

                    # Handle GovernedResources - list of resource types
                    governed_resources = control.get("GovernedResources", [])
                    if isinstance(governed_resources, list):
                        governed_resources_list = governed_resources
                    else:
                        governed_resources_list = [str(governed_resources)] if governed_resources else []

                    controls[identifier] = {
                        "arn": control.get("Arn", ""),
                        "name": control.get("Name", ""),
                        "description": control.get("Description", ""),
                        "behavior": behavior_type,
                        "severity": severity_value,
                        "governedResources": governed_resources_list,
                        "implementationType": impl_type,
                        "identifier": identifier
                    }

        print(f"  Found {len(controls)} Config rule controls in catalog")

        # Fetch all control mappings
        print("Fetching control mappings...")
        all_mappings = get_all_control_mappings(client)
        print(f"  Found mappings for {len(all_mappings)} controls")

        # Associate mappings with controls
        for identifier, control_data in controls.items():
            arn = control_data.get("arn", "")
            if arn and arn in all_mappings:
                controls[identifier]["mappings"] = all_mappings[arn]

    except Exception as e:
        print(f"Error fetching from Control Catalog: {e}", file=sys.stderr)
        raise

    return {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "totalControls": len(controls),
        "controls": controls
    }


def main():
    parser = argparse.ArgumentParser(
        description="Export all Config rules from AWS Control Catalog"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path (default: control-catalog/detective-controls.json)",
        default="control-catalog/detective-controls.json"
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region (uses default region if not specified)",
        default=None
    )

    args = parser.parse_args()

    try:
        # Create output directory if needed
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"Created output folder: {output_dir}")

        # Export Control Catalog
        catalog_data = export_control_catalog(args.region)

        # Write to file
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(catalog_data, f, indent=2)

        print(f"\nControl Catalog exported to: {args.output}")
        print(f"  Total controls: {catalog_data['totalControls']}")
        print(f"  Exported at: {catalog_data['exportedAt']}")

    except NoCredentialsError:
        print("Error: AWS credentials not found. Please configure your AWS credentials.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
