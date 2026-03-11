#!/usr/bin/env python3
"""
Script to retrieve AWS Config configuration items for all resources
listed in a compliance report.

Input: Compliance report JSON file (output from generate_compliance_report.py)
Output: JSON file with configuration items for each resource
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def load_json_file(file_path: str) -> dict:
    """Load and parse a JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def make_resource_key(resource_type: str, resource_id: str) -> str:
    """
    Create a unique key for a resource that can be used for cross-referencing.

    Args:
        resource_type: AWS resource type (e.g., AWS::S3::Bucket)
        resource_id: Resource identifier

    Returns:
        Unique resource key string
    """
    return f"{resource_type}|{resource_id}"


def extract_resources_from_report(report: dict) -> list:
    """
    Extract unique resources from a compliance report.

    Args:
        report: Compliance report JSON

    Returns:
        List of unique resources with resourceType and resourceId
    """
    resources = {}

    for control_set in report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for evidence_source in control.get("evidenceSources", []):
                for eval_result in evidence_source.get("evaluationResults", []):
                    resource_type = eval_result.get("resourceType")
                    resource_id = eval_result.get("resourceId")

                    if resource_type and resource_id:
                        # Use resourceKey for deduplication and cross-referencing
                        resource_key = make_resource_key(resource_type, resource_id)
                        if resource_key not in resources:
                            resources[resource_key] = {
                                "resourceKey": resource_key,
                                "resourceType": resource_type,
                                "resourceId": resource_id
                            }

    return list(resources.values())


def get_resource_configuration(client, resource_type: str, resource_id: str) -> dict:
    """
    Get the current configuration for a resource.

    Args:
        client: boto3 config client
        resource_type: AWS resource type (e.g., AWS::S3::Bucket)
        resource_id: Resource identifier

    Returns:
        Configuration item dictionary or None if not found
    """
    try:
        response = client.get_resource_config_history(
            resourceType=resource_type,
            resourceId=resource_id,
            limit=1  # Get only the latest configuration
        )

        config_items = response.get("configurationItems", [])
        if config_items:
            return config_items[0]

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ["ResourceNotDiscoveredException", "NoAvailableConfigurationRecorderException"]:
            return None
        raise

    return None


def batch_get_resource_configurations(client, resources: list) -> dict:
    """
    Get configurations for multiple resources using batch API.

    Args:
        client: boto3 config client
        resources: List of resource dicts with resourceType and resourceId

    Returns:
        Dictionary mapping (resourceType, resourceId) to configuration
    """
    configurations = {}

    # batch_get_resource_config has a limit of 100 resources per call
    batch_size = 100

    for i in range(0, len(resources), batch_size):
        batch = resources[i:i + batch_size]

        resource_keys = [
            {
                "resourceType": r["resourceType"],
                "resourceId": r["resourceId"]
            }
            for r in batch
        ]

        try:
            response = client.batch_get_resource_config(
                resourceKeys=resource_keys
            )

            for item in response.get("baseConfigurationItems", []):
                key = (item["resourceType"], item["resourceId"])
                configurations[key] = item

            # Track unprocessed keys
            for unprocessed in response.get("unprocessedResourceKeys", []):
                key = (unprocessed["resourceType"], unprocessed["resourceId"])
                configurations[key] = None

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoAvailableConfigurationRecorderException":
                print(f"  Warning: No configuration recorder available", file=sys.stderr)
                break
            raise

    return configurations


def get_all_resource_configurations(report_file: str, region: str = None) -> dict:
    """
    Get configurations for all resources in a compliance report.

    Args:
        report_file: Path to compliance report JSON file
        region: AWS region (optional)

    Returns:
        Result dictionary with resource configurations
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("config", **client_kwargs)

    # Load report
    print(f"Loading compliance report: {report_file}")
    report = load_json_file(report_file)

    # Extract resources
    print("Extracting resources from report...")
    resources = extract_resources_from_report(report)
    print(f"  Found {len(resources)} unique resources")

    # Group resources by type for summary
    resources_by_type = defaultdict(list)
    for r in resources:
        resources_by_type[r["resourceType"]].append(r)

    print("\nResources by type:")
    for resource_type, items in sorted(resources_by_type.items()):
        print(f"  {resource_type}: {len(items)}")

    # Get configurations
    print(f"\nFetching configurations for {len(resources)} resources...")

    # Try batch API first
    configurations = {}
    try:
        configurations = batch_get_resource_configurations(client, resources)
        print(f"  Retrieved {len([v for v in configurations.values() if v])} configurations via batch API")
    except ClientError as e:
        print(f"  Batch API failed, falling back to individual queries: {e}")

    # For any resources not retrieved via batch, try individual queries
    missing_resources = [
        r for r in resources
        if (r["resourceType"], r["resourceId"]) not in configurations
    ]

    if missing_resources:
        print(f"  Fetching {len(missing_resources)} resources individually...")
        for i, resource in enumerate(missing_resources):
            if (i + 1) % 10 == 0:
                print(f"    Processing {i + 1}/{len(missing_resources)}...")

            config = get_resource_configuration(
                client,
                resource["resourceType"],
                resource["resourceId"]
            )
            key = (resource["resourceType"], resource["resourceId"])
            configurations[key] = config

    # Build result
    result = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "sourceReport": report_file,
        "frameworkName": report.get("frameworkName"),
        "conformancePackName": report.get("conformancePackName"),
        "configurations": {},  # Keyed by resourceKey for easy lookup
        "summary": {
            "totalResources": len(resources),
            "configurationsRetrieved": 0,
            "configurationsNotFound": 0,
            "resourceTypes": {}
        }
    }

    # Process each resource
    for resource in resources:
        key = (resource["resourceType"], resource["resourceId"])
        config = configurations.get(key)
        resource_key = resource["resourceKey"]

        config_entry = {
            "resourceKey": resource_key,
            "resourceType": resource["resourceType"],
            "resourceId": resource["resourceId"],
            "configurationFound": config is not None,
            "configuration": None
        }

        if config:
            result["summary"]["configurationsRetrieved"] += 1

            # Parse the configuration JSON if it's a string
            configuration_data = config.get("configuration")
            if isinstance(configuration_data, str):
                try:
                    configuration_data = json.loads(configuration_data)
                except json.JSONDecodeError:
                    pass

            config_entry["configuration"] = {
                "configurationItemCaptureTime": config.get("configurationItemCaptureTime").isoformat()
                    if config.get("configurationItemCaptureTime") else None,
                "configurationStateId": config.get("configurationStateId"),
                "arn": config.get("arn"),
                "resourceName": config.get("resourceName"),
                "awsRegion": config.get("awsRegion"),
                "availabilityZone": config.get("availabilityZone"),
                "resourceCreationTime": config.get("resourceCreationTime").isoformat()
                    if config.get("resourceCreationTime") else None,
                "configuration": configuration_data,
                "supplementaryConfiguration": config.get("supplementaryConfiguration"),
                "tags": config.get("tags")
            }
        else:
            result["summary"]["configurationsNotFound"] += 1

        # Store by resourceKey for cross-referencing
        result["configurations"][resource_key] = config_entry

        # Update type summary
        resource_type = resource["resourceType"]
        if resource_type not in result["summary"]["resourceTypes"]:
            result["summary"]["resourceTypes"][resource_type] = {
                "total": 0,
                "configurationsFound": 0
            }
        result["summary"]["resourceTypes"][resource_type]["total"] += 1
        if config:
            result["summary"]["resourceTypes"][resource_type]["configurationsFound"] += 1

    return result


def print_summary(result: dict):
    """Print a human-readable summary."""
    summary = result["summary"]

    print("\n" + "=" * 80)
    print("RESOURCE CONFIGURATION SUMMARY")
    print("=" * 80)
    print(f"Framework: {result['frameworkName']}")
    print(f"Conformance Pack: {result['conformancePackName']}")
    print(f"Source Report: {result['sourceReport']}")
    print()
    print(f"Total Resources: {summary['totalResources']}")
    print(f"Configurations Retrieved: {summary['configurationsRetrieved']}")
    print(f"Configurations Not Found: {summary['configurationsNotFound']}")

    print("\nBy Resource Type:")
    for resource_type, stats in sorted(summary["resourceTypes"].items()):
        found = stats["configurationsFound"]
        total = stats["total"]
        print(f"  {resource_type}: {found}/{total} configurations found")


def main():
    parser = argparse.ArgumentParser(
        description="Get AWS Config configuration items for resources in a compliance report"
    )
    parser.add_argument(
        "report_file",
        help="Path to compliance report JSON file (output from generate_compliance_report.py)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <report_file>_configurations.json)",
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

    args = parser.parse_args()

    try:
        result = get_all_resource_configurations(args.report_file, args.region)

        if args.stdout:
            print(json.dumps(result, indent=2, default=str))
        else:
            output_file = args.output
            if not output_file:
                base_name = args.report_file.rsplit(".", 1)[0]
                output_file = f"{base_name}_configurations.json"

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)

            print_summary(result)
            print(f"\nFull results written to: {output_file}")

    except FileNotFoundError:
        print(f"Error: Report file not found: {args.report_file}", file=sys.stderr)
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
