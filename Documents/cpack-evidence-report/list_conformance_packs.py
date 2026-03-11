#!/usr/bin/env python3
"""
Script to list all AWS Config conformance packs in the account.
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def list_conformance_packs(region: str = None) -> list:
    """
    List all conformance packs in the account.

    Args:
        region: AWS region (optional)

    Returns:
        List of conformance pack details
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("config", **client_kwargs)

    conformance_packs = []

    print("Fetching conformance packs...")
    paginator = client.get_paginator("describe_conformance_packs")

    for page in paginator.paginate():
        for pack in page.get("ConformancePackDetails", []):
            conformance_packs.append({
                "ConformancePackName": pack.get("ConformancePackName"),
                "ConformancePackArn": pack.get("ConformancePackArn"),
                "ConformancePackId": pack.get("ConformancePackId"),
                "CreatedBy": pack.get("CreatedBy"),
                "LastUpdateRequestedTime": pack.get("LastUpdateRequestedTime").isoformat()
                    if pack.get("LastUpdateRequestedTime") else None
            })

    return conformance_packs


def main():
    parser = argparse.ArgumentParser(
        description="List all AWS Config conformance packs in the account"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: conformance_packs.json)",
        default="conformance_packs.json"
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region (uses default region if not specified)",
        default=None
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout instead of file"
    )

    args = parser.parse_args()

    try:
        conformance_packs = list_conformance_packs(args.region)

        result = {
            "totalConformancePacks": len(conformance_packs),
            "conformancePacks": conformance_packs
        }

        if args.stdout:
            print(json.dumps(result, indent=2))
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

            print(f"\nFound {len(conformance_packs)} conformance packs:")
            for pack in conformance_packs:
                print(f"  - {pack['ConformancePackName']}")
                if pack.get("CreatedBy"):
                    print(f"    Created by: {pack['CreatedBy']}")

            print(f"\nFull list written to: {args.output}")

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
