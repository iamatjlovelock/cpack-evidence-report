#!/usr/bin/env python3
"""
Script to extract controls and mapping sources from an AWS Audit Manager framework.
Calls GetAssessmentFramework API and outputs results in JSON format.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

import boto3


def natural_sort_key(text: str, appendix_last: bool = False) -> tuple:
    """
    Generate a sort key for natural sorting (numbers sorted numerically).

    Args:
        text: The string to generate a sort key for
        appendix_last: If True, appendices are sorted to the end

    Returns:
        Tuple that can be used as a sort key
    """
    # Check if this is an appendix
    is_appendix = text.lower().startswith("appendix")

    # Split text into chunks of digits and non-digits
    chunks = re.split(r'(\d+)', text)

    # Convert digit chunks to integers for proper numerical sorting
    key_parts = []
    for chunk in chunks:
        if chunk.isdigit():
            key_parts.append(int(chunk))
        else:
            key_parts.append(chunk.lower())

    # If appendix_last is True, appendices sort after everything else
    if appendix_last:
        return (1 if is_appendix else 0, key_parts)

    return tuple(key_parts)
from botocore.exceptions import ClientError, NoCredentialsError


def get_control_details(client, control_id: str, cache: dict = None) -> dict:
    """
    Retrieve full control details including mapping sources.

    Args:
        client: boto3 auditmanager client
        control_id: The ID of the control
        cache: Optional cache dictionary to avoid duplicate API calls

    Returns:
        Dictionary containing full control details
    """
    if cache is not None and control_id in cache:
        return cache[control_id]

    response = client.get_control(controlId=control_id)
    control = response.get("control", {})

    if cache is not None:
        cache[control_id] = control

    return control


def get_core_control_evidence_sources(client, source: dict, cache: dict) -> list:
    """
    Retrieve evidence sources from a Core Control.

    Args:
        client: boto3 auditmanager client
        source: The controlMappingSource dict containing sourceId and sourceKeyword
        cache: Cache dictionary to avoid duplicate API calls

    Returns:
        List of evidence sources from the Core Control
    """
    # Try sourceId first, then fall back to sourceKeyword.keywordValue
    source_id = source.get("sourceId")
    keyword_value = source.get("sourceKeyword", {}).get("keywordValue")

    core_control = None

    # Try sourceId first
    if source_id:
        try:
            core_control = get_control_details(client, source_id, cache)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    # Fall back to keywordValue if sourceId failed
    if core_control is None and keyword_value:
        try:
            core_control = get_control_details(client, keyword_value, cache)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

    if core_control is None:
        return []

    evidence_sources = []

    for src in core_control.get("controlMappingSources", []):
        evidence_source = {
            "sourceId": src.get("sourceId"),
            "sourceName": src.get("sourceName"),
            "sourceDescription": src.get("sourceDescription"),
            "sourceType": src.get("sourceType"),
            "sourceSetUpOption": src.get("sourceSetUpOption"),
            "sourceFrequency": src.get("sourceFrequency"),
            "troubleshootingText": src.get("troubleshootingText")
        }

        if src.get("sourceKeyword"):
            evidence_source["sourceKeyword"] = {
                "keywordInputType": src["sourceKeyword"].get("keywordInputType"),
                "keywordValue": src["sourceKeyword"].get("keywordValue")
            }

        evidence_sources.append(evidence_source)

    return evidence_sources


def get_framework_controls(framework_id: str, region: str = None) -> dict:
    """
    Retrieve framework details and extract controls with their mapping sources.

    Args:
        framework_id: The ID of the Audit Manager framework
        region: AWS region (optional, uses default if not specified)

    Returns:
        Dictionary containing framework info and controls with mapping sources
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("auditmanager", **client_kwargs)

    # Cache for Core Controls to avoid duplicate API calls
    core_control_cache = {}

    response = client.get_assessment_framework(frameworkId=framework_id)
    framework = response["framework"]

    result = {
        "frameworkId": framework.get("id"),
        "frameworkName": framework.get("name"),
        "frameworkDescription": framework.get("description"),
        "frameworkType": framework.get("type"),
        "complianceType": framework.get("complianceType"),
        "createdAt": framework.get("createdAt").isoformat() if framework.get("createdAt") else None,
        "lastUpdatedAt": framework.get("lastUpdatedAt").isoformat() if framework.get("lastUpdatedAt") else None,
        "extractedAt": datetime.now(timezone.utc).isoformat(),
        "controlSets": []
    }

    # Count total controls for progress
    total_controls = sum(len(cs.get("controls", [])) for cs in framework.get("controlSets", []))
    processed = 0

    for control_set in framework.get("controlSets", []):
        control_set_data = {
            "controlSetId": control_set.get("id"),
            "controlSetName": control_set.get("name"),
            "controls": []
        }

        for control in control_set.get("controls", []):
            control_id = control.get("id")
            processed += 1
            print(f"  Fetching control {processed}/{total_controls}: {control.get('name', control_id)[:60]}...")

            # Fetch full control details to get mapping sources
            full_control = get_control_details(client, control_id)

            control_data = {
                "controlId": full_control.get("id"),
                "controlName": full_control.get("name"),
                "controlDescription": full_control.get("description"),
                "controlType": full_control.get("type"),
                "testingInformation": full_control.get("testingInformation"),
                "actionPlanTitle": full_control.get("actionPlanTitle"),
                "actionPlanInstructions": full_control.get("actionPlanInstructions"),
                "controlMappingSources": []
            }

            for source in full_control.get("controlMappingSources", []):
                source_data = {
                    "sourceId": source.get("sourceId"),
                    "sourceName": source.get("sourceName"),
                    "sourceDescription": source.get("sourceDescription"),
                    "sourceType": source.get("sourceType"),
                    "sourceSetUpOption": source.get("sourceSetUpOption"),
                    "sourceFrequency": source.get("sourceFrequency"),
                    "troubleshootingText": source.get("troubleshootingText")
                }

                # Include source keyword if present
                if source.get("sourceKeyword"):
                    source_data["sourceKeyword"] = {
                        "keywordInputType": source["sourceKeyword"].get("keywordInputType"),
                        "keywordValue": source["sourceKeyword"].get("keywordValue")
                    }

                # Include AWS service source details if present
                if source.get("sourceType") == "AWS_API_Call":
                    aws_service = source.get("sourceKeyword", {})
                    if aws_service:
                        source_data["awsService"] = aws_service.get("keywordValue")

                # For Core_Control sources, fetch the underlying evidence sources
                if source.get("sourceType") == "Core_Control":
                    evidence_sources = get_core_control_evidence_sources(
                        client, source, core_control_cache
                    )
                    source_data["coreControlEvidenceSources"] = evidence_sources

                control_data["controlMappingSources"].append(source_data)

            control_set_data["controls"].append(control_data)

        result["controlSets"].append(control_set_data)

    # Sort control sets using natural sort (numbers sorted numerically, appendices last)
    result["controlSets"].sort(key=lambda cs: natural_sort_key(cs.get("controlSetName", ""), appendix_last=True))

    # Sort controls within each control set using natural sort
    for control_set in result["controlSets"]:
        control_set["controls"].sort(key=lambda c: natural_sort_key(c.get("controlName", "")))

    # Add summary statistics
    total_controls = sum(len(cs["controls"]) for cs in result["controlSets"])
    total_mapping_sources = sum(
        len(c["controlMappingSources"])
        for cs in result["controlSets"]
        for c in cs["controls"]
    )
    total_core_control_evidence_sources = sum(
        len(s.get("coreControlEvidenceSources", []))
        for cs in result["controlSets"]
        for c in cs["controls"]
        for s in c["controlMappingSources"]
    )

    result["summary"] = {
        "totalControlSets": len(result["controlSets"]),
        "totalControls": total_controls,
        "totalMappingSources": total_mapping_sources,
        "totalCoreControlsReferenced": len(core_control_cache),
        "totalCoreControlEvidenceSources": total_core_control_evidence_sources
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Extract controls and mapping sources from an AWS Audit Manager framework"
    )
    parser.add_argument(
        "framework_id",
        help="The ID of the Audit Manager framework to retrieve"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <framework_id>_controls.json)",
        default=None
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region (uses default region if not specified)",
        default=None
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON output",
        default=True
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout instead of file"
    )

    args = parser.parse_args()

    try:
        print(f"Retrieving framework: {args.framework_id}...")
        result = get_framework_controls(args.framework_id, args.region)

        indent = 2 if args.pretty else None
        json_output = json.dumps(result, indent=indent, default=str)

        if args.stdout:
            print(json_output)
        else:
            output_file = args.output or f"{args.framework_id}_controls.json"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"Successfully wrote controls to: {output_file}")
            print(f"Summary: {result['summary']['totalControlSets']} control sets, "
                  f"{result['summary']['totalControls']} controls, "
                  f"{result['summary']['totalMappingSources']} mapping sources, "
                  f"{result['summary']['totalCoreControlsReferenced']} unique Core Controls, "
                  f"{result['summary']['totalCoreControlEvidenceSources']} Core Control evidence sources")

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
