#!/usr/bin/env python3
"""
Script to generate a compliance report for an AWS Audit Manager framework
based on AWS Config conformance pack evaluation results.

Inputs:
1. Conformance pack name
2. Framework JSON from get_framework_controls.py
3. Config mapping JSON from map_config_rules.py

Output:
A compliance report showing controls grouped by control set with their
AWS Config evaluation results.
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
    Create a unique key for a resource that can be used for cross-referencing
    with the resource configurations file.

    Args:
        resource_type: AWS resource type (e.g., AWS::S3::Bucket)
        resource_id: Resource identifier

    Returns:
        Unique resource key string
    """
    return f"{resource_type}|{resource_id}"


def get_conformance_pack_rule_names(client, conformance_pack_name: str) -> set:
    """
    Get all Config rule names associated with a conformance pack.

    Args:
        client: boto3 config client
        conformance_pack_name: Name of the conformance pack

    Returns:
        Set of Config rule names in the conformance pack
    """
    rule_names = set()
    next_token = None

    try:
        while True:
            if next_token:
                response = client.describe_conformance_pack_compliance(
                    ConformancePackName=conformance_pack_name,
                    NextToken=next_token
                )
            else:
                response = client.describe_conformance_pack_compliance(
                    ConformancePackName=conformance_pack_name
                )

            for rule in response.get("ConformancePackRuleComplianceList", []):
                rule_names.add(rule["ConfigRuleName"])

            next_token = response.get("NextToken")
            if not next_token:
                break

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchConformancePackException":
            print(f"Error: Conformance pack '{conformance_pack_name}' not found.", file=sys.stderr)
            sys.exit(1)
        raise

    return rule_names


def get_conformance_pack_compliance_details(
    client,
    conformance_pack_name: str,
    config_rule_name: str
) -> list:
    """
    Get compliance details for a specific Config rule within a conformance pack.

    Args:
        client: boto3 config client
        conformance_pack_name: Name of the conformance pack
        config_rule_name: Name of the Config rule

    Returns:
        List of evaluation results for resources
    """
    results = []
    next_token = None

    try:
        while True:
            kwargs = {
                "ConformancePackName": conformance_pack_name,
                "Filters": {"ConfigRuleNames": [config_rule_name]}
            }
            if next_token:
                kwargs["NextToken"] = next_token

            response = client.get_conformance_pack_compliance_details(**kwargs)

            for result in response.get("ConformancePackRuleEvaluationResults", []):
                eval_result = result.get("EvaluationResultIdentifier", {})
                qual = eval_result.get("EvaluationResultQualifier", {})

                resource_type = qual.get("ResourceType")
                resource_id = qual.get("ResourceId")

                results.append({
                    "resourceKey": make_resource_key(resource_type, resource_id) if resource_type and resource_id else None,
                    "resourceType": resource_type,
                    "resourceId": resource_id,
                    "complianceType": result.get("ComplianceType"),
                    "configRuleName": qual.get("ConfigRuleName"),
                    "resultRecordedTime": result.get("ResultRecordedTime").isoformat()
                        if result.get("ResultRecordedTime") else None,
                    "annotation": result.get("Annotation")
                })

            next_token = response.get("NextToken")
            if not next_token:
                break

    except ClientError as e:
        # Rule might not be in the conformance pack
        if e.response["Error"]["Code"] in [
            "NoSuchConfigRuleException",
            "NoSuchConformancePackException",
            "NoSuchConfigRuleInConformancePackException"
        ]:
            return []
        raise

    return results


def build_keyword_to_cpack_rule_map(config_mapping: dict, cpack_rule_names: set) -> tuple:
    """
    Build a mapping from keyword values to conformance pack rule names and descriptions.
    Handles both AWS_Config and AWS_Security_Hub source types.

    Args:
        config_mapping: Config mapping JSON from map_config_rules.py
        cpack_rule_names: Set of rule names in the conformance pack

    Returns:
        Tuple of (keyword_to_rule dict, keyword_to_description dict)
    """
    keyword_to_rule = {}
    keyword_to_description = {}

    for mapping in config_mapping.get("mappings", []):
        # Support both old format (managedRuleIdentifier) and new format (identifier)
        keyword = mapping.get("identifier") or mapping.get("managedRuleIdentifier")
        source_type = mapping.get("sourceType", "AWS_Config")

        # Find the rule that's in the conformance pack or mapped from Security Hub
        for rule in mapping.get("configRulesInAccount", []):
            rule_name = rule["ConfigRuleName"]

            # For AWS_Config sources, check if rule is in conformance pack
            # For AWS_Security_Hub sources, always include the mapping
            if rule_name in cpack_rule_names or source_type == "AWS_Security_Hub":
                # Create composite key for Security Hub sources to avoid conflicts
                if source_type == "AWS_Security_Hub":
                    map_key = f"SecurityHub:{keyword}"
                else:
                    map_key = keyword

                keyword_to_rule[map_key] = rule_name
                keyword_to_description[map_key] = rule.get("Description", "")
                break  # Use first matching rule

    return keyword_to_rule, keyword_to_description


def generate_compliance_report(
    conformance_pack_name: str,
    framework_data: dict,
    config_mapping: dict,
    region: str = None
) -> dict:
    """
    Generate a compliance report for the framework based on conformance pack results.

    Args:
        conformance_pack_name: Name of the conformance pack
        framework_data: Framework JSON from get_framework_controls.py
        config_mapping: Config mapping JSON from map_config_rules.py
        region: AWS region (optional)

    Returns:
        Compliance report dictionary
    """
    client_kwargs = {}
    if region:
        client_kwargs["region_name"] = region

    client = boto3.client("config", **client_kwargs)

    # Get conformance pack rules
    print(f"Fetching rules from conformance pack: {conformance_pack_name}...")
    cpack_rule_names = get_conformance_pack_rule_names(client, conformance_pack_name)
    print(f"  Found {len(cpack_rule_names)} rules in conformance pack")

    # Build keyword to conformance pack rule mapping
    print("\nBuilding keyword to conformance pack rule mapping...")
    keyword_to_rule, keyword_to_description = build_keyword_to_cpack_rule_map(config_mapping, cpack_rule_names)
    print(f"  Mapped {len(keyword_to_rule)} keywords to conformance pack rules")

    # Cache for compliance results to avoid duplicate API calls
    compliance_cache = {}

    # Identify conformance pack rules not referenced by the framework
    referenced_rules = set(keyword_to_rule.values())
    extra_rules = cpack_rule_names - referenced_rules
    print(f"  Found {len(extra_rules)} conformance pack rules not referenced by framework")

    # Build the report
    report = {
        "reportGeneratedAt": datetime.now(timezone.utc).isoformat(),
        "conformancePackName": conformance_pack_name,
        "frameworkName": framework_data.get("frameworkName"),
        "frameworkId": framework_data.get("frameworkId"),
        "conformancePackRulesNotInFramework": sorted(list(extra_rules)),
        "controlSets": [],
        "summary": {
            "totalControlSets": 0,
            "totalControls": 0,
            "totalEvidenceSources": 0,
            "awsConfigEvidenceSources": 0,
            "awsSecurityHubEvidenceSources": 0,
            "mappedToConformancePack": 0,
            "mappedFromSecurityHub": 0,
            "notMappedToConformancePack": 0,
            "conformancePackRulesNotInFramework": len(extra_rules),
            "compliantResources": 0,
            "nonCompliantResources": 0,
            "notApplicableResources": 0
        }
    }

    total_controls = sum(
        len(cs.get("controls", []))
        for cs in framework_data.get("controlSets", [])
    )
    processed = 0

    print(f"\nProcessing {total_controls} controls...")

    for control_set in framework_data.get("controlSets", []):
        control_set_report = {
            "controlSetId": control_set.get("controlSetId"),
            "controlSetName": control_set.get("controlSetName"),
            "controls": [],
            "summary": {
                "totalControls": 0,
                "compliantResources": 0,
                "nonCompliantResources": 0
            }
        }

        for control in control_set.get("controls", []):
            processed += 1
            control_name = control.get("controlName", "")[:60]
            print(f"  Processing control {processed}/{total_controls}: {control_name}...")

            control_report = {
                "controlId": control.get("controlId"),
                "controlName": control.get("controlName"),
                "controlDescription": control.get("controlDescription"),
                "evidenceSources": [],
                "summary": {
                    "totalEvidenceSources": 0,
                    "awsConfigSources": 0,
                    "awsSecurityHubSources": 0,
                    "mappedToConformancePack": 0,
                    "mappedFromSecurityHub": 0,
                    "compliantResources": 0,
                    "nonCompliantResources": 0,
                    "notApplicableResources": 0
                }
            }

            # Process each mapping source
            for mapping_source in control.get("controlMappingSources", []):
                # Some frameworks use coreControlEvidenceSources (Core Control references)
                # Others have the evidence source directly on the mapping source
                core_evidence_sources = mapping_source.get("coreControlEvidenceSources", [])

                # If no core evidence sources, treat the mapping source itself as an evidence source
                if not core_evidence_sources and mapping_source.get("sourceKeyword"):
                    evidence_sources_to_process = [mapping_source]
                else:
                    evidence_sources_to_process = core_evidence_sources

                for evidence_source in evidence_sources_to_process:
                    report["summary"]["totalEvidenceSources"] += 1
                    control_report["summary"]["totalEvidenceSources"] += 1

                    keyword_value = evidence_source.get("sourceKeyword", {}).get("keywordValue")
                    # Get description: prefer config mapping (from Controls Catalog), fall back to framework
                    source_description = (
                        keyword_to_description.get(keyword_value) or
                        evidence_source.get("sourceDescription") or
                        mapping_source.get("sourceDescription")
                    )

                    source_report = {
                        "sourceName": evidence_source.get("sourceName") or mapping_source.get("sourceName"),
                        "sourceDescription": source_description,
                        "sourceType": evidence_source.get("sourceType"),
                        "keywordValue": keyword_value,
                        "configRuleName": None,
                        "inConformancePack": False,
                        "evaluationResults": [],
                        "complianceSummary": {
                            "compliant": 0,
                            "nonCompliant": 0,
                            "notApplicable": 0
                        }
                    }

                    source_type = evidence_source.get("sourceType")

                    # Handle AWS_Config sources
                    if source_type == "AWS_Config":
                        report["summary"]["awsConfigEvidenceSources"] += 1
                        control_report["summary"]["awsConfigSources"] += 1

                        if keyword_value and keyword_value in keyword_to_rule:
                            config_rule_name = keyword_to_rule[keyword_value]
                            source_report["configRuleName"] = config_rule_name
                            source_report["inConformancePack"] = True

                            report["summary"]["mappedToConformancePack"] += 1
                            control_report["summary"]["mappedToConformancePack"] += 1

                            # Get compliance details (use cache)
                            if config_rule_name not in compliance_cache:
                                compliance_cache[config_rule_name] = get_conformance_pack_compliance_details(
                                    client, conformance_pack_name, config_rule_name
                                )

                            eval_results = compliance_cache[config_rule_name]
                            source_report["evaluationResults"] = eval_results

                            # Count compliance
                            for result in eval_results:
                                compliance_type = result.get("complianceType", "")
                                if compliance_type == "COMPLIANT":
                                    source_report["complianceSummary"]["compliant"] += 1
                                    control_report["summary"]["compliantResources"] += 1
                                    control_set_report["summary"]["compliantResources"] += 1
                                    report["summary"]["compliantResources"] += 1
                                elif compliance_type == "NON_COMPLIANT":
                                    source_report["complianceSummary"]["nonCompliant"] += 1
                                    control_report["summary"]["nonCompliantResources"] += 1
                                    control_set_report["summary"]["nonCompliantResources"] += 1
                                    report["summary"]["nonCompliantResources"] += 1
                                else:
                                    source_report["complianceSummary"]["notApplicable"] += 1
                                    control_report["summary"]["notApplicableResources"] += 1
                                    report["summary"]["notApplicableResources"] += 1
                        else:
                            report["summary"]["notMappedToConformancePack"] += 1

                    # Handle AWS_Security_Hub sources
                    elif source_type == "AWS_Security_Hub":
                        report["summary"]["awsSecurityHubEvidenceSources"] += 1
                        control_report["summary"]["awsSecurityHubSources"] += 1

                        # Use composite key for Security Hub lookups
                        sec_hub_key = f"SecurityHub:{keyword_value}" if keyword_value else None

                        if sec_hub_key and sec_hub_key in keyword_to_rule:
                            config_rule_name = keyword_to_rule[sec_hub_key]
                            source_report["configRuleName"] = config_rule_name
                            source_report["inConformancePack"] = True
                            source_report["securityHubControlId"] = keyword_value

                            report["summary"]["mappedFromSecurityHub"] += 1
                            control_report["summary"]["mappedFromSecurityHub"] += 1

                            # Get compliance details from Config rule (use cache)
                            if config_rule_name not in compliance_cache:
                                compliance_cache[config_rule_name] = get_conformance_pack_compliance_details(
                                    client, conformance_pack_name, config_rule_name
                                )

                            eval_results = compliance_cache[config_rule_name]
                            source_report["evaluationResults"] = eval_results

                            # Count compliance
                            for result in eval_results:
                                compliance_type = result.get("complianceType", "")
                                if compliance_type == "COMPLIANT":
                                    source_report["complianceSummary"]["compliant"] += 1
                                    control_report["summary"]["compliantResources"] += 1
                                    control_set_report["summary"]["compliantResources"] += 1
                                    report["summary"]["compliantResources"] += 1
                                elif compliance_type == "NON_COMPLIANT":
                                    source_report["complianceSummary"]["nonCompliant"] += 1
                                    control_report["summary"]["nonCompliantResources"] += 1
                                    control_set_report["summary"]["nonCompliantResources"] += 1
                                    report["summary"]["nonCompliantResources"] += 1
                                else:
                                    source_report["complianceSummary"]["notApplicable"] += 1
                                    control_report["summary"]["notApplicableResources"] += 1
                                    report["summary"]["notApplicableResources"] += 1
                        else:
                            report["summary"]["notMappedToConformancePack"] += 1

                    control_report["evidenceSources"].append(source_report)

            control_set_report["controls"].append(control_report)
            control_set_report["summary"]["totalControls"] += 1

        report["controlSets"].append(control_set_report)
        report["summary"]["totalControlSets"] += 1
        report["summary"]["totalControls"] += control_set_report["summary"]["totalControls"]

    return report


def print_report_summary(report: dict):
    """Print a human-readable summary of the compliance report."""
    summary = report["summary"]

    print("\n" + "=" * 100)
    print("COMPLIANCE REPORT SUMMARY")
    print("=" * 100)
    print(f"Framework: {report['frameworkName']}")
    print(f"Conformance Pack: {report['conformancePackName']}")
    print(f"Generated At: {report['reportGeneratedAt']}")
    print()
    print(f"Total Control Sets: {summary['totalControlSets']}")
    print(f"Total Controls: {summary['totalControls']}")
    print(f"Total Evidence Sources: {summary['totalEvidenceSources']}")
    print(f"  AWS Config Evidence Sources: {summary['awsConfigEvidenceSources']}")
    print(f"  AWS Security Hub Evidence Sources: {summary.get('awsSecurityHubEvidenceSources', 0)}")
    print(f"Mapped to Conformance Pack: {summary['mappedToConformancePack']}")
    print(f"Mapped from Security Hub: {summary.get('mappedFromSecurityHub', 0)}")
    print(f"NOT Mapped: {summary['notMappedToConformancePack']}")
    print()
    print("RESOURCE COMPLIANCE:")
    print(f"  Compliant Resources: {summary['compliantResources']}")
    print(f"  Non-Compliant Resources: {summary['nonCompliantResources']}")
    print(f"  Not Applicable: {summary['notApplicableResources']}")

    # Show control sets with non-compliant resources
    print("\n" + "=" * 100)
    print("CONTROL SETS WITH NON-COMPLIANT RESOURCES")
    print("=" * 100)

    for cs in report["controlSets"]:
        if cs["summary"]["nonCompliantResources"] > 0:
            print(f"\n{cs['controlSetName']}")
            print(f"  Compliant: {cs['summary']['compliantResources']}, Non-Compliant: {cs['summary']['nonCompliantResources']}")

            for ctrl in cs["controls"]:
                if ctrl["summary"]["nonCompliantResources"] > 0:
                    print(f"\n  Control: {ctrl['controlName'][:80]}")
                    print(f"    Non-Compliant Resources: {ctrl['summary']['nonCompliantResources']}")

                    for src in ctrl["evidenceSources"]:
                        if src["complianceSummary"]["nonCompliant"] > 0:
                            rule_display = src['configRuleName']
                            if src.get('securityHubControlId'):
                                rule_display = f"[SecurityHub:{src['securityHubControlId']}] {rule_display}"
                            print(f"      - {rule_display}: {src['complianceSummary']['nonCompliant']} non-compliant")
                            # Show first 3 non-compliant resources
                            non_compliant = [r for r in src["evaluationResults"] if r["complianceType"] == "NON_COMPLIANT"]
                            for r in non_compliant[:3]:
                                print(f"        * {r['resourceType']}: {r['resourceId']}")
                            if len(non_compliant) > 3:
                                print(f"        ... and {len(non_compliant) - 3} more")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a compliance report for an AWS Audit Manager framework based on conformance pack results"
    )
    parser.add_argument(
        "conformance_pack_name",
        help="Name of the AWS Config conformance pack"
    )
    parser.add_argument(
        "framework_file",
        help="Path to framework JSON file (output from get_framework_controls.py)"
    )
    parser.add_argument(
        "config_mapping_file",
        help="Path to config mapping JSON file (output from map_config_rules.py)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: compliance_report_<conformance_pack>.json)",
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
        # Load input files
        print(f"Loading framework file: {args.framework_file}")
        framework_data = load_json_file(args.framework_file)

        print(f"Loading config mapping file: {args.config_mapping_file}")
        config_mapping = load_json_file(args.config_mapping_file)

        # Generate report
        report = generate_compliance_report(
            args.conformance_pack_name,
            framework_data,
            config_mapping,
            args.region
        )

        if args.stdout:
            print(json.dumps(report, indent=2))
        else:
            output_file = args.output or f"compliance_report_{args.conformance_pack_name}.json"

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            print_report_summary(report)
            print(f"\nFull report written to: {output_file}")

    except FileNotFoundError as e:
        print(f"Error: File not found: {e.filename}", file=sys.stderr)
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
