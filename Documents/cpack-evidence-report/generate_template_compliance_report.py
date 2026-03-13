#!/usr/bin/env python3
"""
Generate a compliance report based on a conformance pack YAML template.

This script is used when no conformance pack is deployed (--conformance-pack none mode).
It determines which rules from the framework are included in the template and generates
a report showing the mapping status without actual compliance evaluation results.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone


def load_json_file(file_path: str) -> dict:
    """Load and parse a JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_rules_from_yaml(yaml_path: str) -> dict:
    """
    Extract Config rules from a conformance pack YAML template.

    Args:
        yaml_path: Path to the YAML file

    Returns:
        Dict mapping SourceIdentifier to rule name
    """
    rules = {}
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Find all ConfigRule resources
        # Pattern: Resource name followed by Properties and Type: AWS::Config::ConfigRule
        # The Type can appear before or after Properties in CloudFormation

        # Match resource blocks that contain AWS::Config::ConfigRule
        # Look for pattern: ResourceName:\n  Properties:\n  ...\n  Type: AWS::Config::ConfigRule
        resource_pattern = r'^  (\w+):\s*\n((?:.*?\n)*?)    Type:\s*AWS::Config::ConfigRule'

        for match in re.finditer(resource_pattern, content, re.MULTILINE):
            rule_name = match.group(1)
            properties_block = match.group(2)

            # Extract SourceIdentifier
            source_id_match = re.search(r'SourceIdentifier:\s*(\S+)', properties_block)
            if source_id_match:
                source_id = source_id_match.group(1).strip()
                rules[source_id] = rule_name

    except FileNotFoundError:
        print(f"Error: YAML file not found: {yaml_path}", file=sys.stderr)
    except Exception as e:
        print(f"Error parsing YAML: {e}", file=sys.stderr)

    return rules


def generate_template_compliance_report(
    framework_controls: dict,
    template_rules: dict,
    template_name: str,
    no_template: bool = False
) -> dict:
    """
    Generate a compliance report based on template rules.

    Args:
        framework_controls: Framework controls from get_framework_controls.py
        template_rules: Dict of rules from the YAML template
        template_name: Name of the template being used
        no_template: If True, indicates no template was found for the framework

    Returns:
        Compliance report dict
    """
    if no_template:
        conformance_pack_name = "No Template Available"
    else:
        conformance_pack_name = f"Template: {template_name}"

    report = {
        "frameworkId": framework_controls.get("frameworkId", ""),
        "frameworkName": framework_controls.get("frameworkName", ""),
        "conformancePackName": conformance_pack_name,
        "templateMode": True,
        "noTemplateAvailable": no_template,
        "templateName": template_name if not no_template else None,
        "reportGeneratedAt": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "totalControlSets": 0,
            "totalControls": 0,
            "totalEvidenceSources": 0,
            "compliantResources": 0,
            "nonCompliantResources": 0
        },
        "controlSets": [],
        "conformancePackRulesNotInFramework": []
    }

    # Track unique evidence sources
    all_evidence_sources = set()
    framework_rule_identifiers = set()

    for control_set in framework_controls.get("controlSets", []):
        cs_data = {
            "controlSetName": control_set.get("controlSetName", ""),
            "controls": [],
            "summary": {
                "totalControls": 0,
                "totalEvidenceSources": 0
            }
        }

        for control in control_set.get("controls", []):
            ctrl_data = {
                "controlId": control.get("controlId", ""),
                "controlName": control.get("controlName", ""),
                "controlDescription": control.get("controlDescription", ""),
                "evidenceSources": []
            }

            # Extract evidence sources from controlMappingSources
            # These can be direct AWS_Config/AWS_Security_Hub sources or Core_Control sources with nested evidence
            for mapping_source in control.get("controlMappingSources", []):
                source_type = mapping_source.get("sourceType", "")

                if source_type == "AWS_Config":
                    # Direct AWS_Config source
                    keyword = mapping_source.get("sourceKeyword", {}).get("keywordValue", "")
                    if keyword:
                        framework_rule_identifiers.add(keyword)
                        in_template = keyword in template_rules

                        source_data = {
                            "sourceName": mapping_source.get("sourceName", ""),
                            "sourceDescription": mapping_source.get("sourceDescription", ""),
                            "sourceType": "AWS_Config",
                            "keywordValue": keyword,
                            "configRuleName": template_rules.get(keyword, keyword),
                            "inConformancePack": in_template,
                            "evaluationResults": []
                        }
                        ctrl_data["evidenceSources"].append(source_data)
                        all_evidence_sources.add(keyword)

                elif source_type == "AWS_Security_Hub":
                    # Direct AWS_Security_Hub source
                    keyword = mapping_source.get("sourceKeyword", {}).get("keywordValue", "")
                    if keyword:
                        # Use composite key for Security Hub sources
                        sec_hub_key = f"SecurityHub:{keyword}"
                        framework_rule_identifiers.add(sec_hub_key)
                        in_template = sec_hub_key in template_rules or keyword in template_rules

                        source_data = {
                            "sourceName": mapping_source.get("sourceName", ""),
                            "sourceDescription": mapping_source.get("sourceDescription", ""),
                            "sourceType": "AWS_Security_Hub",
                            "keywordValue": keyword,
                            "securityHubControlId": keyword,
                            "configRuleName": template_rules.get(sec_hub_key, template_rules.get(keyword, keyword)),
                            "inConformancePack": in_template,
                            "evaluationResults": []
                        }
                        ctrl_data["evidenceSources"].append(source_data)
                        all_evidence_sources.add(sec_hub_key)

                elif source_type == "Core_Control":
                    # Core_Control with nested evidence sources
                    for nested_source in mapping_source.get("coreControlEvidenceSources", []):
                        nested_type = nested_source.get("sourceType")

                        if nested_type == "AWS_Config":
                            keyword = nested_source.get("sourceKeyword", {}).get("keywordValue", "")
                            if keyword:
                                framework_rule_identifiers.add(keyword)
                                in_template = keyword in template_rules

                                source_data = {
                                    "sourceName": nested_source.get("sourceName", ""),
                                    "sourceDescription": nested_source.get("sourceDescription", ""),
                                    "sourceType": "AWS_Config",
                                    "keywordValue": keyword,
                                    "configRuleName": template_rules.get(keyword, keyword),
                                    "inConformancePack": in_template,
                                    "evaluationResults": []
                                }
                                ctrl_data["evidenceSources"].append(source_data)
                                all_evidence_sources.add(keyword)

                        elif nested_type == "AWS_Security_Hub":
                            keyword = nested_source.get("sourceKeyword", {}).get("keywordValue", "")
                            if keyword:
                                sec_hub_key = f"SecurityHub:{keyword}"
                                framework_rule_identifiers.add(sec_hub_key)
                                in_template = sec_hub_key in template_rules or keyword in template_rules

                                source_data = {
                                    "sourceName": nested_source.get("sourceName", ""),
                                    "sourceDescription": nested_source.get("sourceDescription", ""),
                                    "sourceType": "AWS_Security_Hub",
                                    "keywordValue": keyword,
                                    "securityHubControlId": keyword,
                                    "configRuleName": template_rules.get(sec_hub_key, template_rules.get(keyword, keyword)),
                                    "inConformancePack": in_template,
                                    "evaluationResults": []
                                }
                                ctrl_data["evidenceSources"].append(source_data)
                                all_evidence_sources.add(sec_hub_key)

            cs_data["controls"].append(ctrl_data)
            cs_data["summary"]["totalControls"] += 1

        cs_data["summary"]["totalEvidenceSources"] = len([
            s for c in cs_data["controls"]
            for s in c["evidenceSources"]
        ])

        report["controlSets"].append(cs_data)
        report["summary"]["totalControlSets"] += 1
        report["summary"]["totalControls"] += cs_data["summary"]["totalControls"]

    report["summary"]["totalEvidenceSources"] = len(all_evidence_sources)

    # Find rules in template but not in framework
    template_identifiers = set(template_rules.keys())
    extra_rules = template_identifiers - framework_rule_identifiers
    report["conformancePackRulesNotInFramework"] = sorted(list(extra_rules))

    return report


def find_best_matching_template(framework_name: str, yaml_folder: str, framework_mapping_csv: str = None, templates_csv: str = None, framework_id: str = None) -> tuple:
    """
    Find the best matching YAML template for a framework using two-step CSV lookup.

    Step 1: Look up framework name/ID in Framework-to-conformance-pack-template-mapping.csv
            to get the conformance pack template name.
    Step 2: Look up template name in Conformance pack templates.csv to get the YAML filename.

    Args:
        framework_name: Name of the framework
        yaml_folder: Folder containing YAML templates
        framework_mapping_csv: Path to Framework-to-conformance-pack-template-mapping.csv
        templates_csv: Path to Conformance pack templates.csv
        framework_id: Framework ID for exact matching (optional)

    Returns:
        Tuple of (template_name, yaml_path) or (None, None) if not found
    """
    import csv

    # Step 1: Load framework-to-template mapping
    # CSV format: Framework Name, Framework ID, Template Name, Other Templates, Notes
    framework_to_template = {}
    framework_id_to_template = {}
    if framework_mapping_csv and os.path.exists(framework_mapping_csv):
        try:
            with open(framework_mapping_csv, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 3:
                        fw = row[0].strip()
                        fw_id = row[1].strip() if len(row) > 1 else ""
                        template = row[2].strip() if len(row) > 2 else ""
                        notes = row[4].strip() if len(row) > 4 else ""

                        # Skip if no template or marked as "No Equivalent"
                        if not template or "no equivalent" in notes.lower():
                            continue

                        if fw:
                            framework_to_template[fw] = template
                        if fw_id:
                            framework_id_to_template[fw_id] = template
        except Exception:
            pass

    # Step 2: Load template-to-YAML mapping
    template_to_yaml = {}
    if templates_csv and os.path.exists(templates_csv):
        try:
            with open(templates_csv, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 2:
                        template_name = row[0].strip()
                        yaml_file = row[1].strip()
                        if template_name and yaml_file:
                            template_to_yaml[template_name] = yaml_file
        except Exception:
            pass

    # Try to find matching framework in step 1
    # First try exact match by framework ID
    matched_template_name = None
    if framework_id and framework_id in framework_id_to_template:
        matched_template_name = framework_id_to_template[framework_id]

    # Fall back to fuzzy name matching
    if not matched_template_name:
        framework_normalized = re.sub(r'[^a-z0-9]', '', framework_name.lower())
        for key, template in framework_to_template.items():
            key_normalized = re.sub(r'[^a-z0-9]', '', key.lower())
            if key_normalized in framework_normalized or framework_normalized in key_normalized:
                matched_template_name = template
                break

    if matched_template_name:
        # Step 2a: Try exact lookup in template-to-YAML mapping
        if matched_template_name in template_to_yaml:
            yaml_file = template_to_yaml[matched_template_name]
            yaml_path = os.path.join(yaml_folder, yaml_file)
            if os.path.exists(yaml_path):
                return (yaml_file.replace(".yaml", ""), yaml_path)

        # Step 2b: Try normalized lookup in template-to-YAML mapping
        template_normalized = re.sub(r'[^a-z0-9]', '', matched_template_name.lower())
        for template_key, yaml_file in template_to_yaml.items():
            key_normalized = re.sub(r'[^a-z0-9]', '', template_key.lower())
            if template_normalized in key_normalized or key_normalized in template_normalized:
                yaml_path = os.path.join(yaml_folder, yaml_file)
                if os.path.exists(yaml_path):
                    return (yaml_file.replace(".yaml", ""), yaml_path)

        # Step 2c: Fallback to fuzzy matching against YAML filenames
        if os.path.exists(yaml_folder):
            for filename in os.listdir(yaml_folder):
                if filename.endswith(".yaml"):
                    filename_normalized = re.sub(r'[^a-z0-9]', '', filename.lower().replace(".yaml", ""))
                    if template_normalized in filename_normalized or filename_normalized in template_normalized:
                        return (filename.replace(".yaml", ""), os.path.join(yaml_folder, filename))

    # Final fallback: Try direct framework name matching against YAML filenames
    if os.path.exists(yaml_folder):
        for filename in os.listdir(yaml_folder):
            if filename.endswith(".yaml"):
                filename_normalized = re.sub(r'[^a-z0-9]', '', filename.lower().replace(".yaml", ""))
                if framework_normalized in filename_normalized or filename_normalized in framework_normalized:
                    return (filename.replace(".yaml", ""), os.path.join(yaml_folder, filename))

    return (None, None)


def main():
    parser = argparse.ArgumentParser(
        description="Generate compliance report from conformance pack YAML template"
    )
    parser.add_argument(
        "framework_file",
        help="Path to framework controls JSON file"
    )
    parser.add_argument(
        "-t", "--template",
        help="Path to conformance pack YAML template (auto-detected if not specified)",
        default=None
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path",
        default=None
    )
    parser.add_argument(
        "--yaml-folder",
        help="Folder containing YAML templates (default: conformance-packs/conformance-pack-yamls)",
        default=None
    )
    parser.add_argument(
        "--framework-mapping-csv",
        help="Path to Framework-to-conformance-pack-template-mapping.csv",
        default=None
    )
    parser.add_argument(
        "--templates-csv",
        help="Path to Conformance pack templates.csv",
        default=None
    )

    args = parser.parse_args()

    try:
        # Load framework controls
        print(f"Loading framework controls: {args.framework_file}")
        framework_controls = load_json_file(args.framework_file)
        framework_name = framework_controls.get("frameworkName", "Unknown")
        framework_id = framework_controls.get("frameworkId", "")
        print(f"  Framework: {framework_name}")
        if framework_id:
            print(f"  Framework ID: {framework_id}")

        # Determine YAML template
        script_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_folder = args.yaml_folder or os.path.join(script_dir, "conformance-packs", "conformance-pack-yamls")
        framework_mapping_csv = args.framework_mapping_csv or os.path.join(script_dir, "conformance-packs", "Framework-to-conformance-pack-template-mapping.csv")
        templates_csv = args.templates_csv or os.path.join(script_dir, "conformance-packs", "Conformance pack templates.csv")

        no_template = False
        template_rules = {}

        if args.template:
            template_path = args.template
            template_name = os.path.basename(template_path).replace(".yaml", "")
        else:
            print(f"Auto-detecting template for framework...")
            template_name, template_path = find_best_matching_template(
                framework_name, yaml_folder, framework_mapping_csv, templates_csv, framework_id
            )
            if not template_path:
                print("  No matching conformance pack template found for this framework")
                print("  Generating framework-only report (no template mapping)")
                no_template = True
                template_name = None
                template_path = None

        if template_path:
            print(f"  Using template: {template_name}")
            print(f"  Template path: {template_path}")

            # Extract rules from template
            print("Extracting rules from template...")
            template_rules = extract_rules_from_yaml(template_path)
            print(f"  Found {len(template_rules)} Config rules in template")

        # Generate report
        if no_template:
            print("Generating framework-only report (no template available)...")
        else:
            print("Generating template-based compliance report...")
        report = generate_template_compliance_report(
            framework_controls,
            template_rules,
            template_name,
            no_template
        )

        # Count mapped/unmapped
        mapped = 0
        unmapped = 0
        for cs in report["controlSets"]:
            for ctrl in cs["controls"]:
                for src in ctrl["evidenceSources"]:
                    if src.get("inConformancePack"):
                        mapped += 1
                    else:
                        unmapped += 1

        if no_template:
            print(f"  Total framework Config rules: {unmapped}")
            print(f"  (No template mapping - all rules shown as unmapped)")
        else:
            print(f"  Framework rules mapped to template: {mapped}")
            print(f"  Framework rules not in template: {unmapped}")
            print(f"  Extra rules in template: {len(report['conformancePackRulesNotInFramework'])}")

        # Write output
        output_file = args.output
        if not output_file:
            base_name = args.framework_file.rsplit(".", 1)[0]
            output_file = f"{base_name}_template_report.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"\nTemplate compliance report written to: {output_file}")

    except FileNotFoundError as e:
        print(f"Error: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
