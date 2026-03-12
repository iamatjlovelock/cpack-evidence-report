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
    template_name: str
) -> dict:
    """
    Generate a compliance report based on template rules.

    Args:
        framework_controls: Framework controls from get_framework_controls.py
        template_rules: Dict of rules from the YAML template
        template_name: Name of the template being used

    Returns:
        Compliance report dict
    """
    report = {
        "frameworkId": framework_controls.get("frameworkId", ""),
        "frameworkName": framework_controls.get("frameworkName", ""),
        "conformancePackName": f"Template: {template_name}",
        "templateMode": True,
        "templateName": template_name,
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
            # These can be direct AWS_Config sources or Core_Control sources with nested evidence
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

                elif source_type == "Core_Control":
                    # Core_Control with nested evidence sources
                    for nested_source in mapping_source.get("coreControlEvidenceSources", []):
                        if nested_source.get("sourceType") == "AWS_Config":
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


def find_best_matching_template(framework_name: str, yaml_folder: str, csv_path: str = None) -> tuple:
    """
    Find the best matching YAML template for a framework.

    Args:
        framework_name: Name of the framework
        yaml_folder: Folder containing YAML templates
        csv_path: Path to framework-to-template mapping CSV (optional)

    Returns:
        Tuple of (template_name, yaml_path) or (None, None) if not found
    """
    import csv

    # Try CSV mapping first
    if csv_path and os.path.exists(csv_path):
        mapping = {}
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 2:
                        fw = row[0].strip()
                        template = row[1].strip()
                        if fw and template and template != "-- No equivalent --":
                            mapping[fw] = template
        except Exception:
            pass

        # Try to find matching template from mapping
        framework_normalized = re.sub(r'[^a-z0-9]', '', framework_name.lower())
        for key, template in mapping.items():
            key_normalized = re.sub(r'[^a-z0-9]', '', key.lower())
            if key_normalized in framework_normalized or framework_normalized in key_normalized:
                # Find the YAML file - check both directions since CSV names may differ from filenames
                template_normalized = re.sub(r'[^a-z0-9]', '', template.lower())
                for filename in os.listdir(yaml_folder):
                    if filename.endswith(".yaml"):
                        filename_normalized = re.sub(r'[^a-z0-9]', '', filename.lower().replace(".yaml", ""))
                        if template_normalized in filename_normalized or filename_normalized in template_normalized:
                            return (filename.replace(".yaml", ""), os.path.join(yaml_folder, filename))

    # Fallback: Try direct name matching
    if os.path.exists(yaml_folder):
        framework_normalized = re.sub(r'[^a-z0-9]', '', framework_name.lower())
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
        help="Folder containing YAML templates (default: conformance-pack-yamls)",
        default=None
    )
    parser.add_argument(
        "--csv-mapping",
        help="Path to framework-to-template mapping CSV",
        default=None
    )

    args = parser.parse_args()

    try:
        # Load framework controls
        print(f"Loading framework controls: {args.framework_file}")
        framework_controls = load_json_file(args.framework_file)
        framework_name = framework_controls.get("frameworkName", "Unknown")
        print(f"  Framework: {framework_name}")

        # Determine YAML template
        script_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_folder = args.yaml_folder or os.path.join(script_dir, "conformance-pack-yamls")
        csv_path = args.csv_mapping or os.path.join(script_dir, "Framework-to-conformance-pack-template-mapping.csv")

        if args.template:
            template_path = args.template
            template_name = os.path.basename(template_path).replace(".yaml", "")
        else:
            print(f"Auto-detecting template for framework...")
            template_name, template_path = find_best_matching_template(
                framework_name, yaml_folder, csv_path
            )
            if not template_path:
                print("Error: Could not find matching template for framework", file=sys.stderr)
                print("Use --template to specify the YAML file manually", file=sys.stderr)
                sys.exit(1)

        print(f"  Using template: {template_name}")
        print(f"  Template path: {template_path}")

        # Extract rules from template
        print("Extracting rules from template...")
        template_rules = extract_rules_from_yaml(template_path)
        print(f"  Found {len(template_rules)} Config rules in template")

        # Generate report
        print("Generating template-based compliance report...")
        report = generate_template_compliance_report(
            framework_controls,
            template_rules,
            template_name
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
