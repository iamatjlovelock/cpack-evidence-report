#!/usr/bin/env python3
"""
Generate a Rule Manifest report listing all Config rules across frameworks,
security standards, and conformance pack templates.

This report aggregates rules from:
1. Framework compliance reports (compliance-dashboards/)
2. Security standard files (security-standard-controls/)
3. Conformance pack templates (conformance-packs/conformance-pack-yamls/)
4. AWS Control Catalog (control-catalog/detective-controls.json)

For each rule, it shows:
- Which frameworks reference it
- Which security standards include it
- Which templates include it
- Whether it's in the Control Catalog
- All available metadata with source attribution
"""

import argparse
import html
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime


def escape_html(text) -> str:
    """Escape HTML special characters."""
    if text is None:
        return ""
    return html.escape(str(text))


def normalize_rule_identifier(rule_name: str) -> str:
    """
    Normalize a Config rule name for comparison.

    Handles:
    - Security Hub prefixed rules (securityhub-rule-name-abc123)
    - Standard Config rules (RULE_NAME)
    - Conformance pack rules (OrgConfigRule-rule-name-abc123)
    """
    if not rule_name:
        return ""

    rule_name = rule_name.strip()

    # Handle Security Hub prefixed rules
    if rule_name.lower().startswith("securityhub-"):
        # Remove prefix and trailing hash
        name = rule_name[12:]  # Remove "securityhub-"
        # Remove trailing hash (usually 8 hex chars)
        name = re.sub(r'-[a-f0-9]{6,}$', '', name, flags=re.IGNORECASE)
        # Convert dashes to underscores and uppercase
        return name.replace('-', '_').upper()

    # Handle OrgConfigRule prefix
    if rule_name.startswith("OrgConfigRule-"):
        name = rule_name[14:]
        name = re.sub(r'-[a-f0-9]{6,}$', '', name, flags=re.IGNORECASE)
        return name.replace('-', '_').upper()

    # Standard rule - just uppercase
    return rule_name.upper()


def load_control_catalog(project_dir: str) -> dict:
    """Load the Control Catalog from detective-controls.json."""
    catalog_file = os.path.join(project_dir, "control-catalog", "detective-controls.json")
    catalog = {}

    try:
        with open(catalog_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for identifier, control in data.get("controls", {}).items():
            catalog[identifier.upper()] = {
                "arn": control.get("arn", ""),
                "name": control.get("name", ""),
                "description": control.get("description", ""),
                "severity": control.get("severity", ""),
                "behavior": control.get("behavior", ""),
                "implementation_type": control.get("implementationType", ""),
                "source": "AWS Control Catalog"
            }
    except Exception as e:
        print(f"Warning: Could not load Control Catalog: {e}")

    return catalog


def load_managed_rules(project_dir: str) -> dict:
    """Load all managed rules from documentation scrape or API export."""
    # Prefer the docs scrape (more complete) over the API export
    docs_file = os.path.join(project_dir, "control-catalog", "managed-rules-docs.json")
    api_file = os.path.join(project_dir, "control-catalog", "managed-rules.json")
    managed_rules = {}

    # Try docs file first
    managed_file = docs_file if os.path.exists(docs_file) else api_file

    try:
        with open(managed_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for identifier, info in data.get("rules", {}).items():
            managed_rules[identifier.upper()] = {
                "identifier": identifier.upper(),
                "name": info.get("name", ""),
                "description": info.get("description", ""),
                "resource_types": info.get("resource_types", []),
                "trigger_type": info.get("trigger_type", ""),
                "aws_region": info.get("aws_region", ""),
                "parameters": info.get("parameters", []),
                "source": "AWS Documentation"
            }
    except FileNotFoundError:
        print("Note: No managed rules file found. Run scrape_managed_rules_docs.py to generate it.")
    except Exception as e:
        print(f"Warning: Could not load managed rules: {e}")

    return managed_rules


def load_security_standards(project_dir: str) -> dict:
    """Load all security standard files and extract rule mappings."""
    standards_dir = os.path.join(project_dir, "security-standard-controls")
    standards = {}

    if not os.path.exists(standards_dir):
        return standards

    for filename in os.listdir(standards_dir):
        if not filename.endswith(".json"):
            continue

        standard_name = filename.replace(".json", "")
        filepath = os.path.join(standards_dir, filename)

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            standard_info = {
                "name": data.get("standard_name", standard_name),
                "arn": data.get("standard_arn", ""),
                "controls": {}
            }

            for control in data.get("controls", []):
                control_id = control.get("control_id") or control.get("security_control_id", "")
                config_rule = control.get("config_rule", "")

                if config_rule:
                    normalized = normalize_rule_identifier(config_rule)
                    if normalized:
                        standard_info["controls"][normalized] = {
                            "control_id": control_id,
                            "title": control.get("title", ""),
                            "description": control.get("description", ""),
                            "severity": control.get("severity", ""),
                            "config_rule": config_rule,
                            "source": f"Security Hub: {standard_name}"
                        }

            standards[standard_name] = standard_info
        except Exception as e:
            print(f"Warning: Could not load {filename}: {e}")

    return standards


def load_conformance_templates(project_dir: str) -> dict:
    """Load all conformance pack template YAML files."""
    templates_dir = os.path.join(project_dir, "conformance-packs", "conformance-pack-yamls")
    templates = {}

    if not os.path.exists(templates_dir):
        return templates

    try:
        import yaml
    except ImportError:
        print("Warning: PyYAML not installed, cannot load conformance templates")
        return templates

    for filename in os.listdir(templates_dir):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue

        template_name = filename.replace(".yaml", "").replace(".yml", "")
        filepath = os.path.join(templates_dir, filename)

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            template_info = {
                "name": template_name,
                "rules": {}
            }

            # Extract rules from template
            resources = data.get("Resources", {}) if data else {}
            for resource_name, resource_def in resources.items():
                if not isinstance(resource_def, dict):
                    continue
                if resource_def.get("Type") == "AWS::Config::ConfigRule":
                    props = resource_def.get("Properties", {})
                    source = props.get("Source", {})

                    # Get the rule identifier
                    rule_id = source.get("SourceIdentifier", "")
                    # Skip if rule_id is a reference (dict) or not a string
                    if not isinstance(rule_id, str) or not rule_id:
                        continue
                    normalized = rule_id.upper()
                    if normalized:
                        template_info["rules"][normalized] = {
                            "resource_name": resource_name,
                            "description": props.get("Description", ""),
                            "source": f"Template: {template_name}"
                        }

            templates[template_name] = template_info
        except Exception as e:
            print(f"Warning: Could not load {filename}: {e}")

    return templates


def load_security_standard_mappings(project_dir: str) -> dict:
    """
    Load Security Hub control ID to Config rule mappings from security standard files.

    Returns dict mapping security control ID (e.g., 'ACM.1') to Config rule identifier.
    """
    standards_dir = os.path.join(project_dir, "security-standard-controls")
    mappings = {}

    if not os.path.exists(standards_dir):
        return mappings

    for filename in os.listdir(standards_dir):
        if not filename.endswith(".json"):
            continue
        if filename == "security_hub_standards.json":
            continue

        filepath = os.path.join(standards_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            for control in data.get("controls", []):
                control_id = control.get("control_id", "")
                config_rule = control.get("config_rule", "")

                if control_id and config_rule:
                    # Normalize the config rule to get the managed rule identifier
                    normalized = normalize_rule_identifier(config_rule)
                    if normalized:
                        mappings[control_id.upper()] = normalized
        except Exception as e:
            pass  # Silently skip files that can't be parsed

    return mappings


def extract_security_hub_control_from_description(description: str) -> str:
    """
    Extract Security Hub control ID from framework control description URL.

    Framework controls often reference Security Hub controls via URLs like:
    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-FSBP-controls.html#FSBP-acm-1

    Returns the control ID (e.g., 'ACM.1') or empty string if not found.
    """
    if not description:
        return ""

    # Pattern: #FSBP-acm-1 or #fsbp-apigateway-1 -> ACM.1, APIGateway.1
    match = re.search(r'#[Ff][Ss][Bb][Pp]-([a-zA-Z0-9]+)-(\d+)', description)
    if match:
        service = match.group(1).upper()
        number = match.group(2)
        return f"{service}.{number}"

    # Also try pattern for other standards: #pci-dss-ec2-1 -> EC2.1
    match = re.search(r'#[a-z-]+-([a-zA-Z0-9]+)-(\d+)$', description)
    if match:
        service = match.group(1).upper()
        number = match.group(2)
        return f"{service}.{number}"

    return ""


def load_framework_reports(project_dir: str) -> dict:
    """Load all framework compliance reports."""
    dashboards_dir = os.path.join(project_dir, "compliance-dashboards")
    frameworks = {}

    if not os.path.exists(dashboards_dir):
        return frameworks

    # Load Security Hub control to Config rule mappings for indirect resolution
    security_hub_mappings = load_security_standard_mappings(project_dir)

    for dirname in os.listdir(dashboards_dir):
        dir_path = os.path.join(dashboards_dir, dirname)
        if not os.path.isdir(dir_path):
            continue

        # Find the template_report JSON file
        for filename in os.listdir(dir_path):
            if filename.startswith("template_report_") and filename.endswith(".json"):
                filepath = os.path.join(dir_path, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    framework_name = data.get("frameworkName", dirname)
                    framework_id = data.get("frameworkId", "")

                    framework_info = {
                        "name": framework_name,
                        "id": framework_id,
                        "rules": {}
                    }

                    # Extract rules from evidence sources
                    for control_set in data.get("controlSets", []):
                        for control in control_set.get("controls", []):
                            control_name = control.get("controlName", "")
                            evidence_sources = control.get("evidenceSources", [])

                            # Process explicit evidence sources
                            for source in evidence_sources:
                                source_type = source.get("sourceType", "")
                                if source_type not in ["AWS_Config", "AWS_Security_Hub"]:
                                    continue

                                keyword = source.get("keywordValue", "")
                                if not keyword:
                                    continue

                                if source_type == "AWS_Security_Hub":
                                    config_rule = source.get("configRuleName", "")
                                    if config_rule:
                                        normalized = normalize_rule_identifier(config_rule)
                                    else:
                                        # Security Hub control without config rule mapping
                                        normalized = keyword.upper()
                                else:
                                    normalized = keyword.upper()

                                if normalized not in framework_info["rules"]:
                                    framework_info["rules"][normalized] = {
                                        "controls": [],
                                        "source_type": source_type,
                                        "in_conformance_pack": source.get("inConformancePack", False),
                                        "source": f"Framework: {framework_name}"
                                    }
                                framework_info["rules"][normalized]["controls"].append(control_name)

                            # If no evidence sources, try to resolve via Security Hub control reference
                            # Framework controls (business requirements) may reference Security Hub
                            # controls (technical detective controls) which map to Config rules
                            if not evidence_sources:
                                description = control.get("controlDescription", "")
                                sec_hub_control_id = extract_security_hub_control_from_description(description)

                                if sec_hub_control_id and sec_hub_control_id in security_hub_mappings:
                                    normalized = security_hub_mappings[sec_hub_control_id]

                                    if normalized not in framework_info["rules"]:
                                        framework_info["rules"][normalized] = {
                                            "controls": [],
                                            "source_type": "AWS_Security_Hub_Indirect",
                                            "security_hub_control": sec_hub_control_id,
                                            "in_conformance_pack": False,
                                            "source": f"Framework: {framework_name} (via {sec_hub_control_id})"
                                        }
                                    framework_info["rules"][normalized]["controls"].append(control_name)

                    frameworks[framework_name] = framework_info
                except Exception as e:
                    print(f"Warning: Could not load {filepath}: {e}")
                break

    return frameworks


def build_rule_manifest(control_catalog: dict, standards: dict, templates: dict, frameworks: dict, managed_rules: dict = None) -> dict:
    """Build a unified manifest of all rules."""
    manifest = {}
    managed_rules = managed_rules or {}

    # Add rules from Control Catalog
    for rule_id, info in control_catalog.items():
        if rule_id not in manifest:
            manifest[rule_id] = {
                "identifier": rule_id,
                "in_catalog": True,
                "catalog_metadata": info,
                "frameworks": [],
                "standards": [],
                "templates": [],
                "metadata_sources": []
            }
        manifest[rule_id]["metadata_sources"].append({
            "source": "AWS Control Catalog",
            "name": info.get("name", ""),
            "description": info.get("description", ""),
            "severity": info.get("severity", "")
        })

    # Add rules from Security Standards
    for standard_name, standard_info in standards.items():
        for rule_id, control_info in standard_info["controls"].items():
            if rule_id not in manifest:
                manifest[rule_id] = {
                    "identifier": rule_id,
                    "in_catalog": rule_id in control_catalog,
                    "catalog_metadata": control_catalog.get(rule_id),
                    "frameworks": [],
                    "standards": [],
                    "templates": [],
                    "metadata_sources": []
                }
            manifest[rule_id]["standards"].append({
                "name": standard_name,
                "control_id": control_info.get("control_id", ""),
                "title": control_info.get("title", ""),
                "severity": control_info.get("severity", "")
            })
            manifest[rule_id]["metadata_sources"].append({
                "source": f"Security Hub: {standard_name}",
                "name": control_info.get("title", ""),
                "description": control_info.get("description", ""),
                "severity": control_info.get("severity", "")
            })

    # Add rules from Conformance Pack Templates
    for template_name, template_info in templates.items():
        for rule_id, rule_info in template_info["rules"].items():
            if rule_id not in manifest:
                manifest[rule_id] = {
                    "identifier": rule_id,
                    "in_catalog": rule_id in control_catalog,
                    "catalog_metadata": control_catalog.get(rule_id),
                    "frameworks": [],
                    "standards": [],
                    "templates": [],
                    "metadata_sources": []
                }
            manifest[rule_id]["templates"].append({
                "name": template_name,
                "resource_name": rule_info.get("resource_name", "")
            })
            if rule_info.get("description"):
                manifest[rule_id]["metadata_sources"].append({
                    "source": f"Template: {template_name}",
                    "description": rule_info.get("description", "")
                })

    # Add rules from Frameworks
    for framework_name, framework_info in frameworks.items():
        for rule_id, rule_info in framework_info["rules"].items():
            if rule_id not in manifest:
                manifest[rule_id] = {
                    "identifier": rule_id,
                    "in_catalog": rule_id in control_catalog,
                    "catalog_metadata": control_catalog.get(rule_id),
                    "frameworks": [],
                    "standards": [],
                    "templates": [],
                    "metadata_sources": []
                }
            manifest[rule_id]["frameworks"].append({
                "name": framework_name,
                "controls": rule_info.get("controls", []),
                "source_type": rule_info.get("source_type", ""),
                "in_conformance_pack": rule_info.get("in_conformance_pack", False)
            })

    # Add managed rules not already in manifest (available but not in compliance sources)
    for rule_id, info in managed_rules.items():
        if rule_id not in manifest:
            manifest[rule_id] = {
                "identifier": rule_id,
                "in_catalog": rule_id in control_catalog,
                "catalog_metadata": control_catalog.get(rule_id),
                "frameworks": [],
                "standards": [],
                "templates": [],
                "metadata_sources": [],
                "managed_only": True  # Flag to indicate not in any compliance source
            }
        # Add metadata from documentation for all rules (even existing ones)
        if info.get("description") or info.get("resource_types"):
            manifest[rule_id]["metadata_sources"].append({
                "source": "AWS Documentation",
                "name": info.get("name", ""),
                "description": info.get("description", ""),
                "resource_types": info.get("resource_types", []),
                "trigger_type": info.get("trigger_type", ""),
                "aws_region": info.get("aws_region", ""),
                "parameters": info.get("parameters", [])
            })

    return manifest


def get_best_metadata(rule: dict) -> dict:
    """Get the best available metadata for a rule, prioritizing Control Catalog."""
    best = {
        "name": "",
        "description": "",
        "severity": "",
        "source": ""
    }

    # Priority: Control Catalog > Security Hub > Template
    for source_info in rule.get("metadata_sources", []):
        source = source_info.get("source", "")

        if not best["name"] and source_info.get("name"):
            best["name"] = source_info["name"]
            best["source"] = source

        if not best["description"] and source_info.get("description"):
            best["description"] = source_info["description"]
            if not best["source"]:
                best["source"] = source

        if not best["severity"] and source_info.get("severity"):
            best["severity"] = source_info["severity"]

    return best


def generate_html_report(manifest: dict, output_file: str, frameworks: dict, standards: dict, templates: dict):
    """Generate the HTML Rule Manifest report."""

    # Sort rules by identifier
    sorted_rules = sorted(manifest.values(), key=lambda r: r["identifier"])

    # Count statistics
    total_rules = len(sorted_rules)
    in_catalog_count = sum(1 for r in sorted_rules if r["in_catalog"])
    in_frameworks_count = sum(1 for r in sorted_rules if r["frameworks"])
    in_standards_count = sum(1 for r in sorted_rules if r["standards"])
    in_templates_count = sum(1 for r in sorted_rules if r["templates"])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Config Rules Manifest</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
            background: #f7fafc;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        .header p {{
            margin: 0;
            opacity: 0.9;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .stat-card .value {{
            font-size: 32px;
            font-weight: 700;
            color: #4c51bf;
        }}
        .stat-card .label {{
            color: #718096;
            font-size: 14px;
        }}
        .filters {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .filters h3 {{
            margin: 0 0 15px 0;
            font-size: 16px;
        }}
        .filter-group {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
        }}
        .filter-group label {{
            display: flex;
            align-items: center;
            gap: 5px;
            padding: 5px 10px;
            background: #edf2f7;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
        }}
        .filter-group label:hover {{
            background: #e2e8f0;
        }}
        .filter-group input[type="checkbox"] {{
            cursor: pointer;
        }}
        .search-box {{
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            font-size: 14px;
            margin-bottom: 15px;
        }}
        .search-box:focus {{
            outline: none;
            border-color: #4c51bf;
        }}
        .rule-count {{
            color: #718096;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        th {{
            background: #4c51bf;
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            vertical-align: top;
        }}
        tr:hover {{
            background: #f7fafc;
        }}
        tr.hidden {{
            display: none;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            margin: 1px;
        }}
        .badge.yes {{
            background: #c6f6d5;
            color: #22543d;
        }}
        .badge.no {{
            background: #fef3c7;
            color: #92400e;
        }}
        .badge.framework {{
            background: #bee3f8;
            color: #2a4365;
        }}
        .badge.standard {{
            background: #e9d8fd;
            color: #553c9a;
        }}
        .badge.template {{
            background: #c6f6d5;
            color: #22543d;
        }}
        .badge.severity-critical {{
            background: #fed7d7;
            color: #c53030;
        }}
        .badge.severity-high {{
            background: #feebc8;
            color: #c05621;
        }}
        .badge.severity-medium {{
            background: #fef3c7;
            color: #92400e;
        }}
        .badge.severity-low {{
            background: #e2e8f0;
            color: #4a5568;
        }}
        .badge.hidden {{
            display: none;
        }}
        .no-badge {{
            color: #a0aec0;
        }}
        .rule-id {{
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            font-weight: 600;
            color: #2b6cb0;
            text-decoration: none;
        }}
        .rule-id:hover {{
            color: #1a365d;
            text-decoration: underline;
        }}
        .description {{
            color: #4a5568;
            font-size: 12px;
            max-width: 400px;
        }}
        .metadata-source {{
            font-size: 10px;
            color: #a0aec0;
            font-style: italic;
        }}
        .tag-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 3px;
        }}
        .expandable {{
            cursor: pointer;
        }}
        .expandable:hover {{
            text-decoration: underline;
        }}
        .details {{
            display: none;
            margin-top: 10px;
            padding: 10px;
            background: #f7fafc;
            border-radius: 4px;
            font-size: 12px;
        }}
        .details.show {{
            display: block;
        }}
        .details-row {{
            display: flex;
            margin-bottom: 5px;
        }}
        .details-label {{
            font-weight: 600;
            width: 120px;
            color: #4a5568;
        }}
        .details-value {{
            flex: 1;
        }}
        .generated-at {{
            text-align: center;
            color: #a0aec0;
            font-size: 12px;
            margin-top: 30px;
        }}
        .url-filter-banner {{
            background: linear-gradient(135deg, #f5a623 0%, #e67e22 100%);
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(245, 166, 35, 0.4);
        }}
        .url-filter-banner a {{
            color: white;
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Config Rules Manifest</h1>
        <p>Comprehensive inventory of all AWS Config rules across frameworks, security standards, and conformance pack templates</p>
    </div>

    <div id="urlFilterBanner" class="url-filter-banner" style="display: none;">
        <span id="urlFilterText"></span>
        <a href="?" style="margin-left: 15px; color: white;">Clear filters</a>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="value" id="statTotal">{total_rules}</div>
            <div class="label">Total Rules</div>
        </div>
        <div class="stat-card">
            <div class="value" id="statCatalog">{in_catalog_count}</div>
            <div class="label">In Control Catalog</div>
        </div>
        <div class="stat-card">
            <div class="value" id="statFrameworks">{in_frameworks_count}</div>
            <div class="label" id="labelFrameworks">In Audit Manager Frameworks</div>
        </div>
        <div class="stat-card">
            <div class="value" id="statStandards">{in_standards_count}</div>
            <div class="label" id="labelStandards">In Security Hub Standards</div>
        </div>
        <div class="stat-card">
            <div class="value" id="statTemplates">{in_templates_count}</div>
            <div class="label" id="labelTemplates">In Config Conformance Pack Templates</div>
        </div>
    </div>

    <div class="filters">
        <h3>Filters</h3>
        <input type="text" class="search-box" id="searchBox" placeholder="Search by rule identifier or description..." onkeyup="filterRules()">

        <div class="filter-group">
            <strong style="margin-right: 10px;">Membership:</strong>
            <label><input type="checkbox" id="filterCatalog" onchange="filterRules()"> In Control Catalog</label>
            <label><input type="checkbox" id="filterFramework" onchange="filterRules()"> In Framework</label>
            <label><input type="checkbox" id="filterStandard" onchange="filterRules()"> In Security Standard</label>
            <label><input type="checkbox" id="filterTemplate" onchange="filterRules()"> In Template</label>
        </div>

        <div class="filter-group">
            <strong style="margin-right: 10px;">Venn Segments:</strong>
            <label><input type="checkbox" id="filterFOnly" onchange="filterRules()"> Framework Only</label>
            <label><input type="checkbox" id="filterTOnly" onchange="filterRules()"> Template Only</label>
            <label><input type="checkbox" id="filterSOnly" onchange="filterRules()"> Standard Only</label>
            <label><input type="checkbox" id="filterFT" onchange="filterRules()"> Framework & Template</label>
            <label><input type="checkbox" id="filterFS" onchange="filterRules()"> Framework & Standard</label>
            <label><input type="checkbox" id="filterTS" onchange="filterRules()"> Template & Standard</label>
            <label><input type="checkbox" id="filterFTS" onchange="filterRules()"> All Three</label>
        </div>
    </div>

    <div class="rule-count" id="ruleCount">Showing {total_rules} rules</div>

    <table>
        <thead>
            <tr>
                <th style="width: 22%">Rule Identifier</th>
                <th style="width: 8%; text-align: center;">In Catalog</th>
                <th style="width: 30%">Description</th>
                <th style="width: 8%; text-align: center;">Severity</th>
                <th style="width: 10%">Frameworks</th>
                <th style="width: 10%">Standards</th>
                <th style="width: 12%">Templates</th>
            </tr>
        </thead>
        <tbody id="rulesTable">
"""

    for rule in sorted_rules:
        rule_id = rule["identifier"]
        in_catalog = rule["in_catalog"]
        best_meta = get_best_metadata(rule)

        # Determine Venn segment
        in_f = len(rule["frameworks"]) > 0
        in_t = len(rule["templates"]) > 0
        in_s = len(rule["standards"]) > 0

        venn_segment = ""
        if in_f and in_t and in_s:
            venn_segment = "fts"
        elif in_f and in_t:
            venn_segment = "ft"
        elif in_f and in_s:
            venn_segment = "fs"
        elif in_t and in_s:
            venn_segment = "ts"
        elif in_f:
            venn_segment = "f"
        elif in_t:
            venn_segment = "t"
        elif in_s:
            venn_segment = "s"

        # Badges
        catalog_badge = '<span class="badge yes">Yes</span>' if in_catalog else '<span class="badge no">No</span>'

        # Severity badge
        severity = best_meta.get("severity", "").upper()
        severity_class = f"severity-{severity.lower()}" if severity else ""
        severity_badge = f'<span class="badge {severity_class}">{severity}</span>' if severity else '-'

        # Framework badges - include data-name for filtering
        framework_badges = ""
        for fw in rule["frameworks"]:
            fw_name_display = fw["name"][:20] + "..." if len(fw["name"]) > 20 else fw["name"]
            fw_name_normalized = fw["name"].lower()
            framework_badges += f'<span class="badge framework" data-name="{escape_html(fw_name_normalized)}" title="{escape_html(fw["name"])}">{escape_html(fw_name_display)}</span> '
        if not framework_badges:
            framework_badges = '<span class="no-badge">-</span>'

        # Standard badges - include data-name for filtering
        standard_badges = ""
        for std in rule["standards"]:
            std_name_display = std["name"][:15] + "..." if len(std["name"]) > 15 else std["name"]
            std_name_normalized = std["name"].lower()
            standard_badges += f'<span class="badge standard" data-name="{escape_html(std_name_normalized)}" title="{escape_html(std["name"])}">{escape_html(std_name_display)}</span> '
        if not standard_badges:
            standard_badges = '<span class="no-badge">-</span>'

        # Template badges - include data-name for filtering
        template_badges = ""
        for tpl in rule["templates"]:
            tpl_name_display = tpl["name"][:15] + "..." if len(tpl["name"]) > 15 else tpl["name"]
            tpl_name_normalized = tpl["name"].lower()
            template_badges += f'<span class="badge template" data-name="{escape_html(tpl_name_normalized)}" title="{escape_html(tpl["name"])}">{escape_html(tpl_name_display)}</span> '
        if not template_badges:
            template_badges = '<span class="no-badge">-</span>'

        # Description
        description = best_meta.get("description", "")
        if len(description) > 200:
            description = description[:200] + "..."
        description_html = escape_html(description) if description else '<span style="color: #a0aec0;">No description available</span>'

        # Source attribution
        source = best_meta.get("source", "")
        source_html = f'<div class="metadata-source">Source: {escape_html(source)}</div>' if source else ""

        # Create lists of names for data attributes
        framework_names = "|".join(fw["name"] for fw in rule["frameworks"]).lower()
        standard_names = "|".join(std["name"] for std in rule["standards"]).lower()
        template_names = "|".join(tpl["name"] for tpl in rule["templates"]).lower()

        # Generate documentation URL (rule identifier to kebab-case)
        doc_url_name = rule_id.lower().replace('_', '-')
        doc_url = f"https://docs.aws.amazon.com/config/latest/developerguide/{doc_url_name}.html"

        html_content += f"""
            <tr id="{escape_html(rule_id)}" data-catalog="{str(in_catalog).lower()}" data-framework="{str(in_f).lower()}" data-standard="{str(in_s).lower()}" data-template="{str(in_t).lower()}" data-venn="{venn_segment}" data-search="{escape_html(rule_id.lower())} {escape_html(description.lower())}" data-frameworks="{escape_html(framework_names)}" data-standards="{escape_html(standard_names)}" data-templates="{escape_html(template_names)}">
                <td><a href="{doc_url}" target="_blank" class="rule-id">{escape_html(rule_id)}</a></td>
                <td style="text-align: center;">{catalog_badge}</td>
                <td>
                    <div class="description">{description_html}</div>
                    {source_html}
                </td>
                <td style="text-align: center;">{severity_badge}</td>
                <td><div class="tag-list">{framework_badges}</div></td>
                <td><div class="tag-list">{standard_badges}</div></td>
                <td><div class="tag-list">{template_badges}</div></td>
            </tr>
"""

    html_content += f"""
        </tbody>
    </table>

    <div class="generated-at">
        Generated at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
        {len(frameworks)} frameworks | {len(standards)} security standards | {len(templates)} templates
    </div>

    <script>
        // URL parameter filters (set on page load)
        let urlFramework = '';
        let urlStandard = '';
        let urlTemplate = '';

        function getUrlParams() {{
            const params = new URLSearchParams(window.location.search);
            return {{
                framework: params.get('framework') || '',
                standard: params.get('standard') || '',
                template: params.get('template') || '',
                venn: params.get('venn') || ''
            }};
        }}

        // Normalize template name for matching
        function normalizeTemplateName(name) {{
            return name.toLowerCase()
                .replace(/[()\\s.-]+/g, '');    // Remove parens, spaces, dots, hyphens
        }}

        // Check if two template names match (exact match after normalization)
        function templatesMatch(stored, urlParam) {{
            if (!stored || !urlParam) return false;
            const s = normalizeTemplateName(stored);
            const u = normalizeTemplateName(urlParam);
            return s === u;
        }}

        function filterRules() {{
            const searchText = document.getElementById('searchBox').value.toLowerCase();
            const filterCatalog = document.getElementById('filterCatalog').checked;
            const filterFramework = document.getElementById('filterFramework').checked;
            const filterStandard = document.getElementById('filterStandard').checked;
            const filterTemplate = document.getElementById('filterTemplate').checked;

            const filterFOnly = document.getElementById('filterFOnly').checked;
            const filterTOnly = document.getElementById('filterTOnly').checked;
            const filterSOnly = document.getElementById('filterSOnly').checked;
            const filterFT = document.getElementById('filterFT').checked;
            const filterFS = document.getElementById('filterFS').checked;
            const filterTS = document.getElementById('filterTS').checked;
            const filterFTS = document.getElementById('filterFTS').checked;

            const anyVennFilter = filterFOnly || filterTOnly || filterSOnly || filterFT || filterFS || filterTS || filterFTS;

            const rows = document.querySelectorAll('#rulesTable tr');
            let visibleCount = 0;
            let filteredCatalog = 0;
            let filteredFrameworks = 0;
            let filteredStandards = 0;
            let filteredTemplates = 0;

            rows.forEach(row => {{
                const searchData = row.dataset.search || '';
                const inCatalog = row.dataset.catalog === 'true';
                const inFramework = row.dataset.framework === 'true';
                const inStandard = row.dataset.standard === 'true';
                const inTemplate = row.dataset.template === 'true';
                const venn = row.dataset.venn || '';
                const frameworks = row.dataset.frameworks || '';
                const standards = row.dataset.standards || '';
                const templates = row.dataset.templates || '';

                let show = true;

                // Search filter
                if (searchText && !searchData.includes(searchText)) {{
                    show = false;
                }}

                // URL parameter matching (compute first, needed for membership filters)
                // Use exact matching against pipe-delimited values
                const frameworkList = frameworks ? frameworks.split('|') : [];
                const standardList = standards ? standards.split('|') : [];
                const templateList = templates ? templates.split('|') : [];

                const normalizedUrlFramework = urlFramework ? urlFramework.toLowerCase() : '';
                const normalizedUrlStandard = urlStandard ? urlStandard.toLowerCase() : '';

                const matchesUrlFramework = normalizedUrlFramework && frameworkList.some(f => f === normalizedUrlFramework);
                const matchesUrlStandard = normalizedUrlStandard && standardList.some(s => s === normalizedUrlStandard);
                const matchesUrlTemplate = urlTemplate && templateList.some(t => templatesMatch(t, urlTemplate));
                const hasAnyUrlFilter = urlFramework || urlStandard || urlTemplate;

                // URL parameter filters (OR logic - show if in ANY of the specified sources)
                if (hasAnyUrlFilter) {{
                    if (!matchesUrlFramework && !matchesUrlStandard && !matchesUrlTemplate) show = false;
                }}

                // Membership filters (AND logic)
                // When URL filter is active, check against the specific URL-filtered source
                if (filterCatalog && !inCatalog) show = false;
                if (filterFramework) {{
                    if (urlFramework) {{
                        if (!matchesUrlFramework) show = false;
                    }} else {{
                        if (!inFramework) show = false;
                    }}
                }}
                if (filterStandard) {{
                    if (urlStandard) {{
                        if (!matchesUrlStandard) show = false;
                    }} else {{
                        if (!inStandard) show = false;
                    }}
                }}
                if (filterTemplate) {{
                    if (urlTemplate) {{
                        if (!matchesUrlTemplate) show = false;
                    }} else {{
                        if (!inTemplate) show = false;
                    }}
                }}

                // Venn segment filters (OR logic)
                // When URL filters are active, compute segment based on URL-filtered sources
                if (anyVennFilter) {{
                    // Determine effective membership based on URL filters
                    // When ANY URL filter is active, non-filtered sources are treated as "not in scope"
                    // (i.e., false), not as global membership. This ensures Venn segments are
                    // computed relative to the filtered sources only.
                    const effectiveF = hasAnyUrlFilter ? matchesUrlFramework : inFramework;
                    const effectiveT = hasAnyUrlFilter ? matchesUrlTemplate : inTemplate;
                    const effectiveS = hasAnyUrlFilter ? matchesUrlStandard : inStandard;

                    // Compute the effective venn segment
                    let effectiveVenn = '';
                    if (effectiveF && effectiveT && effectiveS) effectiveVenn = 'fts';
                    else if (effectiveF && effectiveT) effectiveVenn = 'ft';
                    else if (effectiveF && effectiveS) effectiveVenn = 'fs';
                    else if (effectiveT && effectiveS) effectiveVenn = 'ts';
                    else if (effectiveF) effectiveVenn = 'f';
                    else if (effectiveT) effectiveVenn = 't';
                    else if (effectiveS) effectiveVenn = 's';

                    let matchesVenn = false;
                    if (filterFOnly && effectiveVenn === 'f') matchesVenn = true;
                    if (filterTOnly && effectiveVenn === 't') matchesVenn = true;
                    if (filterSOnly && effectiveVenn === 's') matchesVenn = true;
                    if (filterFT && effectiveVenn === 'ft') matchesVenn = true;
                    if (filterFS && effectiveVenn === 'fs') matchesVenn = true;
                    if (filterTS && effectiveVenn === 'ts') matchesVenn = true;
                    if (filterFTS && effectiveVenn === 'fts') matchesVenn = true;
                    if (!matchesVenn) show = false;
                }}

                if (show) {{
                    row.classList.remove('hidden');
                    visibleCount++;
                    if (inCatalog) filteredCatalog++;
                    // When ANY URL filter is active, count only matches to URL-filtered sources
                    // Non-filtered sources show 0 (not in scope), not global counts
                    if (hasAnyUrlFilter) {{
                        if (matchesUrlFramework) filteredFrameworks++;
                        if (matchesUrlStandard) filteredStandards++;
                        if (matchesUrlTemplate) filteredTemplates++;
                    }} else {{
                        // No URL filters - use global membership
                        if (inFramework) filteredFrameworks++;
                        if (inStandard) filteredStandards++;
                        if (inTemplate) filteredTemplates++;
                    }}

                    // Filter badges within visible rows when URL filters are active
                    if (hasAnyUrlFilter) {{
                        // Framework badges - show only the filtered framework or hide all
                        const frameworkBadges = row.querySelectorAll('.badge.framework');
                        frameworkBadges.forEach(badge => {{
                            if (urlFramework) {{
                                const badgeName = badge.dataset.name || '';
                                if (badgeName === normalizedUrlFramework) {{
                                    badge.classList.remove('hidden');
                                }} else {{
                                    badge.classList.add('hidden');
                                }}
                            }} else {{
                                // No framework filter - hide all framework badges
                                badge.classList.add('hidden');
                            }}
                        }});

                        // Standard badges - show only the filtered standard or hide all
                        const standardBadges = row.querySelectorAll('.badge.standard');
                        standardBadges.forEach(badge => {{
                            if (urlStandard) {{
                                const badgeName = badge.dataset.name || '';
                                if (badgeName === normalizedUrlStandard) {{
                                    badge.classList.remove('hidden');
                                }} else {{
                                    badge.classList.add('hidden');
                                }}
                            }} else {{
                                // No standard filter - hide all standard badges
                                badge.classList.add('hidden');
                            }}
                        }});

                        // Template badges - show only the filtered template or hide all
                        const templateBadges = row.querySelectorAll('.badge.template');
                        templateBadges.forEach(badge => {{
                            if (urlTemplate) {{
                                const badgeName = badge.dataset.name || '';
                                if (templatesMatch(badgeName, urlTemplate)) {{
                                    badge.classList.remove('hidden');
                                }} else {{
                                    badge.classList.add('hidden');
                                }}
                            }} else {{
                                // No template filter - hide all template badges
                                badge.classList.add('hidden');
                            }}
                        }});
                    }} else {{
                        // No URL filters - show all badges
                        row.querySelectorAll('.badge.framework, .badge.standard, .badge.template').forEach(badge => {{
                            badge.classList.remove('hidden');
                        }});
                    }}
                }} else {{
                    row.classList.add('hidden');
                }}
            }});

            // Update stats cards with filtered counts
            document.getElementById('statTotal').textContent = visibleCount;
            document.getElementById('statCatalog').textContent = filteredCatalog;
            document.getElementById('statFrameworks').textContent = filteredFrameworks;
            document.getElementById('statStandards').textContent = filteredStandards;
            document.getElementById('statTemplates').textContent = filteredTemplates;

            // Update labels to singular when URL filter is active
            document.getElementById('labelFrameworks').textContent = urlFramework ? 'In Audit Manager Framework' : 'In Audit Manager Frameworks';
            document.getElementById('labelStandards').textContent = urlStandard ? 'In Security Hub Standard' : 'In Security Hub Standards';
            document.getElementById('labelTemplates').textContent = urlTemplate ? 'In Config Conformance Pack Template' : 'In Config Conformance Pack Templates';

            document.getElementById('ruleCount').textContent = `Showing ${{visibleCount}} of {total_rules} rules`;
        }}

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {{
            const params = getUrlParams();
            urlFramework = params.framework;
            urlStandard = params.standard;
            urlTemplate = params.template;
            const urlVenn = params.venn;

            // Pre-check venn segment checkbox if specified in URL
            const vennCheckboxMap = {{
                'f': 'filterFOnly',
                't': 'filterTOnly',
                's': 'filterSOnly',
                'ft': 'filterFT',
                'fs': 'filterFS',
                'ts': 'filterTS',
                'fts': 'filterFTS'
            }};
            if (urlVenn && vennCheckboxMap[urlVenn]) {{
                document.getElementById(vennCheckboxMap[urlVenn]).checked = true;
            }}

            // Show filter banner if URL parameters are set
            if (urlFramework || urlStandard || urlTemplate || urlVenn) {{
                const banner = document.getElementById('urlFilterBanner');
                const text = document.getElementById('urlFilterText');
                let filterParts = [];
                if (urlFramework) filterParts.push('Framework: ' + urlFramework);
                if (urlStandard) filterParts.push('Standard: ' + urlStandard);
                if (urlTemplate) filterParts.push('Template: ' + urlTemplate);
                if (urlVenn) {{
                    const vennLabels = {{
                        'f': 'Framework Only',
                        't': 'Template Only',
                        's': 'Standard Only',
                        'ft': 'Framework & Template',
                        'fs': 'Framework & Standard',
                        'ts': 'Template & Standard',
                        'fts': 'All Three'
                    }};
                    filterParts.push('Segment: ' + (vennLabels[urlVenn] || urlVenn));
                }}
                text.textContent = 'Filtered by: ' + filterParts.join(' | ');
                banner.style.display = 'block';
            }}

            // Apply filters
            filterRules();
        }});
    </script>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Rule Manifest written to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Rule Manifest report listing all Config rules"
    )
    parser.add_argument(
        "-o", "--output",
        default="rule-manifest/rule_manifest.html",
        help="Output HTML file path (default: rule-manifest/rule_manifest.html)"
    )
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Project directory containing source data (default: current directory)"
    )

    args = parser.parse_args()

    project_dir = os.path.abspath(args.project_dir)

    print("Loading data sources...")

    # Load all data sources
    print("  Loading Control Catalog...")
    control_catalog = load_control_catalog(project_dir)
    print(f"    Found {len(control_catalog)} controls")

    print("  Loading Security Standards...")
    standards = load_security_standards(project_dir)
    total_standard_rules = sum(len(s["controls"]) for s in standards.values())
    print(f"    Found {len(standards)} standards with {total_standard_rules} rule mappings")

    print("  Loading Conformance Pack Templates...")
    templates = load_conformance_templates(project_dir)
    total_template_rules = sum(len(t["rules"]) for t in templates.values())
    print(f"    Found {len(templates)} templates with {total_template_rules} rules")

    print("  Loading Framework Reports...")
    frameworks = load_framework_reports(project_dir)
    total_framework_rules = sum(len(f["rules"]) for f in frameworks.values())
    print(f"    Found {len(frameworks)} frameworks with {total_framework_rules} rule references")

    print("  Loading Managed Rules...")
    managed_rules = load_managed_rules(project_dir)
    print(f"    Found {len(managed_rules)} managed rule identifiers")

    print("\nBuilding rule manifest...")
    manifest = build_rule_manifest(control_catalog, standards, templates, frameworks, managed_rules)
    print(f"  Total unique rules: {len(manifest)}")

    print("\nGenerating HTML report...")
    generate_html_report(manifest, args.output, frameworks, standards, templates)

    print(f"\nDone! Open {args.output} to view the manifest.")


if __name__ == "__main__":
    main()
