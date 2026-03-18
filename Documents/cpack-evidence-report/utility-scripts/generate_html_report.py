#!/usr/bin/env python3
"""
Generate multi-page HTML compliance reports from JSON compliance data.

Generates three interconnected HTML pages:
1. Summary Report - Controls grouped by control set with evidence source summaries
2. Evidence Sources - Config rules with resource compliance status
3. Resources - Resource configurations

Inputs:
1. Compliance report JSON (from generate_compliance_report.py)
2. Resource configurations JSON (from get_resource_configurations.py)

Output:
Three HTML files with hyperlinks between them.
"""

import argparse
import csv
import html
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import quote


def load_json_file(file_path: str) -> dict:
    """Load and parse a JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_security_standard_mappings(project_dir: str) -> dict:
    """
    Load Security Hub control ID to Config rule mappings from security standard files.

    Returns dict mapping security control ID (e.g., 'ACM.1') to normalized Config rule identifier.
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
                    normalized = normalize_config_rule_name(config_rule).upper()
                    if normalized:
                        mappings[control_id.upper()] = normalized
        except Exception:
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


def escape_html(text) -> str:
    """Escape HTML special characters."""
    if text is None:
        return ""
    return html.escape(str(text))


def make_anchor_id(text: str) -> str:
    """Create a valid HTML anchor ID from text."""
    # Replace special characters with underscores
    result = ""
    for c in text:
        if c.isalnum():
            result += c
        else:
            result += "_"
    return result


def load_framework_template_mapping(excel_path: str) -> tuple:
    """
    Load the framework-to-conformance-pack-template mapping from Frameworks.xlsx.

    Args:
        excel_path: Path to Frameworks.xlsx

    Returns:
        Tuple of (name_mapping, id_mapping) where each is a dict mapping to template name
    """
    name_mapping = {}
    id_mapping = {}
    try:
        import pandas as pd
        df = pd.read_excel(excel_path)
        for _, row in df.iterrows():
            framework = str(row.get('S Audit Manager Framework', '')).strip()
            framework_id = str(row.get('Framework ID', '')).strip()
            template = row.get('Conformance Pack Template name', '')
            notes = str(row.get('Notes', '')).strip()

            # Skip if no template or NaN or marked as "No Equivalent"
            if pd.isna(template) or not template or "no equivalent" in notes.lower():
                continue

            template = str(template).strip()
            if framework and framework != 'nan':
                name_mapping[framework] = template
            if framework_id and framework_id != 'nan':
                id_mapping[framework_id] = template
    except ImportError:
        print("Warning: pandas not installed, cannot load framework mappings from Excel")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Warning: Error loading framework mappings: {e}")
    return name_mapping, id_mapping


def lookup_security_standard(excel_path: str, framework_id: str) -> str:
    """
    Look up the Security Standard for a framework from Frameworks.xlsx.

    Args:
        excel_path: Path to Frameworks.xlsx
        framework_id: The AWS Audit Manager framework ID

    Returns:
        The security standard name or None if not found
    """
    try:
        import pandas as pd
        df = pd.read_excel(excel_path)
        match = df[df['Framework ID'] == framework_id]
        if match.empty:
            return None
        security_standard = match['Security Standard File'].iloc[0]
        if pd.isna(security_standard) or not security_standard:
            return None
        return str(security_standard).strip()
    except ImportError:
        return None
    except Exception:
        return None


def load_security_hub_standard(standard_file_path: str) -> dict:
    """
    Load Security Hub standard data from JSON file.

    Args:
        standard_file_path: Path to the Security Hub standard JSON file

    Returns:
        Dict with 'total_controls', 'control_ids' (set of control IDs)
    """
    try:
        with open(standard_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        control_ids = set()
        for control in data.get("controls", []):
            control_id = control.get("control_id") or control.get("security_control_id")
            if control_id:
                control_ids.add(control_id)
        return {
            "total_controls": data.get("total_controls", len(control_ids)),
            "control_ids": control_ids,
            "standard_name": data.get("standard_name", "")
        }
    except FileNotFoundError:
        return None
    except Exception:
        return None


def find_security_hub_standard_file(security_standard: str, project_dir: str) -> str:
    """
    Find the Security Hub standard JSON file based on the standard name.

    Args:
        security_standard: The security standard name from Frameworks.xlsx
        project_dir: Path to the project directory

    Returns:
        Path to the JSON file or None if not found
    """
    if not security_standard:
        return None

    standard_folder = os.path.join(project_dir, "security-standard-controls")
    if not os.path.exists(standard_folder):
        return None

    # Try direct match with .json extension
    json_path = os.path.join(standard_folder, f"{security_standard}.json")
    if os.path.exists(json_path):
        return json_path

    return None


def load_control_catalog_identifiers(project_dir: str) -> set:
    """
    Load control identifiers from the detective-controls.json file.

    Args:
        project_dir: Path to the project directory

    Returns:
        Set of control identifiers (uppercase) from the AWS Control Catalog
    """
    catalog_file = os.path.join(project_dir, "control-catalog", "detective-controls.json")
    identifiers = set()

    try:
        with open(catalog_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        controls = data.get("controls", {})
        # Keys are the identifiers
        for identifier in controls.keys():
            identifiers.add(identifier.upper())
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return identifiers


def count_security_hub_sources_in_framework(compliance_report: dict) -> set:
    """
    Count unique Security Hub control IDs referenced in the framework.

    Returns:
        Set of Security Hub control IDs
    """
    security_hub_controls = set()
    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") == "AWS_Security_Hub":
                    control_id = source.get("securityHubControlId") or source.get("keywordValue")
                    if control_id:
                        security_hub_controls.add(control_id)
    return security_hub_controls


def count_framework_rules_in_standard(compliance_report: dict, security_hub_normalized_ids: set) -> int:
    """
    Count unique framework rules that are in the Security Hub standard.

    This counts both:
    - AWS_Security_Hub sources (by control ID)
    - AWS_Config sources whose keywordValue matches a normalized Security Hub identifier

    Args:
        compliance_report: The compliance report data
        security_hub_normalized_ids: Set of normalized identifiers from Security Hub standard

    Returns:
        Count of unique framework rules that are in the standard
    """
    if not security_hub_normalized_ids:
        return 0

    rules_in_standard = set()
    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                source_type = source.get("sourceType")

                if source_type == "AWS_Security_Hub":
                    # Security Hub sources are always in the standard
                    keyword = source.get("keywordValue") or source.get("securityHubControlId")
                    if keyword:
                        rules_in_standard.add(keyword)

                elif source_type == "AWS_Config":
                    # Check if AWS_Config source matches a Security Hub identifier
                    keyword = source.get("keywordValue", "")
                    if keyword and keyword.upper() in security_hub_normalized_ids:
                        rules_in_standard.add(keyword)

    return len(rules_in_standard)


def count_framework_rules_not_covered(compliance_report: dict, security_hub_normalized_ids: set, has_template: bool = True) -> int:
    """
    Count unique framework rules that are NOT in template AND NOT in Security Hub standard.

    Args:
        compliance_report: The compliance report data
        security_hub_normalized_ids: Set of normalized identifiers from Security Hub standard (can be None)
        has_template: Whether a conformance pack template is configured

    Returns:
        Count of unique framework rules not covered by template or standard
    """
    not_covered_rules = set()

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                source_type = source.get("sourceType")

                # Check if in template (only if template is configured)
                in_template = source.get("inConformancePack", False) if has_template else False

                # Check if in standard
                in_standard = False
                if source_type == "AWS_Security_Hub":
                    in_standard = True
                elif source_type == "AWS_Config" and security_hub_normalized_ids:
                    keyword = source.get("keywordValue", "")
                    if keyword and keyword.upper() in security_hub_normalized_ids:
                        in_standard = True

                # Determine if covered
                # If template is configured, must be in template OR standard
                # If only standard is configured, must be in standard
                # If only template is configured, must be in template
                if has_template and security_hub_normalized_ids:
                    is_covered = in_template or in_standard
                elif has_template:
                    is_covered = in_template
                elif security_hub_normalized_ids:
                    is_covered = in_standard
                else:
                    is_covered = True  # Nothing to check against

                if not is_covered:
                    keyword = source.get("keywordValue", "")
                    if keyword:
                        not_covered_rules.add(keyword)

    return len(not_covered_rules)


def calculate_venn_diagram_data(
    compliance_report: dict,
    security_hub_normalized_ids: set,
    template_identifiers: set,
    has_template: bool = True,
    security_hub_mappings: dict = None
) -> dict:
    """
    Calculate the counts for each segment of a 3-way Venn diagram.

    Args:
        compliance_report: The compliance report data
        security_hub_normalized_ids: Set of normalized identifiers from Security Hub standard
        template_identifiers: Set of rule identifiers from conformance pack template
        has_template: Whether a conformance pack template is configured
        security_hub_mappings: Dict mapping Security Hub control IDs to Config rule identifiers
                               (for resolving indirect references in framework controls)

    Returns:
        Dict with counts for each Venn diagram segment:
        - f_only: Framework only
        - t_only: Template only
        - s_only: Standard only
        - f_t: Framework & Template (not Standard)
        - f_s: Framework & Standard (not Template)
        - t_s: Template & Standard (not Framework)
        - f_t_s: Framework & Template & Standard (all three)
    """
    if not security_hub_normalized_ids:
        security_hub_normalized_ids = set()
    if not template_identifiers:
        template_identifiers = set()
    if not security_hub_mappings:
        security_hub_mappings = {}

    # Normalize template identifiers for comparison
    template_normalized = set(t.upper() for t in template_identifiers)

    # Collect framework rules using normalized identifiers
    # Only count rules that can be properly normalized for comparison
    framework_normalized_ids = set()  # Normalized IDs of all framework rules
    framework_rules = {}  # normalized_id -> (in_template, in_standard)
    non_normalizable_count = 0  # Security Hub sources without configRuleName
    non_normalizable_ids = set()  # Track unique non-normalizable rule IDs

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            evidence_sources = control.get("evidenceSources", [])

            # Process explicit evidence sources
            for source in evidence_sources:
                source_type = source.get("sourceType")
                keyword = source.get("keywordValue", "")

                if not keyword:
                    continue

                if source_type == "AWS_Config":
                    normalized_id = keyword.upper()
                    in_template = source.get("inConformancePack", False) if has_template else False
                    in_standard = normalized_id in security_hub_normalized_ids
                    framework_normalized_ids.add(normalized_id)
                    framework_rules[normalized_id] = (in_template, in_standard)

                elif source_type == "AWS_Security_Hub":
                    # Security Hub sources need to be mapped to their normalized config rule ID
                    config_rule = source.get("configRuleName", "")
                    if config_rule:
                        normalized_id = normalize_config_rule_name(config_rule).upper()
                        in_template = False  # Security Hub sources aren't in conformance pack template
                        in_standard = normalized_id in security_hub_normalized_ids
                        framework_normalized_ids.add(normalized_id)

                        # Only add if not already present (AWS_Config takes precedence)
                        if normalized_id not in framework_rules:
                            framework_rules[normalized_id] = (in_template, in_standard)
                    else:
                        # Security Hub sources without configRuleName can't be compared
                        # but should still count as framework-only rules
                        if keyword not in non_normalizable_ids:
                            non_normalizable_ids.add(keyword)
                            non_normalizable_count += 1

            # If no evidence sources, try to resolve via Security Hub control reference
            # Framework controls (business requirements) may reference Security Hub
            # controls (technical detective controls) which map to Config rules
            if not evidence_sources and security_hub_mappings:
                description = control.get("controlDescription", "")
                sec_hub_control_id = extract_security_hub_control_from_description(description)

                if sec_hub_control_id and sec_hub_control_id in security_hub_mappings:
                    normalized_id = security_hub_mappings[sec_hub_control_id]
                    in_template = normalized_id in template_normalized
                    in_standard = normalized_id in security_hub_normalized_ids
                    framework_normalized_ids.add(normalized_id)

                    if normalized_id not in framework_rules:
                        framework_rules[normalized_id] = (in_template, in_standard)

    # Calculate framework segments
    f_only = 0      # Framework only
    f_t = 0         # Framework & Template (not Standard)
    f_s = 0         # Framework & Standard (not Template)
    f_t_s = 0       # All three

    for normalized_id, (in_template, in_standard) in framework_rules.items():
        if in_template and in_standard:
            f_t_s += 1
        elif in_template and not in_standard:
            f_t += 1
        elif in_standard and not in_template:
            f_s += 1
        else:
            f_only += 1

    # Calculate template-only and template-standard (not framework)
    t_only = 0      # Template only
    t_s = 0         # Template & Standard (not Framework)

    for t_rule in template_normalized:
        in_framework = t_rule in framework_normalized_ids
        in_standard = t_rule in security_hub_normalized_ids

        if not in_framework:
            if in_standard:
                t_s += 1
            else:
                t_only += 1

    # Calculate standard-only (not framework, not template)
    s_only = 0
    for s_rule in security_hub_normalized_ids:
        in_framework = s_rule in framework_normalized_ids
        in_template = s_rule in template_normalized

        if not in_framework and not in_template:
            s_only += 1

    # Add non-normalizable Security Hub sources to framework-only count
    # These can't be matched against template or standard
    f_only += non_normalizable_count

    return {
        "f_only": f_only,
        "t_only": t_only,
        "s_only": s_only,
        "f_t": f_t,
        "f_s": f_s,
        "t_s": t_s,
        "f_t_s": f_t_s,
        "f_total": len(framework_rules) + non_normalizable_count,
        "t_total": len(template_identifiers),
        "s_total": len(security_hub_normalized_ids)
    }


def generate_venn_diagram_svg(venn_data: dict, manifest_base_url: str = "") -> str:
    """
    Generate an SVG Venn diagram with three overlapping circles.

    Args:
        venn_data: Dict with counts for each segment
        manifest_base_url: Base URL to the rule manifest (with framework/standard/template params)

    Returns:
        SVG markup string
    """
    f_only = venn_data.get("f_only", 0)
    t_only = venn_data.get("t_only", 0)
    s_only = venn_data.get("s_only", 0)
    f_t = venn_data.get("f_t", 0)
    f_s = venn_data.get("f_s", 0)
    t_s = venn_data.get("t_s", 0)
    f_t_s = venn_data.get("f_t_s", 0)

    # Circle positions and radius
    # Framework: top-left, Template: top-right, Standard: bottom-center
    cx_f, cy_f = 150, 130  # Framework circle center
    cx_t, cy_t = 250, 130  # Template circle center
    cx_s, cy_s = 200, 210  # Standard circle center
    r = 90  # Circle radius

    # Build URLs for each venn segment
    def make_venn_url(segment: str) -> str:
        if not manifest_base_url:
            return ""
        separator = "&" if "?" in manifest_base_url else "?"
        return f"{manifest_base_url}{separator}venn={segment}"

    url_f = make_venn_url("f")
    url_t = make_venn_url("t")
    url_s = make_venn_url("s")
    url_ft = make_venn_url("ft")
    url_fs = make_venn_url("fs")
    url_ts = make_venn_url("ts")
    url_fts = make_venn_url("fts")

    # Helper to wrap count in link if URL available
    def linked_count(count: int, url: str, x: int, y: int) -> str:
        if url and count > 0:
            return f'<a href="{url}" style="text-decoration: none;"><text x="{x}" y="{y}" class="venn-count venn-link" text-anchor="middle">{count}</text></a>'
        return f'<text x="{x}" y="{y}" class="venn-count" text-anchor="middle">{count}</text>'

    svg = f'''
    <svg viewBox="0 0 400 340" style="max-width: 500px; width: 100%;">
        <defs>
            <style>
                .venn-circle {{ fill-opacity: 0.3; stroke-width: 2; }}
                .venn-framework {{ fill: #4299e1; stroke: #2b6cb0; }}
                .venn-template {{ fill: #48bb78; stroke: #276749; }}
                .venn-standard {{ fill: #9f7aea; stroke: #6b46c1; }}
                .venn-label {{ font-size: 12px; font-weight: bold; fill: #2d3748; }}
                .venn-count {{ font-size: 14px; font-weight: bold; fill: #1a202c; }}
                .venn-link {{ cursor: pointer; }}
                .venn-link:hover {{ fill: #4c51bf; text-decoration: underline; }}
                .venn-title {{ font-size: 11px; fill: #4a5568; }}
            </style>
        </defs>

        <!-- Framework circle (top-left, blue) -->
        <circle cx="{cx_f}" cy="{cy_f}" r="{r}" class="venn-circle venn-framework"/>

        <!-- Template circle (top-right, green) -->
        <circle cx="{cx_t}" cy="{cy_t}" r="{r}" class="venn-circle venn-template"/>

        <!-- Standard circle (bottom, purple) -->
        <circle cx="{cx_s}" cy="{cy_s}" r="{r}" class="venn-circle venn-standard"/>

        <!-- Labels for each region -->
        <!-- Framework only -->
        {linked_count(f_only, url_f, 95, 110)}

        <!-- Template only -->
        {linked_count(t_only, url_t, 305, 110)}

        <!-- Standard only -->
        {linked_count(s_only, url_s, 200, 280)}

        <!-- Framework & Template (not Standard) -->
        {linked_count(f_t, url_ft, 200, 95)}

        <!-- Framework & Standard (not Template) -->
        {linked_count(f_s, url_fs, 140, 195)}

        <!-- Template & Standard (not Framework) -->
        {linked_count(t_s, url_ts, 260, 195)}

        <!-- All three -->
        {linked_count(f_t_s, url_fts, 200, 160)}

        <!-- Circle labels -->
        <text x="70" y="50" class="venn-label">Framework</text>
        <text x="70" y="65" class="venn-title">({venn_data.get("f_total", 0)} rules)</text>

        <text x="280" y="50" class="venn-label">Template</text>
        <text x="280" y="65" class="venn-title">({venn_data.get("t_total", 0)} rules)</text>

        <text x="200" y="320" class="venn-label" text-anchor="middle">Standard</text>
        <text x="200" y="335" class="venn-title" text-anchor="middle">({venn_data.get("s_total", 0)} rules)</text>
    </svg>
    '''

    return svg


def normalize_config_rule_name(rule_name: str) -> str:
    """
    Normalize a Config rule name for comparison between Security Hub and template formats.

    Security Hub format: securityhub-acm-certificate-expiration-check-530f2472
    Template format: ACM_CERTIFICATE_EXPIRATION_CHECK

    Returns normalized form: acm_certificate_expiration_check
    """
    if not rule_name:
        return ""

    name = rule_name.lower()

    # Strip 'securityhub-' prefix
    if name.startswith("securityhub-"):
        name = name[12:]

    # Strip trailing hash (8 hex characters after last hyphen)
    # Pattern: -[0-9a-f]{8}$
    if len(name) > 9 and name[-9] == '-':
        suffix = name[-8:]
        if all(c in '0123456789abcdef' for c in suffix):
            name = name[:-9]

    # Convert hyphens to underscores
    name = name.replace('-', '_')

    return name


def extract_template_rule_identifiers(yaml_path: str) -> set:
    """
    Extract Config rule SourceIdentifiers from a conformance pack YAML template.

    Args:
        yaml_path: Path to the YAML file

    Returns:
        Set of SourceIdentifier values
    """
    identifiers = set()
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Find all SourceIdentifier values
        for match in re.finditer(r'SourceIdentifier:\s*(\S+)', content):
            identifier = match.group(1).strip()
            if identifier:
                identifiers.add(identifier)
    except Exception:
        pass

    return identifiers


def get_security_hub_config_rules(standard_file_path: str) -> set:
    """
    Get Config rule names from a Security Hub standard JSON file.

    Args:
        standard_file_path: Path to the Security Hub standard JSON file

    Returns:
        Set of config_rule values
    """
    config_rules = set()
    try:
        with open(standard_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for control in data.get("controls", []):
            config_rule = control.get("config_rule")
            if config_rule:
                config_rules.add(config_rule)
    except Exception:
        pass

    return config_rules


def get_security_hub_normalized_identifiers(standard_file_path: str) -> set:
    """
    Get normalized Config rule identifiers from a Security Hub standard JSON file.

    This normalizes Security Hub config rule names (e.g., securityhub-vpc-sg-open-only-to-authorized-ports-dee04c80)
    to standard identifiers (e.g., VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS) for matching against
    AWS_Config sources in the framework.

    Args:
        standard_file_path: Path to the Security Hub standard JSON file

    Returns:
        Set of normalized identifier strings (uppercase with underscores)
    """
    normalized_ids = set()
    try:
        with open(standard_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for control in data.get("controls", []):
            config_rule = control.get("config_rule")
            if config_rule:
                normalized = normalize_config_rule_name(config_rule)
                if normalized:
                    # Convert to uppercase for matching
                    normalized_ids.add(normalized.upper())
    except Exception:
        pass

    return normalized_ids


def calculate_template_standard_intersection(template_yaml_path: str, security_hub_file_path: str) -> dict:
    """
    Calculate the intersection between template rules and Security Hub standard rules.

    Args:
        template_yaml_path: Path to conformance pack YAML template
        security_hub_file_path: Path to Security Hub standard JSON file

    Returns:
        Dict with intersection stats:
        - template_rules: total rules in template
        - standard_rules: total rules in standard
        - intersection: count of matching rules
        - template_only: rules only in template
        - standard_only: rules only in standard
    """
    if not template_yaml_path or not security_hub_file_path:
        return None

    # Extract and normalize template rules
    template_identifiers = extract_template_rule_identifiers(template_yaml_path)
    template_normalized = {normalize_config_rule_name(r): r for r in template_identifiers}

    # Extract and normalize Security Hub rules
    sh_config_rules = get_security_hub_config_rules(security_hub_file_path)
    sh_normalized = {normalize_config_rule_name(r): r for r in sh_config_rules}

    # Calculate intersection using normalized names
    template_keys = set(template_normalized.keys())
    sh_keys = set(sh_normalized.keys())

    intersection = template_keys & sh_keys
    template_only = template_keys - sh_keys
    standard_only = sh_keys - template_keys

    return {
        "template_rules": len(template_identifiers),
        "standard_rules": len(sh_config_rules),
        "intersection": len(intersection),
        "template_only": len(template_only),
        "standard_only": len(standard_only),
        "intersection_rules": intersection,
        "template_only_rules": template_only,
        "standard_only_rules": standard_only
    }


def load_templates_to_yaml_mapping(yaml_folder: str) -> dict:
    """
    Build template-to-YAML filename mapping by scanning the YAML folder.

    Args:
        yaml_folder: Path to folder containing YAML templates

    Returns:
        Dict mapping normalized template name to YAML filename
    """
    mapping = {}
    if not os.path.exists(yaml_folder):
        return mapping

    for filename in os.listdir(yaml_folder):
        if filename.endswith('.yaml'):
            # Create a normalized key from the filename
            # e.g., "Operational-Best-Practices-for-ACSC-Essential8.yaml"
            # -> "operational best practices for acsc essential8"
            name_part = filename.replace('.yaml', '').replace('-', ' ').lower()
            mapping[name_part] = filename

    return mapping


def find_matching_template(framework_name: str, name_mapping: dict, id_mapping: dict = None, framework_id: str = None) -> str:
    """
    Find the conformance pack template that matches the framework.

    Args:
        framework_name: The framework name from the compliance report
        name_mapping: Dict mapping framework name to template name
        id_mapping: Dict mapping framework ID to template name (optional)
        framework_id: The framework ID for exact matching (optional)

    Returns:
        Template name or None if not found
    """
    # Try exact match by framework ID first
    if framework_id and id_mapping and framework_id in id_mapping:
        return id_mapping[framework_id]

    # Try exact match by name
    if framework_name in name_mapping:
        return name_mapping[framework_name]

    # Try partial match (framework name contains mapping key or vice versa)
    framework_lower = framework_name.lower()
    for key, template in name_mapping.items():
        if key.lower() in framework_lower or framework_lower in key.lower():
            return template

    # Try matching key patterns like "PCI DSS V4.0" in framework name
    for key, template in name_mapping.items():
        # Normalize both for comparison
        key_normalized = re.sub(r'[^a-z0-9]', '', key.lower())
        framework_normalized = re.sub(r'[^a-z0-9]', '', framework_lower)
        if key_normalized in framework_normalized or framework_normalized in key_normalized:
            return template

    return None


def count_config_rules_in_template(yaml_path: str) -> int:
    """
    Count the number of Config rules in a conformance pack YAML template.

    Args:
        yaml_path: Path to the YAML file

    Returns:
        Number of Config rules (AWS::Config::ConfigRule resources)
    """
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Count occurrences of "Type: AWS::Config::ConfigRule"
        return len(re.findall(r"Type:\s*AWS::Config::ConfigRule", content))
    except FileNotFoundError:
        return 0


def find_template_yaml_files(template_name: str, yaml_folder: str, templates_to_yaml: dict = None) -> list:
    """
    Find all YAML files that match a conformance pack template.

    Uses two-step lookup:
    1. First check templates_to_yaml mapping for direct YAML filename
    2. Fall back to fuzzy matching against filenames

    Args:
        template_name: The template name from the mapping
        yaml_folder: Folder containing YAML files
        templates_to_yaml: Dict mapping template name to YAML filename

    Returns:
        List of tuples (filename, path) for matching files
    """
    if not os.path.exists(yaml_folder):
        return []

    matches = []

    # Step 1: Try direct lookup in templates_to_yaml mapping
    if templates_to_yaml:
        # Try exact match
        if template_name in templates_to_yaml:
            yaml_file = templates_to_yaml[template_name]
            yaml_path = os.path.join(yaml_folder, yaml_file)
            if os.path.exists(yaml_path):
                matches.append((yaml_file.replace(".yaml", ""), yaml_path))
                return matches

        # Try normalized match
        template_normalized = re.sub(r'[^a-z0-9]', '', template_name.lower())
        for key, yaml_file in templates_to_yaml.items():
            key_normalized = re.sub(r'[^a-z0-9]', '', key.lower())
            if template_normalized in key_normalized or key_normalized in template_normalized:
                yaml_path = os.path.join(yaml_folder, yaml_file)
                if os.path.exists(yaml_path):
                    matches.append((yaml_file.replace(".yaml", ""), yaml_path))
                    return matches

    # Step 2: Fall back to fuzzy matching against YAML filenames
    template_normalized = re.sub(r'[^a-z0-9]', '', template_name.lower())

    for filename in os.listdir(yaml_folder):
        if filename.endswith(".yaml"):
            # Normalize filename for matching
            filename_normalized = re.sub(r'[^a-z0-9]', '', filename.lower().replace(".yaml", ""))
            # Check if template name is contained in filename or vice versa
            if template_normalized in filename_normalized or filename_normalized in template_normalized:
                matches.append((filename.replace(".yaml", ""), os.path.join(yaml_folder, filename)))

    return matches


def get_common_styles() -> str:
    """Return common CSS styles used across all pages."""
    return """
        * {
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        a {
            color: #2b6cb0;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .nav {
            background: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .nav a {
            margin-right: 20px;
            font-weight: 500;
        }
        .nav a.active {
            color: #1a365d;
            border-bottom: 2px solid #1a365d;
            padding-bottom: 2px;
        }
        .report-header {
            background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .report-header h1 {
            margin: 0 0 10px 0;
            font-size: 28px;
        }
        .report-header .meta {
            opacity: 0.9;
            font-size: 14px;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h3 {
            margin: 0 0 10px 0;
            font-size: 13px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .card .value {
            font-size: 28px;
            font-weight: bold;
            color: #1a365d;
        }
        .card.compliant .value {
            color: #22543d;
        }
        .card.non-compliant .value {
            color: #c53030;
        }
        .compliance-bar {
            height: 8px;
            background: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .compliance-bar .fill {
            height: 100%;
            background: linear-gradient(90deg, #48bb78 0%, #38a169 100%);
            border-radius: 4px;
        }
        .section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            margin: 0 0 20px 0;
            color: #1a365d;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        tr:hover {
            background: #f7fafc;
        }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge.compliant {
            background: #c6f6d5;
            color: #22543d;
        }
        .badge.non-compliant {
            background: #fed7d7;
            color: #c53030;
        }
        .badge.not-applicable {
            background: #e2e8f0;
            color: #718096;
        }
        .badge.warning {
            background: #fef3c7;
            color: #92400e;
        }
        .badge.missing {
            background: #feebc8;
            color: #c05621;
        }
        .count-compliant {
            color: #22543d;
            font-weight: 600;
        }
        .count-non-compliant {
            color: #c53030;
            font-weight: 600;
        }
        .control-set {
            margin-bottom: 30px;
        }
        .control-set-header {
            background: #edf2f7;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 15px;
        }
        .control-set-header h3 {
            margin: 0;
            font-size: 16px;
            color: #2d3748;
        }
        .control-set-header .stats {
            font-size: 14px;
            color: #718096;
            margin-top: 5px;
        }
        .mono {
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 13px;
        }
        .config-block {
            background: #1a202c;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 12px;
            line-height: 1.5;
            max-height: 400px;
            overflow-y: auto;
        }
        .config-block pre {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .resource-entry {
            margin-bottom: 30px;
            padding-bottom: 30px;
            border-bottom: 1px solid #e2e8f0;
        }
        .resource-entry:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        .resource-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }
        .resource-title {
            font-size: 16px;
            font-weight: 600;
            color: #2d3748;
        }
        .resource-type {
            font-size: 13px;
            color: #718096;
            margin-top: 4px;
        }
        .resource-meta {
            font-size: 13px;
            color: #718096;
            margin-bottom: 15px;
        }
        .resource-meta span {
            margin-right: 20px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #718096;
            font-size: 13px;
        }
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .nav {
                display: none;
            }
            .report-header {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }
    """


def generate_navigation(active_page: str, prefix: str, template_mode: bool = False) -> str:
    """Generate navigation bar HTML."""
    pages = [
        ("summary", "Summary Report"),
        ("evidence", "Evidence Sources"),
    ]
    # Only include Resources page if not in template mode
    if not template_mode:
        pages.append(("resources", "Resources"))
    # Always include Control Catalog
    pages.append(("control_catalog", "Control Catalog"))

    nav_items = []
    for page_id, page_name in pages:
        active_class = " active" if page_id == active_page else ""
        nav_items.append(f'<a href="{prefix}_{page_id}.html" class="{active_class}">{page_name}</a>')

    return f"""
    <nav class="nav">
        {" ".join(nav_items)}
    </nav>
    """


def generate_page_header(framework_name: str, conformance_pack: str, generated_at: str,
                         security_standard: str = None, conformance_template: str = None,
                         show_mappings: bool = False) -> str:
    """Generate the common page header.

    Args:
        framework_name: Name of the framework
        conformance_pack: Name of the deployed conformance pack (or 'none' if template mode)
        generated_at: Report generation timestamp
        security_standard: Mapped security standard from Frameworks.xlsx
        conformance_template: Mapped conformance template from Frameworks.xlsx
        show_mappings: If True, show all mapping fields (for summary page)
    """
    if show_mappings:
        template_display = escape_html(conformance_template) if conformance_template else "None"
        security_display = escape_html(security_standard) if security_standard else "None"

        # Build meta fields list
        meta_fields = [f"<div>Conformance Pack Template: {template_display}</div>"]

        if security_standard:
            meta_fields.append(f"<div>Security Standard: {security_display}</div>")

        # Only show deployed pack if one is actually deployed (not 'none' or template mode)
        if conformance_pack and conformance_pack.lower() != "none" and not conformance_pack.startswith("Template:") and conformance_pack != "No Template Available":
            meta_fields.append(f"<div>Deployed Conformance Pack: {escape_html(conformance_pack)}</div>")

        meta_fields.append(f"<div>Generated: {escape_html(generated_at)}</div>")

        return f"""
    <div class="report-header">
        <h1>{escape_html(framework_name)}</h1>
        <div class="meta">
            {"".join(meta_fields)}
        </div>
    </div>
    """
    else:
        # For non-summary pages, show template name if available, otherwise deployed pack
        pack_display = conformance_template if conformance_template else conformance_pack
        return f"""
    <div class="report-header">
        <h1>{escape_html(framework_name)}</h1>
        <div class="meta">
            <div>Conformance Pack Template: {escape_html(pack_display)}</div>
            <div>Generated: {escape_html(generated_at)}</div>
        </div>
    </div>
    """


def build_evidence_source_data(compliance_report: dict) -> dict:
    """
    Build a dictionary of evidence sources with their resources.

    Returns:
        Dict mapping config rule name (or keywordValue for Security Hub) to evidence source data
    """
    evidence_sources = {}

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") not in ["AWS_Config", "AWS_Security_Hub"]:
                    continue

                original_config_rule = source.get("configRuleName")
                rule_name = original_config_rule
                # For Security Hub sources, use keywordValue (control ID) as fallback key
                if not rule_name:
                    if source.get("sourceType") == "AWS_Security_Hub":
                        rule_name = source.get("keywordValue")
                    if not rule_name:
                        continue

                if rule_name not in evidence_sources:
                    evidence_sources[rule_name] = {
                        "configRuleName": original_config_rule,  # Store original, may be None
                        "sourceName": source.get("sourceName"),
                        "sourceDescription": source.get("sourceDescription"),
                        "sourceType": source.get("sourceType"),
                        "keywordValue": source.get("keywordValue"),
                        "inConformancePack": source.get("inConformancePack", False),
                        "resources": {},
                        "complianceSummary": {
                            "compliant": 0,
                            "nonCompliant": 0,
                            "notApplicable": 0
                        }
                    }

                # Add resources (deduplicated by resourceKey)
                for result in source.get("evaluationResults", []):
                    resource_key = result.get("resourceKey")
                    if resource_key and resource_key not in evidence_sources[rule_name]["resources"]:
                        evidence_sources[rule_name]["resources"][resource_key] = {
                            "resourceKey": resource_key,
                            "resourceType": result.get("resourceType"),
                            "resourceId": result.get("resourceId"),
                            "complianceType": result.get("complianceType"),
                            "annotation": result.get("annotation"),
                            "resultRecordedTime": result.get("resultRecordedTime")
                        }

                        # Update counts
                        compliance_type = result.get("complianceType", "")
                        if compliance_type == "COMPLIANT":
                            evidence_sources[rule_name]["complianceSummary"]["compliant"] += 1
                        elif compliance_type == "NON_COMPLIANT":
                            evidence_sources[rule_name]["complianceSummary"]["nonCompliant"] += 1
                        else:
                            evidence_sources[rule_name]["complianceSummary"]["notApplicable"] += 1

    return evidence_sources


def count_mapped_rules(compliance_report: dict) -> int:
    """
    Count unique Config rules referenced in framework that are deployed in conformance pack.

    Returns count of unique rules by keyword value.
    """
    mapped_keywords = set()

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") in ["AWS_Config", "AWS_Security_Hub"] and source.get("inConformancePack", False):
                    keyword = source.get("keywordValue")
                    if keyword:
                        mapped_keywords.add(keyword)

    return len(mapped_keywords)


def count_unmapped_rules(compliance_report: dict) -> int:
    """
    Count unique Config rules referenced in framework but not in conformance pack.

    Returns count of unique rules by keyword value.
    """
    unmapped_keywords = set()

    for control_set in compliance_report.get("controlSets", []):
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") in ["AWS_Config", "AWS_Security_Hub"] and not source.get("inConformancePack", False):
                    keyword = source.get("keywordValue")
                    if keyword:
                        unmapped_keywords.add(keyword)

    return len(unmapped_keywords)


def generate_summary_page(
    compliance_report: dict,
    evidence_sources: dict,
    prefix: str,
    gap_report_link: str = None,
    extra_rules_report_link: str = None,
    matching_templates: list = None,
    template_mode: bool = False,
    security_standard: str = None,
    conformance_template: str = None,
    template_total_rules: int = None,
    security_hub_data: dict = None,
    template_standard_intersection: dict = None,
    security_hub_normalized_ids: set = None,
    template_identifiers: set = None,
    control_catalog_ids: set = None,
    security_hub_mappings: dict = None
) -> str:
    """Generate the summary report HTML page.

    Args:
        compliance_report: The compliance report data
        evidence_sources: Dict of evidence sources
        prefix: URL prefix for links
        gap_report_link: Link to gap report
        extra_rules_report_link: Link to extra rules report
        matching_templates: List of matching template tuples
        template_mode: Whether running in template-only mode
        security_standard: Name of the mapped security standard
        conformance_template: Name of the mapped conformance template
        template_total_rules: Total rules in the conformance pack template
        security_hub_data: Dict with 'total_controls', 'control_ids' from Security Hub standard
        template_standard_intersection: Dict with intersection stats between template and standard
        security_hub_normalized_ids: Set of normalized identifiers from Security Hub standard
        template_identifiers: Set of rule identifiers from conformance pack template (for Venn diagram)
        control_catalog_ids: Set of control identifiers from AWS Control Catalog
    """

    summary = compliance_report.get("summary", {})
    framework_name = compliance_report.get("frameworkName", "Unknown Framework")
    conformance_pack = compliance_report.get("conformancePackName", "Unknown")
    generated_at = compliance_report.get("reportGeneratedAt", "")

    # Count mapped and unmapped rules for the summary cards
    mapped_rules_count = count_mapped_rules(compliance_report)
    unmapped_rules_count = count_unmapped_rules(compliance_report)
    total_config_rules = mapped_rules_count + unmapped_rules_count

    # Count extra rules in conformance pack not in framework
    extra_rules_count = len(compliance_report.get("conformancePackRulesNotInFramework", []))

    # Total rules in conformance pack = mapped rules + extra rules
    rules_in_pack_count = mapped_rules_count + extra_rules_count

    # Calculate compliance percentage
    total_evaluated = (
        summary.get("compliantResources", 0) +
        summary.get("nonCompliantResources", 0)
    )
    compliance_pct = 0
    if total_evaluated > 0:
        compliance_pct = (summary.get("compliantResources", 0) / total_evaluated) * 100

    html_parts = []

    # HTML Header
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Summary - {escape_html(framework_name)}</title>
    <style>
        {get_common_styles()}
    </style>
</head>
<body>
    {generate_navigation("summary", prefix, template_mode)}
    {generate_page_header(framework_name, conformance_pack, generated_at, security_standard, conformance_template, show_mappings=True)}
""")

    # Check if no template was available
    no_template_available = compliance_report.get("noTemplateAvailable", False)

    # Summary Cards - different layout for template mode
    if template_mode:
        if no_template_available:
            html_parts.append(f"""
    <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
        <strong style="color: #b45309;">No Conformance Pack Template Available</strong>
        <p style="color: #92400e; margin: 5px 0 0 0; font-size: 14px;">
            There is no conformance pack template associated with the <strong>{escape_html(framework_name)}</strong> framework.
            This report shows the Config rules referenced in the framework. Use the Control Catalog report to see detailed
            information about each rule. To deploy a conformance pack, you will need to create a custom template or use
            a related framework's template.
        </p>
    </div>
    <div class="summary-cards">
        <div class="card">
            <h3>Control Sets</h3>
            <div class="value">{summary.get('totalControlSets', 0)}</div>
        </div>
        <div class="card">
            <h3>Framework Controls</h3>
            <div class="value">{summary.get('totalControls', 0)}</div>
        </div>
    </div>
""")
        else:
            html_parts.append(f"""
    <div style="background: #f0f9ff; border: 1px solid #0ea5e9; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
        <strong style="color: #0369a1;">Template Analysis Mode</strong>
        <p style="color: #0369a1; margin: 5px 0 0 0; font-size: 14px;">
            This report analyzes the framework against a conformance pack template. No deployed conformance pack was evaluated,
            so resource compliance data is not available. Deploy the conformance pack to see actual compliance results.
        </p>
    </div>
    <div class="summary-cards">
        <div class="card">
            <h3>Control Sets</h3>
            <div class="value">{summary.get('totalControlSets', 0)}</div>
        </div>
        <div class="card">
            <h3>Framework Controls</h3>
            <div class="value">{summary.get('totalControls', 0)}</div>
        </div>
    </div>
""")
    else:
        html_parts.append(f"""
    <div class="summary-cards">
        <div class="card">
            <h3>Control Sets</h3>
            <div class="value">{summary.get('totalControlSets', 0)}</div>
        </div>
        <div class="card">
            <h3>Framework Controls</h3>
            <div class="value">{summary.get('totalControls', 0)}</div>
        </div>
        <div class="card compliant">
            <h3>Compliant Resources</h3>
            <div class="value">{summary.get('compliantResources', 0):,}</div>
        </div>
        <div class="card non-compliant">
            <h3>Non-Compliant Resources</h3>
            <div class="value">{summary.get('nonCompliantResources', 0):,}</div>
        </div>
        <div class="card">
            <h3>Compliance Rate</h3>
            <div class="value">{compliance_pct:.1f}%</div>
            <div class="compliance-bar">
                <div class="fill" style="width: {compliance_pct}%"></div>
            </div>
        </div>
    </div>
""")

    # Calculate Security Hub counts
    sh_total = "N/A"
    sh_mapped = "N/A"
    sh_missing = "N/A"
    if security_hub_data and security_hub_normalized_ids:
        sh_total = security_hub_data.get("total_controls", len(security_hub_normalized_ids))
        # Mapped = framework rules that match Security Hub standard (using normalized identifiers)
        sh_mapped = count_framework_rules_in_standard(compliance_report, security_hub_normalized_ids)
        # Missing = standard controls not covered by framework rules
        # This is total standard controls minus the number of unique normalized identifiers in framework
        sh_missing = len(security_hub_normalized_ids) - sh_mapped
        if sh_missing < 0:
            sh_missing = 0
    elif not security_standard or security_standard == "None":
        pass  # Keep N/A values

    # Calculate template counts
    tpl_total = "N/A"
    tpl_mapped = mapped_rules_count if conformance_template else "N/A"
    tpl_missing = extra_rules_count if conformance_template else "N/A"
    if template_total_rules is not None:
        tpl_total = template_total_rules
    elif conformance_template and not no_template_available:
        tpl_total = rules_in_pack_count  # fallback to calculated count

    # Config Rules Coverage Description
    html_parts.append("""
    <div class="section" style="padding: 15px 20px; margin-bottom: 20px;">
        <p style="color: #4a5568; font-size: 14px; margin: 0; line-height: 1.6;">
            <strong>Config Rules Coverage:</strong> The cards below show the overlap between Config rules in the
            Audit Manager framework, the Conformance Pack template, and the Security Hub standard.
            "Intersection" shows framework rules that appear in the template or standard.
            "Not Covered" shows framework rules that do not appear in either the template or standard.
        </p>
    </div>
""")

    # Calculate rules not covered by either template or standard
    # Use proper set-based calculation to avoid double-counting
    has_template = bool(conformance_template) and not no_template_available
    if has_template or security_hub_normalized_ids:
        not_covered = count_framework_rules_not_covered(compliance_report, security_hub_normalized_ids, has_template)
        not_covered_display = not_covered
    else:
        not_covered_display = "N/A"

    # Row 1: Framework Rules
    html_parts.append(f"""
    <div class="summary-cards">
        <div class="card">
            <h3>Config Rules in Framework</h3>
            <div class="value">{total_config_rules}</div>
        </div>
        <div class="card">
            <h3>Intersection with Template</h3>
            <div class="value">{mapped_rules_count if conformance_template else "N/A"}</div>
        </div>
        <div class="card">
            <h3>Intersection with Standard</h3>
            <div class="value">{sh_mapped}</div>
        </div>
        <div class="card">
            <h3>Not Covered</h3>
            <div class="value">{not_covered_display}</div>
        </div>
    </div>
""")


    # Build manifest URL parameters (used by both Venn diagram and Rules Manifest link)
    # Use the actual YAML filename for template (not the Excel display name) to ensure matching
    manifest_params = []
    if framework_name:
        manifest_params.append(f"framework={quote(framework_name, safe='')}")
    if security_standard:
        manifest_params.append(f"standard={quote(security_standard, safe='')}")
    # Use actual YAML template name from matching_templates for URL matching
    actual_template_name = matching_templates[0][0] if matching_templates else None
    if actual_template_name and not no_template_available:
        manifest_params.append(f"template={quote(actual_template_name, safe='')}")

    manifest_base_url = "../../rule-manifest/rule_manifest.html"
    if manifest_params:
        manifest_base_url += "?" + "&".join(manifest_params)

    # Rules Manifest Link
    html_parts.append(f"""
    <div class="section" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px;">
        <h3 style="margin: 0 0 10px 0; color: white;">Rules Manifest</h3>
        <p style="margin: 0 0 15px 0; opacity: 0.9; font-size: 14px;">
            View the complete inventory of all Config rules, filtered to show rules referenced by this framework,
            its associated security standard, or conformance pack template.
        </p>
        <a href="{manifest_base_url}" style="display: inline-block; background: white; color: #667eea; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600;">
            Open Rules Manifest
        </a>
    </div>
""")

    # Venn Diagram - show if we have at least template or standard data
    has_template_data = bool(conformance_template) and not no_template_available
    has_standard_data = bool(security_hub_normalized_ids)

    if has_template_data or has_standard_data:
        venn_data = calculate_venn_diagram_data(
            compliance_report,
            security_hub_normalized_ids,
            template_identifiers,
            has_template_data,
            security_hub_mappings
        )
        venn_svg = generate_venn_diagram_svg(venn_data, manifest_base_url)

        html_parts.append(f"""
    <div class="section" style="text-align: center;">
        <h3 style="margin-bottom: 10px;">Config Rules Coverage Venn Diagram</h3>
        <p style="color: #718096; font-size: 13px; margin-bottom: 20px;">
            Visualization of rule overlap between Framework, Template, and Security Standard.
            Numbers show unique rules in each region. Click a number to view those rules in the manifest.
        </p>
        {venn_svg}
    </div>
""")

    # Conformance Pack Template Cross-Check
    if matching_templates:
        templates_html = ""
        for item in matching_templates:
            if len(item) == 3:
                template_name, rule_count, yaml_path = item
                templates_html += f'<li><a href="{escape_html(yaml_path)}"><strong>{escape_html(template_name)}</strong></a> — {rule_count} Config Rules</li>\n'
            else:
                template_name, rule_count = item
                templates_html += f"<li><strong>{escape_html(template_name)}</strong> — {rule_count} Config Rules</li>\n"

        html_parts.append(f"""
    <div class="section">
        <h3>Conformance Pack Template Cross-Check</h3>
        <p style="color: #718096; font-size: 14px; margin-bottom: 15px;">
            <em>Note: The AWS Config API does not indicate which template was used when a conformance pack was deployed.
            The following templates are associated with this framework and may have been used:</em>
        </p>
        <ul style="margin: 0; padding-left: 20px;">
            {templates_html}
        </ul>
        <div style="margin-top: 15px; padding: 12px; background: #f7fafc; border-radius: 6px; border-left: 3px solid #4299e1;">
            <p style="color: #4a5568; font-size: 13px; margin: 0 0 8px 0;"><strong>Understanding the "In Template" column:</strong></p>
            <ul style="color: #4a5568; font-size: 13px; margin: 0; padding-left: 20px;">
                <li><span class="badge compliant" style="font-size: 11px;">Yes</span> — Rule is in the conformance pack template</li>
                <li><span class="badge warning" style="font-size: 11px;">No</span> — Rule is not in the conformance pack template (check Gap Report for details)</li>
                <li><span class="badge not-applicable" style="font-size: 11px;">-</span> — No Config rule referenced for this control</li>
            </ul>
        </div>
    </div>
""")

    # Framework Controls by Control Set
    html_parts.append("""
    <div class="section">
        <h2>Framework Controls by Control Set</h2>
""")

    for control_set in compliance_report.get("controlSets", []):
        cs_name = escape_html(control_set.get("controlSetName", ""))
        cs_summary = control_set.get("summary", {})
        num_controls = cs_summary.get("totalControls", 0)

        # Count unique config rules in this control set
        all_config_rules = set()
        for control in control_set.get("controls", []):
            for source in control.get("evidenceSources", []):
                if source.get("sourceType") in ["AWS_Config", "AWS_Security_Hub"]:
                    keyword = source.get("keywordValue") or source.get("configRuleName")
                    if keyword:
                        all_config_rules.add(keyword)

        num_config_rules = len(all_config_rules)

        # Different table layout for template mode vs normal mode
        if template_mode:
            html_parts.append(f"""
        <div class="control-set">
            <div class="control-set-header">
                <h3>{cs_name}</h3>
                <div class="stats">
                    {num_controls} Framework Controls mapped to {num_config_rules} Config Rules
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 30%">Framework Control</th>
                        <th style="width: 34%">Evidence Source (Config Rule)</th>
                        <th style="width: 12%; text-align: center;">In Standard</th>
                        <th style="width: 12%; text-align: center;">In Template</th>
                        <th style="width: 12%; text-align: center;">In Catalog</th>
                    </tr>
                </thead>
                <tbody>
""")
        else:
            html_parts.append(f"""
        <div class="control-set">
            <div class="control-set-header">
                <h3>{cs_name}</h3>
                <div class="stats">
                    {num_controls} Framework Controls mapped to {num_config_rules} Config Rules
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%">Framework Control</th>
                        <th style="width: 27%">Evidence Source (Config Rule)</th>
                        <th style="width: 10%; text-align: center;">In Standard</th>
                        <th style="width: 10%; text-align: center;">In Catalog</th>
                        <th style="width: 9%; text-align: center;">Compliant</th>
                        <th style="width: 9%; text-align: center;">Non-Compliant</th>
                        <th style="width: 10%; text-align: center;">Status</th>
                    </tr>
                </thead>
                <tbody>
""")

        for control in control_set.get("controls", []):
            ctrl_name = escape_html(control.get("controlName", ""))
            sources = control.get("evidenceSources", [])

            # Get all AWS_Config and AWS_Security_Hub sources
            all_config_sources = [s for s in sources if s.get("sourceType") in ["AWS_Config", "AWS_Security_Hub"]]

            # Separate into mapped (in pack or Security Hub) and missing (Config rules not in pack)
            # Security Hub sources are always "mapped" since they link to evidence page
            mapped_sources = [s for s in all_config_sources if s.get("inConformancePack") or s.get("sourceType") == "AWS_Security_Hub"]
            missing_sources = [s for s in all_config_sources if not s.get("inConformancePack") and s.get("sourceType") != "AWS_Security_Hub"]

            if not all_config_sources:
                # Show control with no Config rule references
                if template_mode:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_name}</td>
                        <td style="color: #718096; font-style: italic;">No Config rules referenced</td>
                        <td style="text-align: center;"><span class="badge not-applicable">-</span></td>
                        <td style="text-align: center;"><span class="badge not-applicable">-</span></td>
                        <td style="text-align: center;"><span class="badge not-applicable">-</span></td>
                    </tr>
""")
                else:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_name}</td>
                        <td style="color: #718096; font-style: italic;">No Config rules referenced</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;"><span class="badge not-applicable">N/A</span></td>
                    </tr>
""")
                continue

            # First source row includes control name
            first = True

            # Show mapped sources first (in template/pack)
            for source in mapped_sources:
                # Use sourceName, fall back to keywordValue or configRuleName
                source_name_raw = source.get("sourceName") or source.get("keywordValue") or source.get("configRuleName") or ""
                source_name = escape_html(source_name_raw)
                # For Security Hub sources, use keywordValue as anchor if configRuleName is not set
                rule_name = source.get("configRuleName") or ""
                if not rule_name and source.get("sourceType") == "AWS_Security_Hub":
                    rule_name = source.get("keywordValue", "")
                rule_anchor = make_anchor_id(rule_name)

                ctrl_cell = ctrl_name if first else ""
                first = False

                # Check if this rule is in the Security Hub standard
                # Either: sourceType is AWS_Security_Hub, OR keywordValue matches a normalized Security Hub identifier
                is_security_hub = source.get("sourceType") == "AWS_Security_Hub"
                keyword_value = source.get("keywordValue", "")
                is_in_standard = is_security_hub or (security_hub_normalized_ids and keyword_value.upper() in security_hub_normalized_ids)
                in_standard_badge = '<span class="badge compliant">Yes</span>' if is_in_standard else '<span class="badge warning">No</span>'
                # In Template badge - only Yes if actually in conformance pack (not for Security Hub sources)
                in_template_badge = '<span class="badge compliant">Yes</span>' if source.get("inConformancePack") else '<span class="badge warning">No</span>'
                # In Catalog badge - check if rule identifier is in AWS Control Catalog
                is_in_catalog = control_catalog_ids and keyword_value.upper() in control_catalog_ids
                in_catalog_badge = '<span class="badge compliant">Yes</span>' if is_in_catalog else '<span class="badge warning">No</span>'

                # Link to Rules Manifest using the rule identifier as anchor
                manifest_link = f"../../rule-manifest/rule_manifest.html#{keyword_value.upper()}"

                if template_mode:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td><a href="{manifest_link}">{source_name}</a></td>
                        <td style="text-align: center;">{in_standard_badge}</td>
                        <td style="text-align: center;">{in_template_badge}</td>
                        <td style="text-align: center;">{in_catalog_badge}</td>
                    </tr>
""")
                else:
                    comp_summary = source.get("complianceSummary", {})
                    compliant_count = comp_summary.get("compliant", 0)
                    non_compliant_count = comp_summary.get("nonCompliant", 0)

                    # Determine status badge
                    if non_compliant_count > 0:
                        status_badge = '<span class="badge non-compliant">Issues</span>'
                    elif compliant_count > 0:
                        status_badge = '<span class="badge compliant">Compliant</span>'
                    else:
                        status_badge = '<span class="badge not-applicable">N/A</span>'

                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td><a href="{manifest_link}">{source_name}</a></td>
                        <td style="text-align: center;">{in_standard_badge}</td>
                        <td style="text-align: center;">{in_catalog_badge}</td>
                        <td style="text-align: center;" class="count-compliant">{compliant_count}</td>
                        <td style="text-align: center;" class="count-non-compliant">{non_compliant_count}</td>
                        <td style="text-align: center;">{status_badge}</td>
                    </tr>
""")

            # Show missing sources (not in template/pack)
            for source in missing_sources:
                source_name_raw = source.get("sourceName") or source.get("keywordValue") or ""
                source_name = escape_html(source_name_raw)
                keyword = source.get("keywordValue", "")
                keyword_anchor = make_anchor_id(keyword)

                ctrl_cell = ctrl_name if first else ""
                first = False

                # Check if this rule is in the Security Hub standard
                # Either: sourceType is AWS_Security_Hub, OR keywordValue matches a normalized Security Hub identifier
                is_security_hub = source.get("sourceType") == "AWS_Security_Hub"
                is_in_standard = is_security_hub or (security_hub_normalized_ids and keyword.upper() in security_hub_normalized_ids)
                in_standard_badge = '<span class="badge compliant">Yes</span>' if is_in_standard else '<span class="badge warning">No</span>'
                # In Template badge - missing sources are by definition not in template
                in_template_badge = '<span class="badge warning">No</span>'
                # In Catalog badge
                is_in_catalog = control_catalog_ids and keyword.upper() in control_catalog_ids
                in_catalog_badge = '<span class="badge compliant">Yes</span>' if is_in_catalog else '<span class="badge warning">No</span>'

                # Link to Rules Manifest
                manifest_link = f"../../rule-manifest/rule_manifest.html#{keyword.upper()}"
                source_display = f'<a href="{manifest_link}">{source_name}</a>'

                # Determine status badge based on template availability
                if gap_report_link and not no_template_available:
                    status_badge = f'<a href="{gap_report_link}#{keyword_anchor}"><span class="badge missing">Gap</span></a>'
                elif no_template_available:
                    status_badge = '<span class="badge not-applicable">N/A</span>'
                else:
                    status_badge = '<span class="badge missing">Gap</span>'

                if template_mode:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td>{source_display}</td>
                        <td style="text-align: center;">{in_standard_badge}</td>
                        <td style="text-align: center;">{in_template_badge}</td>
                        <td style="text-align: center;">{in_catalog_badge}</td>
                    </tr>
""")
                else:
                    html_parts.append(f"""
                    <tr>
                        <td>{ctrl_cell}</td>
                        <td>{source_display}</td>
                        <td style="text-align: center;">{in_standard_badge}</td>
                        <td style="text-align: center;">{in_catalog_badge}</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">-</td>
                        <td style="text-align: center;">{status_badge}</td>
                    </tr>
""")

        html_parts.append("""
                </tbody>
            </table>
        </div>
""")

    html_parts.append("""
    </div>

    <div class="footer">
        Generated by AWS Compliance Reporting Workflow
    </div>
</body>
</html>
""")

    return "".join(html_parts)


def generate_evidence_page(
    compliance_report: dict,
    evidence_sources: dict,
    prefix: str,
    control_catalog_link: str = None,
    template_mode: bool = False
) -> str:
    """Generate the evidence sources HTML page."""

    framework_name = compliance_report.get("frameworkName", "Unknown Framework")
    conformance_pack = compliance_report.get("conformancePackName", "Unknown")
    generated_at = compliance_report.get("reportGeneratedAt", "")

    html_parts = []

    # HTML Header
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Evidence Sources - {escape_html(framework_name)}</title>
    <style>
        {get_common_styles()}
        .evidence-entry {{
            margin-bottom: 30px;
            padding-bottom: 30px;
            border-bottom: 1px solid #e2e8f0;
        }}
        .evidence-entry:last-child {{
            border-bottom: none;
        }}
        .evidence-header {{
            margin-bottom: 15px;
        }}
        .evidence-title {{
            font-size: 18px;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 5px;
        }}
        .evidence-rule {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 13px;
            color: #718096;
        }}
        .evidence-stats {{
            display: flex;
            gap: 20px;
            margin: 15px 0;
        }}
        .evidence-stat {{
            padding: 10px 15px;
            background: #f7fafc;
            border-radius: 6px;
        }}
        .evidence-stat .label {{
            font-size: 12px;
            color: #718096;
            text-transform: uppercase;
        }}
        .evidence-stat .value {{
            font-size: 20px;
            font-weight: 600;
        }}
        .evidence-stat.compliant .value {{
            color: #22543d;
        }}
        .evidence-stat.non-compliant .value {{
            color: #c53030;
        }}
    </style>
</head>
<body>
    {generate_navigation("evidence", prefix, template_mode)}
    {generate_page_header(framework_name, conformance_pack, generated_at)}

    <div class="section">
        <h2>Evidence Sources (AWS Config Rules)</h2>
        <p style="color: #718096; margin-bottom: 20px;">
            {f"{len(evidence_sources)} Config rules mapped from the conformance pack template. This is a template analysis - no deployed conformance pack evaluations are available." if template_mode else f"{len(evidence_sources)} Config rules evaluated across the conformance pack. Click on a resource to view its configuration."}
        </p>
""")

    # Sort evidence sources by rule name
    for rule_name in sorted(evidence_sources.keys()):
        source = evidence_sources[rule_name]
        rule_anchor = make_anchor_id(rule_name)
        source_name = escape_html(source.get("sourceName", ""))
        source_description = escape_html(source.get("sourceDescription", "") or "")
        keyword = escape_html(source.get("keywordValue", ""))
        comp_summary = source.get("complianceSummary", {})
        compliant_count = comp_summary.get("compliant", 0)
        non_compliant_count = comp_summary.get("nonCompliant", 0)
        not_applicable_count = comp_summary.get("notApplicable", 0)

        # Build description HTML if present
        description_html = ""
        if source_description:
            description_html = f'<p style="color: #4a5568; margin: 10px 0 0 0; font-size: 14px;">{source_description}</p>'

        # Build catalog link for keyword
        keyword_raw = source.get("keywordValue", "")
        source_type = source.get("sourceType", "")
        config_rule_name = source.get("configRuleName", "")

        # For Security Hub sources, derive the catalog identifier from the actual config rule name (not the key)
        # Only create link if we have a proper config rule mapping
        if source_type == "AWS_Security_Hub":
            if config_rule_name and config_rule_name.startswith("securityhub-"):
                # Normalize: securityhub-cloudwatch-alarm-action-check-xxx -> CLOUDWATCH_ALARM_ACTION_CHECK
                catalog_identifier = normalize_config_rule_name(config_rule_name).upper()
                catalog_anchor = make_anchor_id(catalog_identifier)
                keyword_link = f'<a href="{control_catalog_link}#{catalog_anchor}">{keyword}</a>' if control_catalog_link else keyword
            else:
                # No config rule mapping - display without link
                keyword_link = keyword
        else:
            # For AWS_Config sources, use keywordValue directly
            catalog_anchor = make_anchor_id(keyword_raw)
            keyword_link = f'<a href="{control_catalog_link}#{catalog_anchor}">{keyword}</a>' if control_catalog_link and keyword_raw else keyword

        # Build stats section (only show in non-template mode)
        if template_mode:
            stats_html = """
            <div style="background: #f7fafc; border-radius: 6px; padding: 15px; margin: 15px 0; color: #718096; font-style: italic;">
                Template mode: No resource evaluations available. Deploy this conformance pack to see compliance results.
            </div>
"""
        else:
            stats_html = f"""
            <div class="evidence-stats">
                <div class="evidence-stat compliant">
                    <div class="label">Compliant</div>
                    <div class="value">{compliant_count}</div>
                </div>
                <div class="evidence-stat non-compliant">
                    <div class="label">Non-Compliant</div>
                    <div class="value">{non_compliant_count}</div>
                </div>
                <div class="evidence-stat">
                    <div class="label">Not Applicable</div>
                    <div class="value" style="color: #718096;">{not_applicable_count}</div>
                </div>
            </div>
"""

        html_parts.append(f"""
        <div class="evidence-entry" id="{rule_anchor}">
            <div class="evidence-header">
                <div class="evidence-title">{source_name}</div>
                {description_html}
                <div class="evidence-rule" style="margin-top: 10px;">Rule: {escape_html(rule_name)}</div>
                <div class="evidence-rule">Keyword: {keyword_link}</div>
            </div>

            {stats_html}
""")

        # Resource table (only show in non-template mode)
        if not template_mode:
            html_parts.append("""
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%">Resource Type</th>
                        <th style="width: 35%">Resource ID</th>
                        <th style="width: 15%">Status</th>
                        <th style="width: 25%">Annotation</th>
                    </tr>
                </thead>
                <tbody>
""")

            # Sort resources: non-compliant first, then by resource type and ID
            resources = list(source.get("resources", {}).values())
            resources.sort(key=lambda r: (
                0 if r.get("complianceType") == "NON_COMPLIANT" else 1,
                r.get("resourceType", ""),
                r.get("resourceId", "")
            ))

            for resource in resources:
                resource_key = resource.get("resourceKey", "")
                resource_anchor = make_anchor_id(resource_key)
                resource_type = escape_html(resource.get("resourceType", ""))
                resource_id = escape_html(resource.get("resourceId", ""))
                compliance_type = resource.get("complianceType", "")
                annotation = escape_html(resource.get("annotation", "") or "")

                if len(annotation) > 100:
                    annotation = annotation[:100] + "..."

                if compliance_type == "COMPLIANT":
                    badge = '<span class="badge compliant">Compliant</span>'
                elif compliance_type == "NON_COMPLIANT":
                    badge = '<span class="badge non-compliant">Non-Compliant</span>'
                else:
                    badge = '<span class="badge not-applicable">N/A</span>'

                html_parts.append(f"""
                    <tr>
                        <td class="mono">{resource_type}</td>
                        <td class="mono"><a href="{prefix}_resources.html#{resource_anchor}">{resource_id}</a></td>
                        <td>{badge}</td>
                        <td style="font-size: 13px; color: #718096;">{annotation}</td>
                    </tr>
""")

            html_parts.append("""
                </tbody>
            </table>
""")

        html_parts.append("""
        </div>
""")

    html_parts.append("""
    </div>

    <div class="footer">
        Generated by AWS Compliance Reporting Workflow
    </div>
</body>
</html>
""")

    return "".join(html_parts)


def generate_resources_page(
    compliance_report: dict,
    configurations: dict,
    prefix: str
) -> str:
    """Generate the resources HTML page."""

    framework_name = compliance_report.get("frameworkName", "Unknown Framework")
    conformance_pack = compliance_report.get("conformancePackName", "Unknown")
    generated_at = compliance_report.get("reportGeneratedAt", "")

    # Get all configurations - handle both array format (resources) and dict format (configurations)
    if "configurations" in configurations:
        config_entries = configurations.get("configurations", {})
    elif "resources" in configurations:
        # Convert array to dict keyed by resourceKey
        config_entries = {}
        for resource in configurations.get("resources", []):
            resource_type = resource.get("resourceType", "")
            resource_id = resource.get("resourceId", "")
            resource_key = resource.get("resourceKey") or f"{resource_type}|{resource_id}"
            config_entries[resource_key] = {
                "resourceKey": resource_key,
                "resourceType": resource_type,
                "resourceId": resource_id,
                "configurationFound": resource.get("configurationFound", False),
                "configuration": resource.get("configuration")
            }
    else:
        config_entries = {}

    config_summary = configurations.get("summary", {})

    # Calculate stats from actual data if summary is incomplete
    total_resources = config_summary.get('totalResources') or len(config_entries)
    configs_retrieved = config_summary.get('configurationsRetrieved')
    configs_not_found = config_summary.get('configurationsNotFound')

    if configs_retrieved is None or configs_not_found is None:
        configs_retrieved = sum(1 for e in config_entries.values() if e.get("configurationFound"))
        configs_not_found = total_resources - configs_retrieved

    html_parts = []

    # HTML Header
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resources - {escape_html(framework_name)}</title>
    <style>
        {get_common_styles()}
    </style>
</head>
<body>
    {generate_navigation("resources", prefix)}
    {generate_page_header(framework_name, conformance_pack, generated_at)}

    <div class="summary-cards">
        <div class="card">
            <h3>Total Resources</h3>
            <div class="value">{total_resources}</div>
        </div>
        <div class="card compliant">
            <h3>Configs Retrieved</h3>
            <div class="value">{configs_retrieved}</div>
        </div>
        <div class="card">
            <h3>Configs Not Found</h3>
            <div class="value" style="color: #718096;">{configs_not_found}</div>
        </div>
    </div>

    <div class="section">
        <h2>Resource Configurations</h2>
        <p style="color: #718096; margin-bottom: 20px;">
            Configuration items for all evaluated resources.
        </p>
""")

    # Group resources by type
    resources_by_type = defaultdict(list)
    for resource_key, entry in config_entries.items():
        resource_type = entry.get("resourceType", "Unknown")
        resources_by_type[resource_type].append(entry)

    # Sort each group by resource ID
    for resource_type in resources_by_type:
        resources_by_type[resource_type].sort(key=lambda r: r.get("resourceId", ""))

    # Output resources grouped by type
    for resource_type in sorted(resources_by_type.keys()):
        entries = resources_by_type[resource_type]
        type_summary = config_summary.get("resourceTypes", {}).get(resource_type, {})
        total_count = type_summary.get("total") or len(entries)
        # Calculate found_count from actual data
        found_count = type_summary.get("configurationsFound")
        if found_count is None:
            found_count = sum(1 for e in entries if e.get("configurationFound"))

        html_parts.append(f"""
        <div class="control-set">
            <div class="control-set-header">
                <h3>{escape_html(resource_type)}</h3>
                <div class="stats">
                    {total_count} resources | {found_count} configurations found
                </div>
            </div>
""")

        for entry in entries:
            resource_key = entry.get("resourceKey", "")
            resource_anchor = make_anchor_id(resource_key)
            resource_id = escape_html(entry.get("resourceId", ""))
            config_found = entry.get("configurationFound", False)
            config_data = entry.get("configuration", {})

            html_parts.append(f"""
            <div class="resource-entry" id="{resource_anchor}">
                <div class="resource-header">
                    <div>
                        <div class="resource-title">{resource_id}</div>
                        <div class="resource-type">{escape_html(resource_type)}</div>
                    </div>
                    <div>
                        {"<span class='badge compliant'>Config Found</span>" if config_found else "<span class='badge not-applicable'>No Config</span>"}
                    </div>
                </div>
""")

            if config_found and config_data:
                # Show metadata
                arn = escape_html(config_data.get("arn", ""))
                region = escape_html(config_data.get("awsRegion", ""))
                captured = escape_html(config_data.get("configurationItemCaptureTime", ""))

                html_parts.append(f"""
                <div class="resource-meta">
                    <span><strong>ARN:</strong> {arn}</span>
                    <span><strong>Region:</strong> {region}</span>
                    <span><strong>Captured:</strong> {captured}</span>
                </div>
""")

                # Show configuration JSON
                config_json = config_data.get("configuration", {})
                if config_json:
                    formatted_json = json.dumps(config_json, indent=2, default=str)
                    html_parts.append(f"""
                <div class="config-block">
                    <pre>{escape_html(formatted_json)}</pre>
                </div>
""")

                # Show supplementary configuration if present
                supp_config = config_data.get("supplementaryConfiguration", {})
                if supp_config:
                    supp_json = json.dumps(supp_config, indent=2, default=str)
                    html_parts.append(f"""
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; color: #4a5568; font-weight: 500;">Supplementary Configuration</summary>
                    <div class="config-block" style="margin-top: 10px;">
                        <pre>{escape_html(supp_json)}</pre>
                    </div>
                </details>
""")

                # Show tags if present
                tags = config_data.get("tags", {})
                if tags:
                    html_parts.append("""
                <div style="margin-top: 15px;">
                    <strong style="color: #4a5568;">Tags:</strong>
                    <div style="margin-top: 8px;">
""")
                    for tag_key, tag_value in tags.items():
                        html_parts.append(f"""
                        <span style="display: inline-block; background: #edf2f7; padding: 4px 10px; border-radius: 4px; margin: 2px; font-size: 13px;">
                            <strong>{escape_html(tag_key)}:</strong> {escape_html(tag_value)}
                        </span>
""")
                    html_parts.append("""
                    </div>
                </div>
""")

            html_parts.append("""
            </div>
""")

        html_parts.append("""
        </div>
""")

    html_parts.append("""
    </div>

    <div class="footer">
        Generated by AWS Compliance Reporting Workflow
    </div>
</body>
</html>
""")

    return "".join(html_parts)


def main():
    parser = argparse.ArgumentParser(
        description="Generate multi-page HTML compliance report from JSON data"
    )
    parser.add_argument(
        "report_file",
        help="Path to compliance report JSON file (from generate_compliance_report.py)"
    )
    parser.add_argument(
        "configurations_file",
        nargs="?",
        help="Path to resource configurations JSON file (from get_resource_configurations.py)",
        default=None
    )
    parser.add_argument(
        "-o", "--output-prefix",
        help="Output file prefix (default: derived from report filename)",
        default=None
    )
    parser.add_argument(
        "--template-mode",
        action="store_true",
        help="Template mode: generate reports without resource configurations"
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.template_mode and not args.configurations_file:
        parser.error("configurations_file is required unless --template-mode is specified")

    try:
        # Load compliance report
        print(f"Loading compliance report: {args.report_file}")
        compliance_report = load_json_file(args.report_file)

        # Check if this is a template-mode report
        template_mode = args.template_mode or compliance_report.get("templateMode", False)

        # Load configurations (if not template mode)
        if template_mode:
            print("Running in template mode (no resource configurations)")
            configurations = {"configurations": {}}
        else:
            print(f"Loading resource configurations: {args.configurations_file}")
            configurations = load_json_file(args.configurations_file)

        # Determine output prefix
        output_prefix = args.output_prefix
        if not output_prefix:
            base_name = os.path.basename(args.report_file)
            output_prefix = base_name.rsplit(".", 1)[0]

        # Build evidence source data
        print("Building evidence source index...")
        evidence_sources = build_evidence_source_data(compliance_report)
        print(f"  Found {len(evidence_sources)} unique Config rules")

        # Generate pages
        print("Generating HTML pages...")

        # Use basename for HTML links (all files are in same directory)
        link_prefix = os.path.basename(output_prefix)
        gap_report_link = f"{link_prefix}_gaps.html"
        extra_rules_report_link = f"{link_prefix}_extra_rules.html"
        control_catalog_link = f"{link_prefix}_control_catalog.html"

        # Look up conformance pack templates and security standard for this framework using Frameworks.xlsx
        matching_templates = []
        security_standard = None
        conformance_template = None
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(script_dir)
        frameworks_excel = os.path.join(project_dir, "Frameworks.xlsx")
        yaml_folder = os.path.join(project_dir, "conformance-packs", "conformance-pack-yamls")

        if os.path.exists(frameworks_excel):
            framework_name = compliance_report.get("frameworkName", "")
            framework_id = compliance_report.get("frameworkId", "")

            # Look up security standard
            security_standard = lookup_security_standard(frameworks_excel, framework_id)

            # Load framework-to-template mapping from Excel
            name_mapping, id_mapping = load_framework_template_mapping(frameworks_excel)
            conformance_template = find_matching_template(framework_name, name_mapping, id_mapping, framework_id)

            if conformance_template:
                # Find YAML files by scanning the folder
                templates_to_yaml = load_templates_to_yaml_mapping(yaml_folder)
                yaml_files = find_template_yaml_files(conformance_template, yaml_folder, templates_to_yaml)
                for name, path in yaml_files:
                    rule_count = count_config_rules_in_template(path)
                    # Store relative path for the hyperlink
                    rel_path = os.path.relpath(path, os.path.dirname(os.path.abspath(args.report_file)))
                    matching_templates.append((name, rule_count, rel_path))
                    print(f"  Template cross-check: {name} has {rule_count} rules")

        # Calculate template total rules from matching_templates
        template_total_rules = None
        if matching_templates:
            # Use the first (primary) template's rule count
            template_total_rules = matching_templates[0][1]

        # Load Security Hub standard data
        security_hub_data = None
        security_hub_normalized_ids = None
        sh_file = None
        if security_standard:
            sh_file = find_security_hub_standard_file(security_standard, project_dir)
            if sh_file:
                security_hub_data = load_security_hub_standard(sh_file)
                security_hub_normalized_ids = get_security_hub_normalized_identifiers(sh_file)
                if security_hub_data:
                    print(f"  Security Hub standard: {security_hub_data.get('total_controls', 0)} controls")

        # Load Control Catalog identifiers
        control_catalog_ids = load_control_catalog_identifiers(project_dir)
        if control_catalog_ids:
            print(f"  Control Catalog: {len(control_catalog_ids)} detective controls")

        # Load Security Hub control mappings for resolving indirect references
        security_hub_mappings = load_security_standard_mappings(project_dir)
        if security_hub_mappings:
            print(f"  Security Hub control mappings: {len(security_hub_mappings)} controls")

        # Calculate Template ∩ Standard intersection and extract template identifiers
        template_standard_intersection = None
        template_identifiers = None
        template_yaml_path = None

        if matching_templates:
            # Get the first template's YAML path
            for item in matching_templates:
                if len(item) == 3:
                    _, _, rel_path = item
                    # Convert relative path back to absolute
                    template_yaml_path = os.path.join(os.path.dirname(os.path.abspath(args.report_file)), rel_path)
                    break

            if template_yaml_path and os.path.exists(template_yaml_path):
                # Extract template rule identifiers for Venn diagram
                template_identifiers = extract_template_rule_identifiers(template_yaml_path)

                # Calculate intersection with Security Hub standard
                if sh_file:
                    template_standard_intersection = calculate_template_standard_intersection(template_yaml_path, sh_file)
                    if template_standard_intersection:
                        print(f"  Template & Standard intersection: {template_standard_intersection.get('intersection', 0)} rules in common")

        # Summary page
        summary_html = generate_summary_page(
            compliance_report, evidence_sources, link_prefix, gap_report_link,
            extra_rules_report_link, matching_templates, template_mode,
            security_standard, conformance_template, template_total_rules, security_hub_data,
            template_standard_intersection, security_hub_normalized_ids, template_identifiers,
            control_catalog_ids, security_hub_mappings
        )
        summary_file = f"{output_prefix}_summary.html"
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write(summary_html)
        print(f"  Summary page: {summary_file}")

        # Evidence sources page
        evidence_html = generate_evidence_page(compliance_report, evidence_sources, link_prefix, control_catalog_link, template_mode)
        evidence_file = f"{output_prefix}_evidence.html"
        with open(evidence_file, "w", encoding="utf-8") as f:
            f.write(evidence_html)
        print(f"  Evidence sources page: {evidence_file}")

        # Resources page (skip in template mode)
        if template_mode:
            print(f"  Resources page: Skipped (template mode)")
            print(f"\nGenerated 2 HTML files with prefix: {output_prefix}")
        else:
            resources_html = generate_resources_page(compliance_report, configurations, link_prefix)
            resources_file = f"{output_prefix}_resources.html"
            with open(resources_file, "w", encoding="utf-8") as f:
                f.write(resources_html)
            print(f"  Resources page: {resources_file}")
            print(f"\nGenerated 3 HTML files with prefix: {output_prefix}")

        print(f"Open {summary_file} to start browsing the report.")

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
