#!/usr/bin/env python3
"""
Unified workflow script that runs all compliance report scripts in sequence.

This script orchestrates:
1. get_framework_controls.py - Extract controls from Audit Manager framework
2. export_control_catalog.py - Export Config rules from AWS Control Catalog (cached)
3. map_config_rules.py - Map evidence sources to Config rules
4. generate_compliance_report.py - Generate compliance report from conformance pack
5. get_resource_configurations.py - Get configuration items for all resources
6. generate_html_report.py - Generate multi-page HTML reports
7-9. Generate Control Catalog, Gap, and Extra Rules reports

All output files will be written to a folder named for the output-prefix parameter
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


FRAMEWORK_CONTROLS_FOLDER = "framework-controls"
CONTROL_CATALOG_FOLDER = "control-catalog"
CONTROL_CATALOG_FILE = "detective-controls.json"
CONFIG_RULES_CACHE_FILE = "account-config-rules.json"
COMPLIANCE_DASHBOARDS_FOLDER = "compliance-dashboards"
FRAMEWORKS_EXCEL_FILE = "Frameworks.xlsx"
SECURITY_STANDARD_CONTROLS_FOLDER = "security-standard-controls"


def get_python_executable():
    """Get the Python executable path."""
    return sys.executable


def lookup_security_standard(framework_id: str) -> str | None:
    """
    Look up the Security Standard for a framework from Frameworks.xlsx.

    Args:
        framework_id: The AWS Audit Manager framework ID

    Returns:
        The security standard name (e.g., 'aws-foundational-security-best-practices-v100')
        or None if not found or no mapping exists
    """
    try:
        import pandas as pd
    except ImportError:
        print("Warning: pandas not installed, cannot look up Security Standard from Frameworks.xlsx")
        return None

    excel_path = os.path.join(os.path.dirname(__file__), FRAMEWORKS_EXCEL_FILE)
    if not os.path.exists(excel_path):
        print(f"Warning: {FRAMEWORKS_EXCEL_FILE} not found")
        return None

    try:
        df = pd.read_excel(excel_path)
        # Find row matching framework ID
        match = df[df['Framework ID'] == framework_id]
        if match.empty:
            return None
        security_standard = match['Security Standard'].iloc[0]
        # Return None if NaN or empty
        if pd.isna(security_standard) or not security_standard:
            return None
        return str(security_standard).strip()
    except Exception as e:
        print(f"Warning: Error reading {FRAMEWORKS_EXCEL_FILE}: {e}")
        return None


def run_script(script_name: str, args: list, description: str) -> bool:
    """
    Run a Python script with the given arguments.

    Args:
        script_name: Name of the script to run
        args: List of arguments to pass to the script
        description: Description of what the script does

    Returns:
        True if successful, False otherwise
    """
    print(f"\n{'=' * 80}")
    print(f"STEP: {description}")
    print(f"Running: {script_name} {' '.join(args)}")
    print('=' * 80)

    script_path = os.path.join(os.path.dirname(__file__), "utility-scripts", script_name)

    if not os.path.exists(script_path):
        print(f"Error: Script not found: {script_path}", file=sys.stderr)
        return False

    cmd = [get_python_executable(), script_path] + args

    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error: Script failed with return code {e.returncode}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error running script: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Run the complete compliance reporting workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # Run full workflow with PCI DSS framework
  # (uses cached framework controls if available)
  # (Security Hub file auto-detected from Frameworks.xlsx)
  python run_compliance_workflow.py \\
    --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \\
    --conformance-pack PCI-DSS-CPAC \\
    --output-prefix "PCI_DSS_v4"

  # Run template analysis mode (no deployed conformance pack)
  # Security Hub mapping auto-detected from Frameworks.xlsx
  python run_compliance_workflow.py \\
    --framework-id 07938c2d-aa7a-442e-913a-4777b4efddd3 \\
    --conformance-pack none

  # Force re-download of framework controls
  python run_compliance_workflow.py \\
    --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \\
    --conformance-pack PCI-DSS-CPAC \\
    --refresh-framework

  # Run only steps 3-4 using existing files
  python run_compliance_workflow.py \\
    --conformance-pack PCI-DSS-CPAC \\
    --framework-file "PCI_DSS_v4_controls.json" \\
    --mapping-file "PCI_DSS_v4_config_mapping.json" \\
    --skip-extract --skip-map
"""
    )

    parser.add_argument(
        "--framework-id",
        help="AWS Audit Manager framework ID (required unless --skip-extract). Run utility-scripts/list_audit_manager_frameworks.py to generate a list of frameworks with their IDs"
    )
    parser.add_argument(
        "--conformance-pack",
        required=True,
        help="AWS Config conformance pack name, or 'none' for template-only mode. Run list_conformance_packs.py to generate a list of deployed Conformance packs"
    )
    parser.add_argument(
        "--template",
        help="Path to conformance pack YAML template (for template-only mode, auto-detected if not specified)",
        default=None
    )
    parser.add_argument(
        "--output-prefix",
        help="Prefix for output files (default: framework name if available, otherwise conformance pack name)",
        default=None
    )
    parser.add_argument(
        "-r", "--region",
        help="AWS region (uses default region if not specified)",
        default=None
    )

    # Skip options
    parser.add_argument(
        "--skip-extract",
        action="store_true",
        help="Skip framework extraction (requires --framework-file)"
    )
    parser.add_argument(
        "--refresh-framework",
        action="store_true",
        help="Force re-download of framework controls even if cached version exists"
    )
    parser.add_argument(
        "--refresh-rules",
        action="store_true",
        help="Force re-download of Control Catalog and Config rules caches"
    )
    parser.add_argument(
        "--skip-map",
        action="store_true",
        help="Skip config rule mapping (requires --mapping-file)"
    )
    parser.add_argument(
        "--skip-report",
        action="store_true",
        help="Skip compliance report generation"
    )
    parser.add_argument(
        "--skip-configs",
        action="store_true",
        help="Skip resource configuration retrieval"
    )
    parser.add_argument(
        "--skip-html",
        action="store_true",
        help="Skip HTML report generation"
    )

    # Input file overrides
    parser.add_argument(
        "--framework-file",
        help="Use existing framework controls JSON file"
    )
    parser.add_argument(
        "--mapping-file",
        help="Use existing config mapping JSON file"
    )
    parser.add_argument(
        "--report-file",
        help="Use existing compliance report JSON file"
    )
    parser.add_argument(
        "--security-hub-file",
        help="Override Security Hub standard controls JSON file (auto-detected from Frameworks.xlsx if not specified)"
    )

    args = parser.parse_args()

    # Look up Security Hub file from Frameworks.xlsx if not explicitly provided
    if not args.security_hub_file and args.framework_id:
        security_standard = lookup_security_standard(args.framework_id)
        if security_standard:
            security_hub_path = os.path.join(
                os.path.dirname(__file__),
                SECURITY_STANDARD_CONTROLS_FOLDER,
                f"{security_standard}.json"
            )
            if os.path.exists(security_hub_path):
                args.security_hub_file = security_hub_path
                print(f"Auto-detected Security Hub file: {security_hub_path}")
            else:
                print(f"Warning: Security Hub file not found: {security_hub_path}")
                print(f"  Run: python security-standard-controls/get_all_enabled_standard_controls.py")

    # Resolve security-hub-file path if just a name was provided
    if args.security_hub_file and not os.path.exists(args.security_hub_file):
        # Try adding .json extension
        if os.path.exists(args.security_hub_file + ".json"):
            args.security_hub_file = args.security_hub_file + ".json"
        # Try looking in security-standard-controls folder
        elif os.path.exists(os.path.join(SECURITY_STANDARD_CONTROLS_FOLDER, args.security_hub_file)):
            args.security_hub_file = os.path.join(SECURITY_STANDARD_CONTROLS_FOLDER, args.security_hub_file)
        elif os.path.exists(os.path.join(SECURITY_STANDARD_CONTROLS_FOLDER, args.security_hub_file + ".json")):
            args.security_hub_file = os.path.join(SECURITY_STANDARD_CONTROLS_FOLDER, args.security_hub_file + ".json")
        else:
            parser.error(f"Security Hub file not found: {args.security_hub_file}")

    # Check for template-only mode
    template_mode = args.conformance_pack.lower() == "none"

    # Validate arguments
    if not args.skip_extract and not args.framework_id and not args.framework_file:
        parser.error("--framework-id is required unless --skip-extract or --framework-file is specified")

    if args.skip_extract and not args.framework_file:
        parser.error("--framework-file is required when using --skip-extract")

    if args.skip_map and not args.mapping_file:
        parser.error("--mapping-file is required when using --skip-map")

    if not template_mode and args.skip_report and not args.report_file and not args.skip_configs:
        parser.error("--report-file is required when using --skip-report (unless also using --skip-configs)")

    # Create framework-controls folder if needed
    if not os.path.exists(FRAMEWORK_CONTROLS_FOLDER):
        os.makedirs(FRAMEWORK_CONTROLS_FOLDER)
        print(f"Created framework controls folder: {FRAMEWORK_CONTROLS_FOLDER}")

    # Create control-catalog folder if needed
    if not os.path.exists(CONTROL_CATALOG_FOLDER):
        os.makedirs(CONTROL_CATALOG_FOLDER)
        print(f"Created control catalog folder: {CONTROL_CATALOG_FOLDER}")

    # Determine Control Catalog and Config rules cache paths
    cached_catalog_file = os.path.join(CONTROL_CATALOG_FOLDER, CONTROL_CATALOG_FILE)
    cached_config_rules_file = os.path.join(CONTROL_CATALOG_FOLDER, CONFIG_RULES_CACHE_FILE)
    use_cached_catalog = os.path.exists(cached_catalog_file) and not args.refresh_rules
    use_cached_config_rules = os.path.exists(cached_config_rules_file) and not args.refresh_rules

    # Determine framework file path
    # Priority: 1) --framework-file argument, 2) cached file in framework-controls folder
    cached_framework_file = None
    use_cached_framework = False

    if args.framework_id:
        cached_framework_file = os.path.join(FRAMEWORK_CONTROLS_FOLDER, f"{args.framework_id}_controls.json")
        if os.path.exists(cached_framework_file) and not args.refresh_framework:
            use_cached_framework = True

    if args.framework_file:
        framework_file = args.framework_file
    elif use_cached_framework:
        framework_file = cached_framework_file
    elif args.framework_id:
        framework_file = cached_framework_file
    else:
        framework_file = None

    # Build region args early (needed for framework extraction)
    region_args = ["-r", args.region] if args.region else []

    # If framework doesn't exist yet, extract it NOW before determining output_prefix
    # This ensures output_prefix is always based on framework name
    needs_framework_extraction = (
        not args.skip_extract and
        not use_cached_framework and
        framework_file and
        not os.path.exists(framework_file)
    )

    if needs_framework_extraction:
        print("\n" + "=" * 80)
        print("STEP: Extract framework controls from AWS Audit Manager (early)")
        print(f"Running: get_framework_controls.py {args.framework_id} -o {framework_file}")
        print("=" * 80)
        script_path = os.path.join(os.path.dirname(__file__), "utility-scripts", "get_framework_controls.py")
        cmd = [get_python_executable(), script_path, args.framework_id, "-o", framework_file] + region_args
        try:
            result = subprocess.run(cmd, check=True)
            if result.returncode != 0:
                print("Error: Framework extraction failed", file=sys.stderr)
                return 1
        except subprocess.CalledProcessError as e:
            print(f"Error: Framework extraction failed with return code {e.returncode}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error extracting framework: {e}", file=sys.stderr)
            return 1

    # Now determine output prefix - framework file should exist if we extracted it
    if args.output_prefix:
        output_prefix = args.output_prefix
    elif framework_file and os.path.exists(framework_file):
        # Load framework to get its name
        try:
            with open(framework_file, "r", encoding="utf-8") as f:
                fw_data = json.load(f)
            framework_name = fw_data.get("frameworkName", "")
            # Sanitize framework name for use as folder name
            output_prefix = "".join(c if c.isalnum() or c in "._- " else "_" for c in framework_name)
            output_prefix = output_prefix.replace(" ", "_")
            # Truncate to avoid Windows MAX_PATH issues (keep under 50 chars)
            if len(output_prefix) > 50:
                output_prefix = output_prefix[:50].rstrip("_")
        except Exception:
            output_prefix = args.conformance_pack if not template_mode else "template_analysis"
    elif template_mode:
        output_prefix = "template_analysis"
    else:
        output_prefix = args.conformance_pack

    # Create compliance-dashboards folder if needed
    if not os.path.exists(COMPLIANCE_DASHBOARDS_FOLDER):
        os.makedirs(COMPLIANCE_DASHBOARDS_FOLDER)
        print(f"Created compliance dashboards folder: {COMPLIANCE_DASHBOARDS_FOLDER}")

    # Create output folder inside compliance-dashboards
    output_folder = os.path.join(COMPLIANCE_DASHBOARDS_FOLDER, output_prefix)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder: {output_folder}")

    mapping_file = args.mapping_file or os.path.join(output_folder, f"{output_prefix}_config_mapping.json")

    if template_mode:
        report_file = args.report_file or os.path.join(output_folder, f"template_report_{output_prefix}.json")
        configs_file = None  # No configs in template mode
        html_prefix = os.path.join(output_folder, f"template_report_{output_prefix}")
    else:
        report_file = args.report_file or os.path.join(output_folder, f"compliance_report_{args.conformance_pack}.json")
        configs_file = os.path.join(output_folder, f"compliance_report_{args.conformance_pack}_configurations.json")
        html_prefix = os.path.join(output_folder, f"compliance_report_{args.conformance_pack}")
    html_summary = f"{html_prefix}_summary.html"
    html_evidence = f"{html_prefix}_evidence.html"
    html_resources = f"{html_prefix}_resources.html"
    html_gaps = f"{html_prefix}_gaps.html"
    html_extra_rules = f"{html_prefix}_extra_rules.html"
    html_control_catalog = f"{html_prefix}_control_catalog.html"

    print("\n" + "=" * 80)
    print("AWS COMPLIANCE REPORTING WORKFLOW")
    if template_mode:
        print("  (TEMPLATE-ONLY MODE)")
    print("=" * 80)
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    if template_mode:
        print(f"Mode: Template Analysis (no deployed conformance pack)")
    else:
        print(f"Conformance Pack: {args.conformance_pack}")
    if args.framework_id:
        print(f"Framework ID: {args.framework_id}")
    print(f"Output Folder: {output_folder}")
    print()
    print("Output Files:")
    print(f"  Framework Controls: {framework_file}")
    print(f"  Config Mapping: {mapping_file}")
    print(f"  Compliance Report: {report_file}")
    if not template_mode:
        print(f"  Resource Configs: {configs_file}")
    print(f"  Control Catalog: {cached_catalog_file}")
    print(f"  Config Rules Cache: {cached_config_rules_file}")
    if args.security_hub_file:
        print(f"  Security Hub File: {args.security_hub_file}")
    print(f"  HTML Summary: {html_summary}")
    print(f"  HTML Evidence: {html_evidence}")
    if not template_mode:
        print(f"  HTML Resources: {html_resources}")
    print(f"  HTML Control Catalog: {html_control_catalog}")
    print(f"  HTML Gap Report: {html_gaps}")
    print(f"  HTML Extra Rules: {html_extra_rules}")

    success = True

    # Step 1: Extract framework controls (may have been done early for output_prefix)
    if args.skip_extract:
        print(f"\nSkipping Step 1: Using existing framework file: {framework_file}")
    elif use_cached_framework:
        print(f"\nSkipping Step 1: Using cached framework file: {framework_file}")
        print(f"  (use --refresh-framework to force re-download)")
    elif needs_framework_extraction:
        print(f"\nSkipping Step 1: Framework already extracted above")
    else:
        script_args = [args.framework_id, "-o", framework_file] + region_args
        if not run_script(
            "get_framework_controls.py",
            script_args,
            "Extract framework controls from AWS Audit Manager"
        ):
            print("\nWorkflow failed at Step 1: Framework extraction", file=sys.stderr)
            return 1

    # Step 2: Export Control Catalog (needed for descriptions in map_config_rules)
    if use_cached_catalog:
        print(f"\nSkipping Step 2: Using cached Control Catalog: {cached_catalog_file}")
        print(f"  (use --refresh-rules to force re-download)")
    else:
        script_args = ["-o", cached_catalog_file] + region_args
        if not run_script(
            "export_control_catalog.py",
            script_args,
            "Export Config rules from AWS Control Catalog"
        ):
            print("\nWorkflow failed at Step 2: Control Catalog export", file=sys.stderr)
            return 1

    # Step 3: Map Config rules (and cache account's Config rules)
    if not args.skip_map:
        script_args = [framework_file, "-o", mapping_file, "--catalog-file", cached_catalog_file]
        if use_cached_config_rules:
            print(f"\n  Using cached Config rules: {cached_config_rules_file}")
            print(f"  (use --refresh-rules to force re-download)")
            script_args.extend(["--config-rules-file", cached_config_rules_file])
        else:
            script_args.extend(["--save-config-rules", cached_config_rules_file])
        if args.security_hub_file:
            script_args.extend(["--security-hub-file", args.security_hub_file])
        script_args.extend(region_args)
        if not run_script(
            "map_config_rules.py",
            script_args,
            "Map evidence sources to AWS Config rules"
        ):
            print("\nWorkflow failed at Step 3: Config rule mapping", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 3: Using existing mapping file: {mapping_file}")

    # Track if no template was available (for skipping gap/extra reports)
    no_template_available = False

    # Step 4: Generate compliance report
    if not args.skip_report:
        if template_mode:
            # Template mode: Use template-based report generator
            script_args = [framework_file, "-o", report_file]
            if args.template:
                script_args.extend(["--template", args.template])
            # Pass mapping file if it exists (for Security Hub rule name resolution)
            if os.path.exists(mapping_file):
                script_args.extend(["--mapping-file", mapping_file])
            if not run_script(
                "generate_template_compliance_report.py",
                script_args,
                "Generate template-based compliance report (no deployed pack)"
            ):
                print("\nWorkflow failed at Step 4: Template report generation", file=sys.stderr)
                return 1

            # Check if no template was available
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    report_data = json.load(f)
                no_template_available = report_data.get("noTemplateAvailable", False)
            except Exception:
                pass
        else:
            # Normal mode: Use conformance pack report generator
            script_args = [
                args.conformance_pack,
                framework_file,
                mapping_file,
                "-o", report_file
            ] + region_args
            if not run_script(
                "generate_compliance_report.py",
                script_args,
                "Generate compliance report from conformance pack"
            ):
                print("\nWorkflow failed at Step 4: Report generation", file=sys.stderr)
                return 1
    else:
        print(f"\nSkipping Step 4: Using existing report file: {report_file}")

    # Step 5: Get resource configurations (skip in template mode)
    if template_mode:
        print(f"\nSkipping Step 5: No resource configurations in template mode")
    elif not args.skip_configs:
        script_args = [report_file, "-o", configs_file] + region_args
        if not run_script(
            "get_resource_configurations.py",
            script_args,
            "Retrieve resource configurations for all evaluated resources"
        ):
            print("\nWorkflow failed at Step 5: Resource configuration retrieval", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 5: Resource configuration retrieval")

    # Step 6: Generate HTML reports
    if template_mode:
        # Template mode: Generate HTML without configs
        if not args.skip_html:
            script_args = [report_file, "-o", html_prefix, "--template-mode"]
            if not run_script(
                "generate_html_report.py",
                script_args,
                "Generate HTML reports (template mode - no resource data)"
            ):
                print("\nWorkflow failed at Step 6: HTML report generation", file=sys.stderr)
                return 1
        else:
            print(f"\nSkipping Step 6: HTML report generation")
    elif not args.skip_html and not args.skip_configs:
        script_args = [report_file, configs_file, "-o", html_prefix]
        if not run_script(
            "generate_html_report.py",
            script_args,
            "Generate multi-page HTML reports"
        ):
            print("\nWorkflow failed at Step 6: HTML report generation", file=sys.stderr)
            return 1
    elif args.skip_html:
        print(f"\nSkipping Step 6: HTML report generation")
    else:
        print(f"\nSkipping Step 6: HTML report generation (requires resource configurations)")

    # Step 7: Generate control catalog report
    if not args.skip_html:
        summary_link = os.path.basename(html_summary)
        link_prefix = os.path.basename(html_prefix)
        script_args = [
            report_file,
            "-o", html_control_catalog,
            "--catalog-file", cached_catalog_file,
            "--skip-fetch",
            "--link-prefix", link_prefix
        ]
        if args.security_hub_file:
            script_args.extend(["--security-hub-file", args.security_hub_file])
        script_args.extend(region_args)
        if not run_script(
            "generate_control_catalog_report.py",
            script_args,
            "Generate control catalog report for all Config rules"
        ):
            print("\nWorkflow failed at Step 7: Control catalog report generation", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 7: Control catalog report generation")

    # Step 8: Generate gap report (skip if no template available)
    if no_template_available:
        print(f"\nSkipping Step 8: Gap report (no template available for comparison)")
    elif not args.skip_html:
        summary_link = os.path.basename(html_summary)
        control_catalog_link = os.path.basename(html_control_catalog)
        script_args = [report_file, "-o", html_gaps, "--summary-link", summary_link, "--control-catalog-link", control_catalog_link, "--catalog-file", cached_catalog_file]
        if not run_script(
            "generate_gap_report.py",
            script_args,
            "Generate gap analysis report for unmapped rules"
        ):
            print("\nWorkflow failed at Step 8: Gap report generation", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 8: Gap report generation")

    # Step 9: Generate extra rules report (skip if no template available)
    if no_template_available:
        print(f"\nSkipping Step 9: Extra rules report (no template available for comparison)")
    elif not args.skip_html:
        summary_link = os.path.basename(html_summary)
        control_catalog_link = os.path.basename(html_control_catalog)
        script_args = [
            report_file, "-o", html_extra_rules,
            "--summary-link", summary_link,
            "--control-catalog-link", control_catalog_link,
            "--catalog-file", cached_catalog_file,
            "--config-rules-file", cached_config_rules_file
        ] + region_args
        if not run_script(
            "generate_extra_rules_report.py",
            script_args,
            "Generate extra rules report for conformance pack rules not in framework"
        ):
            print("\nWorkflow failed at Step 9: Extra rules report generation", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 9: Extra rules report generation")

    # Final summary
    print("\n" + "=" * 80)
    print("WORKFLOW COMPLETED SUCCESSFULLY")
    print("=" * 80)
    print(f"Completed at: {datetime.now(timezone.utc).isoformat()}")
    print()
    print("Generated Files:")

    generated_files = []
    if not args.skip_extract and not use_cached_framework:
        generated_files.append(("Framework Controls", framework_file))
    elif use_cached_framework:
        generated_files.append(("Framework Controls (cached)", framework_file))
    if not args.skip_map:
        generated_files.append(("Config Mapping", mapping_file))
    if not args.skip_report:
        generated_files.append(("Compliance Report", report_file))
    if not args.skip_configs and not template_mode and configs_file:
        generated_files.append(("Resource Configurations", configs_file))
    # Control Catalog and Config rules caches
    if use_cached_catalog:
        generated_files.append(("Control Catalog (cached)", cached_catalog_file))
    else:
        generated_files.append(("Control Catalog", cached_catalog_file))
    if use_cached_config_rules:
        generated_files.append(("Config Rules (cached)", cached_config_rules_file))
    else:
        generated_files.append(("Config Rules", cached_config_rules_file))
    if not args.skip_html:
        generated_files.append(("HTML Summary", html_summary))
        generated_files.append(("HTML Evidence", html_evidence))
        if not template_mode:
            generated_files.append(("HTML Resources", html_resources))
        generated_files.append(("HTML Control Catalog", html_control_catalog))
        if not no_template_available:
            generated_files.append(("HTML Gap Report", html_gaps))
            generated_files.append(("HTML Extra Rules", html_extra_rules))

    for name, path in generated_files:
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"  {name}: {path} ({size:,} bytes)")
        else:
            print(f"  {name}: {path} (file not found)")

    print()
    print(f"Output folder: {os.path.abspath(output_folder)}")
    if not args.skip_html:
        print(f"\nOpen {html_summary} in a browser to view the compliance report.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
