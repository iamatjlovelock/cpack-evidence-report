#!/usr/bin/env python3
"""
Unified workflow script that runs all compliance report scripts in sequence.

This script orchestrates:
1. get_framework_controls.py - Extract controls from Audit Manager framework
2. map_config_rules.py - Map evidence sources to Config rules
3. generate_compliance_report.py - Generate compliance report from conformance pack
4. get_resource_configurations.py - Get configuration items for all resources
5. generate_html_report.py - Generate multi-page HTML reports

All output files will be written to a folder named for the output-prefix parameter 
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def get_python_executable():
    """Get the Python executable path."""
    return sys.executable


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

    script_path = os.path.join(os.path.dirname(__file__), script_name)

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
  python run_compliance_workflow.py \\
    --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \\
    --conformance-pack PCI-DSS-CPAC \\
    --output-prefix "PCI_DSS_v4"

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
        help="AWS Audit Manager framework ID (required unless --skip-extract). Run list_audit_manager_frameworks.py to generate a list of frameworks with their IDs"
    )
    parser.add_argument(
        "--conformance-pack",
        required=True,
        help="AWS Config conformance pack name. Run list_conformance_packs.py to generate a list of deployed Conformance packs"
    )
    parser.add_argument(
        "--output-prefix",
        help="Prefix for output files (default: conformance pack name)",
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

    args = parser.parse_args()

    # Validate arguments
    if not args.skip_extract and not args.framework_id:
        parser.error("--framework-id is required unless --skip-extract is specified")

    if args.skip_extract and not args.framework_file:
        parser.error("--framework-file is required when using --skip-extract")

    if args.skip_map and not args.mapping_file:
        parser.error("--mapping-file is required when using --skip-map")

    if args.skip_report and not args.report_file and not args.skip_configs:
        parser.error("--report-file is required when using --skip-report (unless also using --skip-configs)")

    # Set output prefix
    output_prefix = args.output_prefix or args.conformance_pack

    # Create output folder
    output_folder = output_prefix
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder: {output_folder}")

    # Define output file names (all within output folder)
    framework_file = args.framework_file or os.path.join(output_folder, f"{output_prefix}_controls.json")
    mapping_file = args.mapping_file or os.path.join(output_folder, f"{output_prefix}_config_mapping.json")
    report_file = args.report_file or os.path.join(output_folder, f"compliance_report_{args.conformance_pack}.json")
    configs_file = os.path.join(output_folder, f"compliance_report_{args.conformance_pack}_configurations.json")

    # HTML report files
    html_prefix = os.path.join(output_folder, f"compliance_report_{args.conformance_pack}")
    html_summary = f"{html_prefix}_summary.html"
    html_evidence = f"{html_prefix}_evidence.html"
    html_resources = f"{html_prefix}_resources.html"
    html_gaps = f"{html_prefix}_gaps.html"
    html_extra_rules = f"{html_prefix}_extra_rules.html"
    html_control_catalog = f"{html_prefix}_control_catalog.html"

    print("\n" + "=" * 80)
    print("AWS COMPLIANCE REPORTING WORKFLOW")
    print("=" * 80)
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print(f"Conformance Pack: {args.conformance_pack}")
    if args.framework_id:
        print(f"Framework ID: {args.framework_id}")
    print(f"Output Folder: {output_folder}")
    print()
    print("Output Files:")
    print(f"  Framework Controls: {framework_file}")
    print(f"  Config Mapping: {mapping_file}")
    print(f"  Compliance Report: {report_file}")
    print(f"  Resource Configs: {configs_file}")
    print(f"  HTML Summary: {html_summary}")
    print(f"  HTML Evidence: {html_evidence}")
    print(f"  HTML Resources: {html_resources}")
    print(f"  HTML Gap Report: {html_gaps}")
    print(f"  HTML Extra Rules: {html_extra_rules}")
    print(f"  HTML Control Catalog: {html_control_catalog}")

    # Build region args
    region_args = ["-r", args.region] if args.region else []

    success = True

    # Step 1: Extract framework controls
    if not args.skip_extract:
        script_args = [args.framework_id, "-o", framework_file] + region_args
        if not run_script(
            "get_framework_controls.py",
            script_args,
            "Extract framework controls from AWS Audit Manager"
        ):
            print("\nWorkflow failed at Step 1: Framework extraction", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 1: Using existing framework file: {framework_file}")

    # Step 2: Map Config rules
    if not args.skip_map:
        script_args = [framework_file, "-o", mapping_file] + region_args
        if not run_script(
            "map_config_rules.py",
            script_args,
            "Map evidence sources to AWS Config rules"
        ):
            print("\nWorkflow failed at Step 2: Config rule mapping", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 2: Using existing mapping file: {mapping_file}")

    # Step 3: Generate compliance report
    if not args.skip_report:
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
            print("\nWorkflow failed at Step 3: Report generation", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 3: Using existing report file: {report_file}")

    # Step 4: Get resource configurations
    if not args.skip_configs:
        script_args = [report_file, "-o", configs_file] + region_args
        if not run_script(
            "get_resource_configurations.py",
            script_args,
            "Retrieve resource configurations for all evaluated resources"
        ):
            print("\nWorkflow failed at Step 4: Resource configuration retrieval", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 4: Resource configuration retrieval")

    # Step 5: Generate HTML reports
    if not args.skip_html and not args.skip_configs:
        script_args = [report_file, configs_file, "-o", html_prefix]
        if not run_script(
            "generate_html_report.py",
            script_args,
            "Generate multi-page HTML reports"
        ):
            print("\nWorkflow failed at Step 5: HTML report generation", file=sys.stderr)
            return 1
    elif args.skip_html:
        print(f"\nSkipping Step 5: HTML report generation")
    else:
        print(f"\nSkipping Step 5: HTML report generation (requires resource configurations)")

    # Step 6: Generate control catalog report
    if not args.skip_html:
        summary_link = os.path.basename(html_summary)
        script_args = [report_file, "-o", html_control_catalog, "--summary-link", summary_link] + region_args
        if not run_script(
            "generate_control_catalog_report.py",
            script_args,
            "Generate control catalog report for all Config rules"
        ):
            print("\nWorkflow failed at Step 6: Control catalog report generation", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 6: Control catalog report generation")

    # Step 7: Generate gap report
    if not args.skip_html:
        summary_link = os.path.basename(html_summary)
        control_catalog_link = os.path.basename(html_control_catalog)
        script_args = [report_file, "-o", html_gaps, "--summary-link", summary_link, "--control-catalog-link", control_catalog_link]
        if not run_script(
            "generate_gap_report.py",
            script_args,
            "Generate gap analysis report for unmapped rules"
        ):
            print("\nWorkflow failed at Step 7: Gap report generation", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 7: Gap report generation")

    # Step 8: Generate extra rules report
    if not args.skip_html:
        summary_link = os.path.basename(html_summary)
        control_catalog_link = os.path.basename(html_control_catalog)
        script_args = [report_file, "-o", html_extra_rules, "--summary-link", summary_link, "--control-catalog-link", control_catalog_link] + region_args
        if not run_script(
            "generate_extra_rules_report.py",
            script_args,
            "Generate extra rules report for conformance pack rules not in framework"
        ):
            print("\nWorkflow failed at Step 8: Extra rules report generation", file=sys.stderr)
            return 1
    else:
        print(f"\nSkipping Step 8: Extra rules report generation")

    # Final summary
    print("\n" + "=" * 80)
    print("WORKFLOW COMPLETED SUCCESSFULLY")
    print("=" * 80)
    print(f"Completed at: {datetime.now(timezone.utc).isoformat()}")
    print()
    print("Generated Files:")

    generated_files = []
    if not args.skip_extract:
        generated_files.append(("Framework Controls", framework_file))
    if not args.skip_map:
        generated_files.append(("Config Mapping", mapping_file))
    if not args.skip_report:
        generated_files.append(("Compliance Report", report_file))
    if not args.skip_configs:
        generated_files.append(("Resource Configurations", configs_file))
    if not args.skip_html and not args.skip_configs:
        generated_files.append(("HTML Summary", html_summary))
        generated_files.append(("HTML Evidence", html_evidence))
        generated_files.append(("HTML Resources", html_resources))
    if not args.skip_html:
        generated_files.append(("HTML Control Catalog", html_control_catalog))
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
    if not args.skip_html and not args.skip_configs:
        print(f"\nOpen {html_summary} in a browser to view the compliance report.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
