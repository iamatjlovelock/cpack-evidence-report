#!/usr/bin/env python3
"""
Run compliance workflow for all frameworks listed in supported_frameworks.txt.

Usage:
    python run_all_frameworks.py [--dry-run] [--parallel N]

Options:
    --dry-run       Print commands without executing
    --parallel N    Run N frameworks in parallel (default: 1, sequential)
"""

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def parse_supported_frameworks(file_path: str) -> list:
    """
    Parse supported_frameworks.txt and return list of (framework_id, framework_name) tuples.

    Expected format:
        ID	Framework Name
        ------------------------------------
        <uuid>	<name>
        ...
    """
    frameworks = []

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        # Skip empty lines, header, and separator
        if not line or line.startswith("ID") or line.startswith("-"):
            continue

        # Split on tab
        parts = line.split("\t", 1)
        if len(parts) >= 2:
            framework_id = parts[0].strip()
            framework_name = parts[1].strip()
            # Validate UUID format (basic check)
            if len(framework_id) == 36 and framework_id.count("-") == 4:
                frameworks.append((framework_id, framework_name))

    return frameworks


def run_workflow(framework_id: str, framework_name: str, dry_run: bool = False) -> tuple:
    """
    Run the compliance workflow for a single framework.

    Returns:
        Tuple of (framework_id, framework_name, success, message)
    """
    cmd = [
        sys.executable,
        "run_compliance_workflow.py",
        "--framework-id", framework_id,
        "--conformance-pack", "none"
    ]

    if dry_run:
        print(f"[DRY RUN] Would execute: {' '.join(cmd)}")
        return (framework_id, framework_name, True, "Dry run")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per framework
        )

        if result.returncode == 0:
            return (framework_id, framework_name, True, "Success")
        else:
            error_msg = result.stderr[-500:] if result.stderr else "Unknown error"
            return (framework_id, framework_name, False, error_msg)

    except subprocess.TimeoutExpired:
        return (framework_id, framework_name, False, "Timeout (5 minutes)")
    except Exception as e:
        return (framework_id, framework_name, False, str(e))


def main():
    parser = argparse.ArgumentParser(
        description="Run compliance workflow for all supported frameworks"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing"
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of frameworks to process in parallel (default: 1)"
    )
    parser.add_argument(
        "--frameworks-file",
        default="supported_frameworks.txt",
        help="Path to frameworks file (default: supported_frameworks.txt)"
    )

    args = parser.parse_args()

    # Parse frameworks file
    if not Path(args.frameworks_file).exists():
        print(f"Error: {args.frameworks_file} not found", file=sys.stderr)
        return 1

    frameworks = parse_supported_frameworks(args.frameworks_file)

    if not frameworks:
        print("No frameworks found in file", file=sys.stderr)
        return 1

    print(f"Found {len(frameworks)} frameworks to process")
    print("=" * 80)

    results = []
    failed = 0

    if args.parallel > 1:
        # Parallel execution
        print(f"Running {args.parallel} frameworks in parallel...")
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {
                executor.submit(run_workflow, fid, fname, args.dry_run): (fid, fname)
                for fid, fname in frameworks
            }

            for i, future in enumerate(as_completed(futures), 1):
                fid, fname, success, msg = future.result()
                status = "OK" if success else "FAILED"
                print(f"[{i}/{len(frameworks)}] {status}: {fname[:60]}")
                if not success:
                    print(f"    Error: {msg[:100]}")
                    failed += 1
                results.append((fid, fname, success, msg))
    else:
        # Sequential execution
        for i, (framework_id, framework_name) in enumerate(frameworks, 1):
            print(f"\n[{i}/{len(frameworks)}] Processing: {framework_name}")
            print("-" * 80)

            fid, fname, success, msg = run_workflow(framework_id, framework_name, args.dry_run)

            if success:
                print(f"  Result: OK")
            else:
                print(f"  Result: FAILED - {msg[:100]}")
                failed += 1

            results.append((fid, fname, success, msg))

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total frameworks: {len(frameworks)}")
    print(f"Successful: {len(frameworks) - failed}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFailed frameworks:")
        for fid, fname, success, msg in results:
            if not success:
                print(f"  - {fname}")
                print(f"    ID: {fid}")
                print(f"    Error: {msg[:200]}")

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
