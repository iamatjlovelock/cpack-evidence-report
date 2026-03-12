#!/usr/bin/env python3
"""
Download conformance pack YAML templates from the AWS Config Rules GitHub repository.

This script fetches the list of YAML files from:
https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs

And downloads each file to the conformance-packs/conformance-pack-yamls folder.
"""

import argparse
import os
import sys
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


GITHUB_API_URL = "https://api.github.com/repos/awslabs/aws-config-rules/contents/aws-config-conformance-packs"
RAW_BASE_URL = "https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs"


def get_yaml_file_list() -> list:
    """
    Fetch the list of YAML files from the GitHub API.

    Returns:
        List of file names (*.yaml files only)
    """
    print(f"Fetching file list from GitHub API...")

    req = urllib.request.Request(
        GITHUB_API_URL,
        headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "Python"}
    )

    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode("utf-8"))

    yaml_files = [
        item["name"] for item in data
        if item["type"] == "file" and item["name"].endswith(".yaml")
    ]

    print(f"  Found {len(yaml_files)} YAML files")
    return yaml_files


def download_file(file_name: str, output_folder: str) -> tuple:
    """
    Download a single YAML file.

    Args:
        file_name: Name of the file to download
        output_folder: Folder to save the file to

    Returns:
        Tuple of (file_name, success, error_message)
    """
    url = f"{RAW_BASE_URL}/{file_name}"
    output_path = os.path.join(output_folder, file_name)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Python"})
        with urllib.request.urlopen(req) as response:
            content = response.read()

        with open(output_path, "wb") as f:
            f.write(content)

        return (file_name, True, None)
    except Exception as e:
        return (file_name, False, str(e))


def main():
    parser = argparse.ArgumentParser(
        description="Download conformance pack YAML templates from AWS Config Rules GitHub repo"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output folder (default: conformance-packs/conformance-pack-yamls)",
        default="conformance-packs/conformance-pack-yamls"
    )
    parser.add_argument(
        "-j", "--jobs",
        type=int,
        help="Number of parallel downloads (default: 10)",
        default=10
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Only list available templates without downloading"
    )

    args = parser.parse_args()

    try:
        # Get list of YAML files
        yaml_files = get_yaml_file_list()

        if not yaml_files:
            print("No YAML files found in the repository.")
            return 1

        if args.list_only:
            print("\nAvailable conformance pack templates:")
            for f in sorted(yaml_files):
                print(f"  {f}")
            return 0

        # Create output folder
        output_folder = args.output
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
            print(f"Created output folder: {output_folder}")

        # Download files in parallel
        print(f"\nDownloading {len(yaml_files)} files to {output_folder}...")

        success_count = 0
        fail_count = 0

        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(download_file, f, output_folder): f
                for f in yaml_files
            }

            for future in as_completed(futures):
                file_name, success, error = future.result()
                if success:
                    success_count += 1
                    print(f"  Downloaded: {file_name}")
                else:
                    fail_count += 1
                    print(f"  FAILED: {file_name} - {error}", file=sys.stderr)

        print(f"\nDownload complete:")
        print(f"  Success: {success_count}")
        print(f"  Failed: {fail_count}")
        print(f"  Output folder: {os.path.abspath(output_folder)}")

        return 0 if fail_count == 0 else 1

    except urllib.error.HTTPError as e:
        print(f"Error: HTTP {e.code} - {e.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Error: {e.reason}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
