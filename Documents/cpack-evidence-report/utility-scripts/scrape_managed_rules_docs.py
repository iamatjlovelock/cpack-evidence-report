#!/usr/bin/env python3
"""
Scrape AWS Config managed rules documentation to build a complete list
of all available managed rules with their metadata.

Source: https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


BASE_URL = "https://docs.aws.amazon.com/config/latest/developerguide/"
INDEX_URL = BASE_URL + "managed-rules-by-aws-config.html"


def fetch_page(url: str, retries: int = 3) -> str:
    """Fetch a page with retries."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                print(f"  Error fetching {url}: {e}", file=sys.stderr)
                return None
    return None


def extract_rule_links(index_html: str) -> list:
    """Extract all managed rule page links from the index page."""
    soup = BeautifulSoup(index_html, 'html.parser')
    rule_links = []

    # Find all links that look like rule pages
    # Links are in format ./rule-name.html or rule-name.html
    for link in soup.find_all('a', href=True):
        href = link['href']
        # Normalize href - remove leading ./
        if href.startswith('./'):
            href = href[2:]
        # Rule pages are typically like "access-keys-rotated.html"
        if re.match(r'^[a-z0-9-]+\.html$', href) and href != 'managed-rules-by-aws-config.html':
            # Skip non-rule pages
            if any(skip in href for skip in ['index', 'getting-started', 'concepts', 'setting-up', 'what-is', 'how-does']):
                continue
            rule_links.append(href)

    return list(set(rule_links))


def extract_rule_metadata(rule_html: str, rule_url: str) -> dict:
    """Extract metadata from a rule documentation page."""
    soup = BeautifulSoup(rule_html, 'html.parser')

    metadata = {
        "url": rule_url,
        "identifier": "",
        "name": "",
        "description": "",
        "resource_types": [],
        "trigger_type": "",
        "aws_region": "",
        "parameters": []
    }

    # Get the page title (rule name)
    title = soup.find('h1')
    if title:
        metadata["name"] = title.get_text(strip=True)

    # Default identifier from URL (will be overwritten if found in content)
    url_name = rule_url.split('/')[-1].replace('.html', '')
    metadata["identifier"] = url_name.upper().replace('-', '_')

    # Get the full text content for regex matching
    text_content = soup.get_text()

    # Extract description - first paragraph that's not metadata
    main_content = soup.find('div', {'id': 'main-content'}) or soup.find('main') or soup
    for para in main_content.find_all('p'):
        para_text = para.get_text(strip=True)
        # Skip if it looks like metadata
        if para_text and not para_text.startswith('Identifier:') and not para_text.startswith('Resource'):
            if 'check' in para_text.lower() or 'rule' in para_text.lower():
                metadata["description"] = para_text
                break

    # Extract Identifier - stop before "Resource" or end of identifier chars
    identifier_match = re.search(r'Identifier:\s*([A-Z][A-Z0-9_]+)(?=Resource|Trigger|AWS|$|\s*<)', text_content)
    if identifier_match:
        metadata["identifier"] = identifier_match.group(1).strip()

    # Extract Resource Types - stop before "Trigger"
    resource_match = re.search(r'Resource\s+Types?:\s*(AWS::[A-Za-z0-9:]+(?:\s*,\s*AWS::[A-Za-z0-9:]+)*)(?=Trigger|AWS Region|$)', text_content)
    if resource_match:
        resources = resource_match.group(1)
        metadata["resource_types"] = [r.strip() for r in resources.split(',') if r.strip()]

    # Extract Trigger type - stop before "AWS Region"
    trigger_match = re.search(r'Trigger\s+type:\s*(Periodic|Configuration\s+changes|Hybrid)(?=AWS|Parameter|$)', text_content, re.IGNORECASE)
    if trigger_match:
        metadata["trigger_type"] = trigger_match.group(1).strip()

    # Extract AWS Region - stop before "Parameters"
    region_match = re.search(r'AWS\s+Region:\s*(.+?)(?=Parameters:|Note:|$)', text_content, re.IGNORECASE)
    if region_match:
        region_text = region_match.group(1).strip()
        # Clean up the region text
        region_text = re.sub(r'\s+', ' ', region_text)
        # Remove trailing "Region" if present
        region_text = re.sub(r'\s*Region$', '', region_text)
        if region_text:
            metadata["aws_region"] = region_text

    # Extract Parameters
    params_match = re.search(r'\*?\*?Parameters:?\*?\*?\s*\n(.+?)(?=\n\s*AWS CloudFormation|Supported resource types|$)', text_content, re.DOTALL | re.IGNORECASE)
    if params_match:
        params_text = params_match.group(1).strip()
        if params_text and params_text.lower() != 'none':
            # Parse individual parameters
            # Look for parameter names (usually camelCase or with underscores)
            param_blocks = re.split(r'\n(?=[a-zA-Z][a-zA-Z0-9_]*\n)', params_text)
            for block in param_blocks:
                lines = block.strip().split('\n')
                if lines:
                    param_name = lines[0].strip()
                    if param_name and not param_name.startswith('Type:') and not param_name.startswith('Default:'):
                        param_info = {"name": param_name}
                        for line in lines[1:]:
                            if line.strip().startswith('Type:'):
                                param_info["type"] = line.replace('Type:', '').strip()
                            elif line.strip().startswith('Default:'):
                                param_info["default"] = line.replace('Default:', '').strip()
                            elif line.strip() and 'description' not in param_info:
                                param_info["description"] = line.strip()
                        if param_info.get("name") and (param_info.get("type") or param_info.get("description")):
                            metadata["parameters"].append(param_info)

    return metadata


def scrape_all_rules(verbose: bool = False) -> list:
    """Scrape all managed rules from AWS documentation."""
    print("Fetching index page...")
    index_html = fetch_page(INDEX_URL)
    if not index_html:
        print("Error: Could not fetch index page", file=sys.stderr)
        return []

    print("Extracting rule links...")
    rule_links = extract_rule_links(index_html)
    print(f"  Found {len(rule_links)} potential rule pages")

    rules = []
    for i, link in enumerate(rule_links):
        rule_url = urljoin(BASE_URL, link)
        if verbose:
            print(f"  [{i+1}/{len(rule_links)}] Fetching {link}...")
        else:
            # Progress indicator
            if (i + 1) % 50 == 0 or i == 0:
                print(f"  Processing rules... {i+1}/{len(rule_links)}")

        rule_html = fetch_page(rule_url)
        if rule_html:
            metadata = extract_rule_metadata(rule_html, rule_url)
            if metadata["identifier"]:
                rules.append(metadata)

        # Be nice to AWS servers
        time.sleep(0.2)

    return rules


def main():
    parser = argparse.ArgumentParser(
        description="Scrape AWS Config managed rules documentation"
    )
    parser.add_argument(
        "-o", "--output",
        default="control-catalog/managed-rules-docs.json",
        help="Output JSON file path"
    )
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Project directory"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()
    project_dir = os.path.abspath(args.project_dir)

    print("Scraping AWS Config managed rules documentation...")
    print(f"Source: {INDEX_URL}\n")

    rules = scrape_all_rules(verbose=args.verbose)

    if not rules:
        print("No rules found!", file=sys.stderr)
        return 1

    print(f"\nTotal rules scraped: {len(rules)}")

    # Sort by identifier
    rules.sort(key=lambda r: r["identifier"])

    # Build output structure
    output = {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "source": INDEX_URL,
        "totalRules": len(rules),
        "rules": {r["identifier"]: r for r in rules}
    }

    # Write output
    output_path = os.path.join(project_dir, args.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Output written to: {output_path}")

    # Print some stats
    with_resources = sum(1 for r in rules if r["resource_types"])
    with_trigger = sum(1 for r in rules if r["trigger_type"])
    with_params = sum(1 for r in rules if r["parameters"])

    print(f"\nMetadata coverage:")
    print(f"  Rules with resource types: {with_resources}")
    print(f"  Rules with trigger type: {with_trigger}")
    print(f"  Rules with parameters: {with_params}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
