# Getting Started

## Prerequisites

- Python 3.8+
- AWS credentials configured with appropriate permissions
- Required packages: `pip install boto3 pyyaml pandas openpyxl`

## Step 1: Extract Security Hub Standard Controls

Before running the compliance workflow, extract the Security Hub controls and their Config rule mappings. This is required if your Audit Manager frameworks reference AWS_Security_Hub evidence sources.

```bash
python security-standard-controls/get_all_enabled_standard_controls.py
```

This script:
1. Refreshes the list of Security Hub standards in your account
2. Extracts controls for each enabled standard (skips existing files)
3. Creates JSON files in `security-standard-controls/` (e.g., `aws-foundational-security-best-practices-v100.json`)

These files map Security Hub controls to their underlying AWS Config rules.

To refresh all files (including existing ones):

```bash
python security-standard-controls/get_all_enabled_standard_controls.py --refresh
```
