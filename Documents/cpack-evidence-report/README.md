# AWS Compliance Reporting Workflow

Generate compliance evidence reports for AWS Audit Manager frameworks using AWS Config conformance pack evaluation results.

## Overview

This toolkit generates detailed compliance reports by:
1. Extracting controls and evidence sources from AWS Audit Manager frameworks
2. Mapping evidence sources to AWS Config rules in your account (with descriptions from Controls Catalog)
3. Retrieving conformance pack evaluation results for each control
4. Fetching resource configuration items for compliance evidence
5. Generating multi-page HTML reports for stakeholder review

## Prerequisites

- Python 3.8+
- AWS credentials configured (via environment variables, AWS CLI, or IAM role)
- boto3 installed (`pip install boto3`)
- pyyaml installed (`pip install pyyaml`) - required for `extract_conformance_pack_rules.py`

## Two Operational Modes

The workflow supports two modes of operation:

### 1. Live Compliance Mode (Default)

Use this mode when you have a conformance pack deployed in your AWS account and want to generate compliance reports with actual resource evaluation results.

```bash
python run_compliance_workflow.py \
  --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \
  --conformance-pack PCI-DSS-CPAC
```

**What it does:**
- Extracts controls from the Audit Manager framework
- Maps framework evidence sources to deployed Config rules
- Retrieves actual compliance evaluation results from the conformance pack
- Fetches resource configurations for evaluated resources
- Generates reports showing real compliance status per control

**Use cases:**
- Generating compliance evidence for audits
- Reviewing current compliance posture
- Identifying non-compliant resources that need remediation

### 2. Template Analysis Mode

Use this mode to analyze how well a conformance pack template covers a framework's requirements, without needing a deployed conformance pack.

```bash
python run_compliance_workflow.py \
  --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \
  --conformance-pack none
```

**What it does:**
- Extracts controls from the Audit Manager framework
- Auto-detects the matching conformance pack YAML template
- Analyzes which framework Config rules are included in the template
- Identifies gaps (rules required by framework but missing from template)
- Identifies extra rules (rules in template but not required by framework)

**Use cases:**
- Planning a conformance pack deployment before committing
- Evaluating different conformance pack templates for a framework
- Understanding coverage gaps between frameworks and available templates
- Comparing what a template provides vs. what a framework requires

The template is auto-detected using `Frameworks.xlsx`. Override with `--template path/to/template.yaml`.

#### Frameworks Without Templates

Not all Audit Manager frameworks have an associated conformance pack template. When you run template analysis mode on such a framework, the workflow:

1. **Generates a framework-only report** - Lists all Config rules referenced by the framework
2. **Shows an informational banner** - Explains that no template is available for this framework
3. **Skips gap and extra rules reports** - Since there's no template to compare against
4. **Still generates the Control Catalog report** - Provides detailed information about each Config rule from the AWS Control Catalog API

This allows you to explore what Config rules a framework requires even when AWS doesn't provide a matching conformance pack template. You can use this information to create a custom conformance pack or identify a related framework's template that might work.

Example output when no template is found:
```
Auto-detecting template for framework...
  No matching conformance pack template found for this framework
  Generating framework-only report (no template mapping)
  Total framework Config rules: 42
...
Skipping Step 8: Gap report (no template available for comparison)
Skipping Step 9: Extra rules report (no template available for comparison)
```

## Quick Start

### Run Full Workflow (Live Mode)

```bash
python run_compliance_workflow.py \
  --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \
  --conformance-pack PCI-DSS-CPAC
```

The output prefix defaults to the framework name (sanitized for filesystem). You can override with `--output-prefix`.

**Cached Data (reused across runs):**
```
framework-controls/
└── 1f50f59a-fc3c-4b99-be05-6a79cf3f9538_controls.json  # Cached by framework ID

control-catalog/
└── detective-controls.json      # All Config rules from Control Catalog
└── account-config-rules.json    # Config rules deployed in your account
```

**Report Output:**
```
compliance-dashboards/
└── PCI_DSS_v4_0/                              # Folder name from framework
    ├── PCI_DSS_v4_0_config_mapping.json       # Config rule mappings
    ├── PCI_DSS_v4_0_report.json               # Full compliance report
    ├── PCI_DSS_v4_0_configurations.json       # Resource configurations
    ├── PCI_DSS_v4_0_summary.html              # HTML summary page
    ├── PCI_DSS_v4_0_evidence.html             # HTML evidence sources
    ├── PCI_DSS_v4_0_resources.html            # HTML resource configs
    ├── PCI_DSS_v4_0_gaps.html                 # HTML gap analysis report
    ├── PCI_DSS_v4_0_extra_rules.html          # HTML extra rules report
    └── PCI_DSS_v4_0_control_catalog.html      # HTML control catalog
```

**Caching:** Framework controls, Control Catalog data, and account Config rules are cached for reuse. Subsequent runs automatically use cached files, avoiding redundant API calls. Use `--refresh-rules` to force refresh of Control Catalog and account Config rules caches.

### Generate HTML Reports

HTML reports are automatically generated by `run_compliance_workflow.py`. To regenerate manually:

```bash
python utility-scripts/generate_html_report.py compliance_report.json configurations.json -o output_prefix
```

This generates six linked HTML pages:
- `*_summary.html` - Compliance summary and controls (start here)
- `*_evidence.html` - Evidence sources with resources
- `*_resources.html` - Resource configurations
- `*_gaps.html` - Gap analysis (rules in framework but not in conformance pack)
- `*_extra_rules.html` - Extra rules (rules in conformance pack but not in framework)
- `*_control_catalog.html` - Control Catalog details for all Config rules

The evidence, gap, and extra rules reports link rule identifiers to the Control Catalog report for detailed information.

## Utility Scripts

All scripts are located in the `utility-scripts/` folder.

### Workflow Scripts (called by run_compliance_workflow.py)

#### get_framework_controls.py

Extract controls and evidence sources from an AWS Audit Manager framework.

```bash
python utility-scripts/get_framework_controls.py <framework_id> -o output.json
```

**Key Features:**
- Resolves Core Control references to get actual evidence sources
- Caches Core Control lookups to avoid duplicate API calls
- Natural sorting of control sets (with appendices last)

#### map_config_rules.py

Map framework evidence sources to AWS Config rules in your account.

```bash
python utility-scripts/map_config_rules.py <framework_controls.json> -o mapping.json
```

**Key Features:**
- Maps `keywordValue` to Config rule `SourceIdentifier`
- Fetches accurate rule descriptions from the AWS Controls Catalog API
- Shows which rules exist in your account
- Identifies unmapped evidence sources

#### generate_compliance_report.py

Generate a compliance report from conformance pack evaluation results.

```bash
python utility-scripts/generate_compliance_report.py <conformance_pack> <framework.json> <mapping.json> -o report.json
```

**Key Features:**
- Retrieves resource-level evaluation results
- Generates `resourceKey` for cross-referencing with configurations
- Caches compliance details to avoid duplicate API calls
- Shows non-compliant resources by control

#### get_resource_configurations.py

Retrieve AWS Config configuration items for all evaluated resources.

```bash
python utility-scripts/get_resource_configurations.py <compliance_report.json> -o configurations.json
```

**Key Features:**
- Uses batch API for efficiency (100 resources per call)
- Falls back to individual queries for unsupported resources
- Parses JSON configuration fields
- Deduplicates resources across multiple evaluations

#### generate_html_report.py

Generate multi-page HTML reports from compliance data.

```bash
python utility-scripts/generate_html_report.py <compliance_report.json> <configurations.json>
```

**Generates three interconnected HTML pages:**

1. **Summary Page** (`*_summary.html`)
   - Header showing framework name, Security Standard, and Conformance Template (from Frameworks.xlsx)
   - Compliance summary cards (control sets, framework controls, resources, compliance rate)
   - Config rules summary (in framework, mapped to pack, missing from pack, extra rules)
   - Conformance pack template cross-check showing matching AWS templates and rule counts
   - Framework controls grouped by control set
   - Each control set shows number of controls and config rules with issues
   - Evidence sources with compliant/non-compliant counts (missing rules link to gap report)
   - Links to evidence sources page

2. **Evidence Sources Page** (`*_evidence.html`)
   - All Config rules with full descriptions from Controls Catalog
   - Resource list for each rule with compliance status
   - Links to resource configurations page

3. **Resources Page** (`*_resources.html`)
   - All evaluated resources grouped by type
   - Full configuration items from AWS Config
   - Supplementary configuration and tags

#### generate_gap_report.py

Generate an HTML gap analysis report showing Config rules referenced in the framework but not deployed in the conformance pack.

```bash
python utility-scripts/generate_gap_report.py <compliance_report.json> -o gaps.html --summary-link summary.html
```

**Key Features:**
- Identifies rules in the framework that are missing from the conformance pack
- Groups unmapped rules by keyword value (unique rules)
- Shows which controls reference each unmapped rule
- Uses rule descriptions from cached Control Catalog data
- Includes navigation link back to summary page
- Links to Control Catalog report for detailed rule information
- Helps identify gaps between compliance framework requirements and deployed controls

#### generate_extra_rules_report.py

Generate an HTML report showing Config rules deployed in the conformance pack but not referenced by the framework.

```bash
python utility-scripts/generate_extra_rules_report.py <compliance_report.json> -o extra_rules.html --summary-link summary.html
```

**Key Features:**
- Identifies rules in the conformance pack that are not required by the framework
- Fetches rule descriptions from AWS Config API
- Shows source identifier and owner for each rule
- Includes navigation link back to summary page
- Helps identify additional compliance coverage beyond framework requirements

#### generate_control_catalog_report.py

Generate an HTML report with detailed AWS Control Catalog information for all Config rules referenced in the framework or deployed in the conformance pack.

```bash
python utility-scripts/generate_control_catalog_report.py <compliance_report.json> -o control_catalog.html --summary-link summary.html
```

**Key Features:**
- Fetches comprehensive control details from AWS Control Catalog API
- Includes rule name, description, ARN, severity, behavior, and governed resources
- Shows deployed Config rule name(s) when available (in addition to the managed rule identifier)
- Displays source badges indicating whether each rule is in the Framework and/or Conformance Pack Template
- Fetches control mappings via ListControlMappings API showing which frameworks reference each rule
- Color-coded quick navigation index:
  - **Green**: Rules in catalog and mapped to the current framework
  - **Purple**: Rules in catalog but not mapped to the current framework
  - **Red**: Rules not found in the Control Catalog
- Control entries highlighted green when mapped to the current framework
- Serves as central reference linked from evidence, gap, and extra rules reports
- Generates JSON extract (`--catalog-file`) for reuse with `--skip-fetch` mode

#### export_control_catalog.py

Export Config rules from the AWS Control Catalog.

```bash
python utility-scripts/export_control_catalog.py -o control-catalog/detective-controls.json
```

**Key Features:**
- Fetches all detective controls from AWS Control Catalog API
- Caches results for reuse across workflow runs
- Provides rule descriptions for mapping and reports

#### generate_template_compliance_report.py

Generate a template-based compliance report (for template analysis mode).

```bash
python utility-scripts/generate_template_compliance_report.py <framework.json> -o report.json --template template.yaml
```

**Key Features:**
- Analyzes conformance pack templates without deployment
- Maps framework rules to template rules
- Identifies coverage gaps

### Standalone Utility Scripts

#### download_conformance_pack_templates.py

Download conformance pack YAML templates from the AWS Config Rules GitHub repository.

```bash
# Download all templates
python utility-scripts/download_conformance_pack_templates.py

# List available templates without downloading
python utility-scripts/download_conformance_pack_templates.py --list-only

# Download to custom folder
python utility-scripts/download_conformance_pack_templates.py -o my-templates
```

**Key Features:**
- Downloads from https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs
- Parallel downloads for efficiency (configurable with `-j`)
- Outputs to `conformance-packs/conformance-pack-yamls/` by default

### list_audit_manager_frameworks.py

List all available AWS Audit Manager frameworks and their IDs.

```bash
python utility-scripts/list_audit_manager_frameworks.py
```

**Key Features:**
- Lists both AWS standard frameworks and custom frameworks
- Shows framework IDs needed for the workflow

### extract_conformance_pack_rules.py

Extract Config rules from conformance pack YAML templates into CSV files.

```bash
# Process all YAML files
python extract_conformance_pack_rules.py

# Process a specific YAML file
python extract_conformance_pack_rules.py AWS-Control-Tower-Detective-Guardrails.yaml

# Custom input/output folders
python extract_conformance_pack_rules.py -i my-yamls -o my-rules
```

**Key Features:**
- Parses conformance pack YAML templates
- Extracts ConfigRuleName and SourceIdentifier for each rule
- Outputs CSV files to `conformance-packs/conformance-pack-rules/` by default
- Can process all YAMLs or a specific file

## Security Hub Scripts

Located in `security-standard-controls/` folder. These scripts extract Security Hub standard controls and their AWS Config rule mappings, which can be used with the `--security-hub-file` option in the workflow.

### list_security_hub_standards.py

List all Security Hub security standards and their enabled status.

```bash
python security-standard-controls/list_security_hub_standards.py
```

**Key Features:**
- Lists all available Security Hub standards in your account
- Shows which standards are enabled
- Outputs to `security-standard-controls/security_hub_standards.json`

### get_all_enabled_standard_controls.py

Extract controls for all enabled Security Hub standards. This is the main entry point for Security Hub integration.

```bash
# Extract controls for all enabled standards (skips existing files)
python security-standard-controls/get_all_enabled_standard_controls.py

# Force refresh all control files
python security-standard-controls/get_all_enabled_standard_controls.py --refresh
```

**Key Features:**
- Automatically calls `list_security_hub_standards.py` first to refresh the standards list
- Calls `get_standard_controls.py` for each enabled standard
- Skips existing control files unless `--refresh` is specified
- Creates JSON files for each standard (e.g., `aws-foundational-security-best-practices-v100.json`)

### get_standard_controls.py

Extract controls for a single Security Hub standard with Config rule mappings.

```bash
python security-standard-controls/get_standard_controls.py \
    --subscription-arn "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0" \
    --name "CIS AWS Foundations Benchmark v1.2.0" \
    --standards-arn "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
```

**Key Features:**
- Retrieves all controls for a Security Hub standard
- Enriches each control with `security_control_id` and `config_rule` mappings
- Queries Security Hub findings to discover the AWS Config rule for each control
- Output used with `--security-hub-file` in the workflow to map AWS_Security_Hub evidence sources

## Conformance Pack Template Cross-Check

The summary report includes a cross-check section that shows conformance pack templates associated with the framework. This uses:

- `Frameworks.xlsx` - Maps Audit Manager frameworks to conformance pack templates and Security Hub standards
- `conformance-packs/conformance-pack-yamls/` - Downloaded YAML templates from AWS Config Rules repository

### Frameworks.xlsx Format

The Excel file has the following columns:

| Column | Description |
|--------|-------------|
| S Audit Manager Framework | Framework name as shown in AWS Audit Manager |
| Framework ID | UUID of the framework (used for exact matching) |
| Conformance Pack Template name | Primary conformance pack template for this framework |
| Security Standard | Security Hub standard name for AWS_Security_Hub evidence source mapping |
| Other relevant Conformance packs | Additional templates that may be useful |
| Notes | Additional information (e.g., "No Equivalent" for frameworks without templates) |

The cross-check displays all matching templates with their Config rule counts. A note explains that the AWS Config API does not indicate which template was used when a conformance pack was deployed.

To download the YAML templates:
```bash
python utility-scripts/download_conformance_pack_templates.py
```

## Output File Relationships

```
┌─────────────────────────────────────────────┐
│   Audit Manager Framework                   │
│   (utility-scripts/get_framework_controls.py)│
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│   Config Rule Mapping                       │◄───── Descriptions from
│   (utility-scripts/map_config_rules.py)     │       Controls Catalog API
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│   Compliance Report                                 │◄───── Contains resourceKey for
│   (utility-scripts/generate_compliance_report.py)   │       cross-referencing
└──────────────┬──────────────────────────────────────┘
               │
        ┌──────┴──────┐
        │             │
        ▼             ▼
┌───────────────┐  ┌────────────────────────────────────┐
│ Resource      │  │ HTML Reports                       │
│ Configs       │  │ (utility-scripts/generate_html_    │
│               │  │  report.py)                        │
└───────┬───────┘  └──────────┬─────────────────────────┘
        │                     │
        └──────────┬──────────┘
                   ▼
        ┌─────────────────────┐
        │  6 Linked HTML Pages │
        │  • Summary          │
        │  • Evidence Sources │
        │  • Resources        │
        │  • Gap Analysis     │
        │  • Extra Rules      │
        │  • Control Catalog  │
        └─────────────────────┘
```

## Cross-Referencing Resources

Each evaluation result includes a `resourceKey` that can be used to look up the full configuration:

```python
# In compliance report:
evaluation_result = {
    "resourceKey": "AWS::EC2::SecurityGroup|sg-0123456789abcdef0",
    "resourceType": "AWS::EC2::SecurityGroup",
    "resourceId": "sg-0123456789abcdef0",
    "complianceType": "NON_COMPLIANT"
}

# Look up configuration:
resource_key = evaluation_result["resourceKey"]
config = configurations["configurations"][resource_key]
```

## Discovering Frameworks and Conformance Packs

### List Available Frameworks

Run `utility-scripts/list_audit_manager_frameworks.py` to generate a list of all frameworks supported by AWS Audit Manager, including their framework IDs:

```bash
python utility-scripts/list_audit_manager_frameworks.py
```

This outputs a list of Audit Manager frameworks with their IDs. Use the framework ID with the `--framework-id` parameter in the workflow.

**Common Framework IDs:**

| Framework | ID |
|-----------|-----|
| PCI DSS v4.0 | `1f50f59a-fc3c-4b99-be05-6a79cf3f9538` |

### List Deployed Conformance Packs

Run `list_conformance_packs.py` to generate a list of AWS Config conformance packs deployed in your account:

```bash
python list_conformance_packs.py
```

This writes the list to `conformance_packs.json` and displays a summary. Use the conformance pack name with the `--conformance-pack` parameter in the workflow.

## Running Scripts

### Run Individual Scripts

Each script can be run independently from the `utility-scripts/` folder. When using the workflow, output is automatically placed in `compliance-dashboards/`. For manual runs, you can specify any output paths:

```bash
# Step 1: Extract framework
python utility-scripts/get_framework_controls.py 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 -o framework.json

# Step 2: Map to Config rules
python utility-scripts/map_config_rules.py framework.json -o mapping.json

# Step 3: Generate compliance report
python utility-scripts/generate_compliance_report.py PCI-DSS-CPAC framework.json mapping.json -o report.json

# Step 4: Get configurations
python utility-scripts/get_resource_configurations.py report.json -o configs.json

# Step 5: Generate HTML (creates 3 linked pages)
python utility-scripts/generate_html_report.py report.json configs.json -o report_prefix

# Step 6: Generate control catalog report
python utility-scripts/generate_control_catalog_report.py report.json -o report_prefix_control_catalog.html --summary-link report_prefix_summary.html

# Step 7: Generate gap report
python utility-scripts/generate_gap_report.py report.json -o report_prefix_gaps.html --summary-link report_prefix_summary.html --control-catalog-link report_prefix_control_catalog.html

# Step 8: Generate extra rules report
python utility-scripts/generate_extra_rules_report.py report.json -o report_prefix_extra_rules.html --summary-link report_prefix_summary.html --control-catalog-link report_prefix_control_catalog.html
```

### Workflow Options

The unified workflow supports several options:

```bash
# Force re-download of framework controls (ignores cache)
python run_compliance_workflow.py \
  --framework-id <id> \
  --conformance-pack <pack> \
  --refresh-framework

# Force refresh of Control Catalog and account Config rules caches
python run_compliance_workflow.py \
  --framework-id <id> \
  --conformance-pack <pack> \
  --refresh-rules

# Skip HTML generation
python run_compliance_workflow.py \
  --framework-id <id> \
  --conformance-pack <pack> \
  --skip-html

# Use existing files and only regenerate report + HTML
python run_compliance_workflow.py \
  --conformance-pack PCI-DSS-CPAC \
  --framework-file "existing_controls.json" \
  --mapping-file "existing_mapping.json" \
  --skip-extract --skip-map

# Override auto-detected template in template analysis mode
python run_compliance_workflow.py \
  --framework-id <id> \
  --conformance-pack none \
  --template path/to/custom-template.yaml
```

**Caching and Output:**
- Framework controls are cached in `framework-controls/` by framework ID
- Control Catalog data is cached in `control-catalog/detective-controls.json`
- Account Config rules are cached in `control-catalog/account-config-rules.json`
- Report output is placed in `compliance-dashboards/{output-prefix}/`
- Use `--refresh-framework` to force fresh download of framework controls
- Use `--refresh-rules` to force refresh of Control Catalog and account Config rules

## Troubleshooting

### "No module named 'boto3'"

Install boto3:
```bash
pip install boto3
```

### "AWS credentials not found"

Configure AWS credentials:
```bash
aws configure
```

Or set environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

### "Conformance pack not found"

Verify the conformance pack exists:
```bash
aws configservice describe-conformance-packs --conformance-pack-names YOUR_PACK_NAME
```

### "ResourceNotDiscoveredException"

Some resource types may not be tracked by AWS Config. Check your Config recording settings.

## License

This project is provided as-is for compliance reporting purposes.
