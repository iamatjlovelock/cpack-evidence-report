# Prompt: Generate Control Catalog Report

Create a Python script called `generate_control_catalog_report.py` that generates an HTML report with detailed AWS Control Catalog information for all Config rules.

## Requirements

### Purpose
Provide a central reference for detailed information about each Config rule from the AWS Control Catalog. This includes descriptions, severity, behavior, governed resources, and framework mappings.

### Input
- Compliance report JSON file
- Optionally: Pre-exported Control Catalog JSON file (for `--skip-fetch` mode)

### Output
- HTML report with detailed control information
- JSON file with Control Catalog data (for caching)

### Key Features

1. **Control Catalog Data**
   - Fetch all Config rules via `controlcatalog.list_controls()`
   - Fetch framework mappings via `controlcatalog.list_control_mappings()`
   - Include: ARN, name, description, severity, behavior, governed resources

2. **Framework Mappings**
   - Show which compliance frameworks reference each rule
   - Highlight mappings for the current framework being reviewed
   - Group other frameworks in a compact list

3. **Report Content**
   - Summary cards (total rules, in catalog, not in catalog)
   - Quick navigation index (3-column layout)
   - Each rule entry showing all Control Catalog metadata
   - Warning for rules not found in Control Catalog
   - Warning when framework has no mappings in Control Catalog

4. **Caching Support**
   - `--catalog-file`: Path to save/load Control Catalog JSON
   - `--skip-fetch`: Use existing catalog file instead of API calls
   - Compute `extraRuleIdentifiers` from compliance report if not in cache

### Control Entry Structure

```html
<div class="control-entry" id="RULE_IDENTIFIER">
    <h3>Rule Name</h3>
    <div class="control-meta">
        <span><strong>Identifier:</strong> RULE_IDENTIFIER</span>
        <span><strong>Severity:</strong> MEDIUM</span>
        <span><strong>Behavior:</strong> DETECTIVE</span>
    </div>
    <div class="control-description">Description text</div>
    <div class="governed-resources">
        <strong>Governed Resources:</strong> AWS::EC2::Instance, AWS::S3::Bucket
    </div>
    <div class="control-mappings">
        <!-- Framework mappings -->
    </div>
</div>
```

### CLI Arguments
- `report_file` (positional): Path to compliance report JSON
- `-o, --output`: Output HTML file path
- `-r, --region`: AWS region
- `--summary-link`: Link back to summary page
- `--catalog-file`: Path to Control Catalog JSON file
- `--skip-fetch`: Skip API calls, use existing catalog file
- `--stdout`: Print to stdout instead of file

### Example Usage

```bash
# Fetch from API and generate report
python generate_control_catalog_report.py compliance_report.json -o control_catalog.html

# Use cached catalog file
python generate_control_catalog_report.py compliance_report.json -o control_catalog.html \
    --catalog-file control-catalog/detective-controls.json --skip-fetch
```

### Dependencies
- argparse
- json
- html
- os
- boto3
- botocore
