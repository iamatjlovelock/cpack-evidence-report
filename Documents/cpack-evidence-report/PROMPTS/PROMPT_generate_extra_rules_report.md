# Prompt: Generate Extra Rules Report

Create a Python script called `generate_extra_rules_report.py` that generates an HTML report showing Config rules deployed in the conformance pack but not referenced by the framework.

## Requirements

### Purpose
Identify additional compliance coverage beyond framework requirements. These "extra" rules provide security controls that aren't specifically required by the framework but add value to the overall security posture.

### Input
- Compliance report JSON file (from `generate_compliance_report.py`)

### Output
- HTML report listing extra rules with descriptions from Control Catalog

### Key Features

1. **Extra Rule Identification**
   - Read `conformancePackRulesNotInFramework` array from compliance report
   - Fetch rule details from AWS Config API (`describe_config_rules`)
   - Fetch descriptions from AWS Control Catalog API for better descriptions

2. **Report Content**
   - Summary card showing total extra rules count
   - Info box explaining what the report shows
   - Each rule entry showing:
     - Config rule name
     - Source identifier (linked to Control Catalog report)
     - Description (from Control Catalog if available)
     - Source owner (AWS or CUSTOM_LAMBDA)

3. **API Calls**
   - `config.describe_config_rules(ConfigRuleNames=[...])` - Batch in groups of 25
   - `controlcatalog.list_controls()` - Fetch descriptions for source identifiers

### HTML Structure

```html
<div class="rule-entry">
    <h3>config-rule-name</h3>
    <div><span class="rule-identifier">SOURCE_IDENTIFIER</span></div>
    <div class="rule-description">Description from Control Catalog</div>
    <div class="rule-meta">
        <span><strong>Owner:</strong> AWS</span>
    </div>
</div>
```

### CLI Arguments
- `report_file` (positional): Path to compliance report JSON
- `-o, --output`: Output HTML file path
- `-r, --region`: AWS region
- `--summary-link`: Link back to summary page
- `--control-catalog-link`: Link to control catalog report
- `--stdout`: Print to stdout instead of file

### Example Usage

```bash
python generate_extra_rules_report.py compliance_report.json -o extra_rules.html --summary-link summary.html
```

### Dependencies
- argparse
- json
- html
- os
- boto3
- botocore
