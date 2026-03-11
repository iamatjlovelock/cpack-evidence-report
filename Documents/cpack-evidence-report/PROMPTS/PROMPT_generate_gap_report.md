# Prompt: Generate Gap Analysis Report

Create a Python script called `generate_gap_report.py` that generates an HTML report showing Config rules referenced in the framework but not deployed in the conformance pack.

## Requirements

### Purpose
Identify gaps between compliance framework requirements and deployed conformance pack rules. This helps teams understand which automated controls are missing from their environment.

### Input
- Compliance report JSON file (from `generate_compliance_report.py`)

### Output
- HTML report showing unmapped rules grouped by source identifier

### Key Features

1. **Gap Identification**
   - Find all evidence sources with `sourceType: "AWS_Config"` and `inConformancePack: false`
   - Group by `keywordValue` (unique rule identifier)
   - Show which controls reference each missing rule

2. **Report Content**
   - Summary card showing total unmapped rules
   - Info box explaining what the report shows
   - Each unmapped rule entry showing:
     - Rule identifier (keywordValue)
     - Source name and description
     - List of controls that reference this rule
   - Link to Control Catalog report for detailed rule information

3. **Navigation**
   - Link back to summary page
   - Link to Control Catalog report for each rule identifier

### HTML Structure

```html
<div class="rule-entry">
    <h3 id="anchor_id">RULE_IDENTIFIER</h3>
    <div class="rule-description">Description text</div>
    <div class="controls-list">
        <strong>Referenced by:</strong>
        <ul>
            <li>Control Name 1</li>
            <li>Control Name 2</li>
        </ul>
    </div>
</div>
```

### CLI Arguments
- `report_file` (positional): Path to compliance report JSON
- `-o, --output`: Output HTML file path
- `--summary-link`: Link back to summary page
- `--control-catalog-link`: Link to control catalog report
- `--stdout`: Print to stdout instead of file

### Example Usage

```bash
python generate_gap_report.py compliance_report.json -o gaps.html --summary-link summary.html
```

### Dependencies
- argparse
- json
- html
- os
