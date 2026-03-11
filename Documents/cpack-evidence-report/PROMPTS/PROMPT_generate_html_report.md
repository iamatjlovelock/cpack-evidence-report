# Prompt: Generate Multi-Page HTML Compliance Report

Create a Python script called `generate_html_report.py` that generates interconnected HTML reports from compliance data.

## Requirements

### Purpose
Generate a set of linked HTML pages that present compliance data in a user-friendly format for stakeholder review. The reports should be visually appealing, easy to navigate, and suitable for printing.

### Input Files
1. **Compliance Report JSON** - Output from `generate_compliance_report.py`
2. **Resource Configurations JSON** - Output from `get_resource_configurations.py`

### Output Files
Three interconnected HTML pages:
1. `*_summary.html` - Compliance overview and controls by control set
2. `*_evidence.html` - Evidence sources with resource details
3. `*_resources.html` - Full resource configurations

### Key Features

1. **Summary Page**
   - Summary cards showing totals (control sets, controls, evidence sources, compliant/non-compliant resources, compliance rate)
   - Second row of cards for Config rule metrics (rules in framework, mapped to pack, missing from pack, rules in pack, extra rules in pack)
   - Controls grouped by control set
   - Each control set header shows: number of controls, config rules with non-compliant resources, missing rules count
   - Evidence sources for each control with compliance counts and status badges
   - Missing rules shown with "Missing" badge linking to gap report
   - Links to evidence sources page

2. **Evidence Sources Page**
   - All Config rules with descriptions from Control Catalog
   - Resource list for each rule with compliance status
   - Links to resource configurations page
   - Anchor IDs for deep linking from summary page

3. **Resources Page**
   - All evaluated resources grouped by resource type
   - Full configuration items from AWS Config
   - Supplementary configuration and tags
   - Collapsible JSON sections for large configurations

### HTML Structure

```html
<!-- Common navigation -->
<nav class="nav">
    <a href="*_summary.html">Summary</a> |
    <a href="*_evidence.html">Evidence Sources</a> |
    <a href="*_resources.html">Resources</a>
</nav>

<!-- Page header -->
<div class="report-header">
    <h1>Page Title</h1>
    <div class="meta">Framework | Conformance Pack | Generated Date</div>
</div>
```

### Status Badges
- `badge compliant` - Green for compliant resources
- `badge non-compliant` - Red for non-compliant resources
- `badge not-applicable` - Gray for N/A
- `badge missing` - Orange for rules missing from conformance pack

### CLI Arguments
- `report_file` (positional): Path to compliance report JSON
- `config_file` (positional): Path to resource configurations JSON
- `-o, --output`: Output file prefix (generates 3 files)
- `--gap-report-link`: Link to gap analysis report
- `--extra-rules-report-link`: Link to extra rules report

### Helper Functions
- `escape_html(text)` - Escape HTML special characters
- `make_anchor_id(text)` - Create valid HTML anchor IDs
- `get_common_styles()` - Return shared CSS styles
- `generate_navigation(current_page, prefix)` - Generate nav with current page highlighted
- `generate_page_header(framework, pack, date)` - Generate consistent page header

### Example Usage

```bash
python generate_html_report.py compliance_report.json configurations.json -o report_prefix
```

### Dependencies
- argparse
- json
- html
- os
