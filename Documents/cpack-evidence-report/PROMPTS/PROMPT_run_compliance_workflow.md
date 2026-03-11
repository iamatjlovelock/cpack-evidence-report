# Prompt: Unified Compliance Reporting Workflow

Create a Python script called `run_compliance_workflow.py` that orchestrates all compliance report scripts in sequence.

## Requirements

### Purpose
Provide a single command to run the complete compliance reporting workflow, with caching support for framework controls and Control Catalog data.

### Workflow Steps
1. **Export Control Catalog** - Export all Config rules from Control Catalog (cached)
2. **Extract Framework Controls** - Get controls from AWS Audit Manager (cached by framework ID)
3. **Map Config Rules** - Map evidence sources to Config rules
4. **Generate Compliance Report** - Generate report from conformance pack
5. **Get Resource Configurations** - Retrieve config items for all resources
6. **Generate HTML Reports** - Generate summary, evidence, and resources pages
7. **Generate Control Catalog Report** - Generate detailed control catalog HTML
8. **Generate Gap Report** - Generate gap analysis report
9. **Generate Extra Rules Report** - Generate extra rules report

### Caching Behavior

1. **Framework Controls Cache**
   - Location: `framework-controls/{framework_id}_controls.json`
   - Reused automatically on subsequent runs
   - Force refresh with `--refresh-framework`

2. **Control Catalog Cache**
   - Location: `control-catalog/detective-controls.json`
   - Reused automatically on subsequent runs
   - Force refresh with `--refresh-catalog`

### Output Structure

```
framework-controls/
└── {framework_id}_controls.json

control-catalog/
└── detective-controls.json

compliance-dashboards/
└── {output_prefix}/
    ├── {prefix}_config_mapping.json
    ├── compliance_report_{pack}.json
    ├── compliance_report_{pack}_configurations.json
    ├── compliance_report_{pack}_summary.html
    ├── compliance_report_{pack}_evidence.html
    ├── compliance_report_{pack}_resources.html
    ├── compliance_report_{pack}_control_catalog.html
    ├── compliance_report_{pack}_gaps.html
    └── compliance_report_{pack}_extra_rules.html
```

### CLI Arguments
- `--framework-id`: AWS Audit Manager framework ID
- `--conformance-pack` (required): AWS Config conformance pack name
- `--output-prefix`: Prefix for output files/folder
- `-r, --region`: AWS region
- `--refresh-framework`: Force re-download of framework controls
- `--refresh-catalog`: Force re-download of Control Catalog
- `--skip-extract`: Skip framework extraction
- `--skip-map`: Skip config rule mapping
- `--skip-report`: Skip compliance report generation
- `--skip-configs`: Skip resource configuration retrieval
- `--skip-html`: Skip HTML report generation
- `--framework-file`: Use existing framework controls file
- `--mapping-file`: Use existing config mapping file
- `--report-file`: Use existing compliance report file

### Example Usage

```bash
# Full workflow (uses cache if available)
python run_compliance_workflow.py \
    --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \
    --conformance-pack PCI-DSS-CPAC \
    --output-prefix "PCI_DSS_v4"

# Force refresh all cached data
python run_compliance_workflow.py \
    --framework-id 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 \
    --conformance-pack PCI-DSS-CPAC \
    --refresh-framework --refresh-catalog

# Skip to report generation with existing files
python run_compliance_workflow.py \
    --conformance-pack PCI-DSS-CPAC \
    --framework-file framework.json \
    --mapping-file mapping.json \
    --skip-extract --skip-map
```

### Dependencies
- argparse
- json
- os
- subprocess
- sys
- datetime
