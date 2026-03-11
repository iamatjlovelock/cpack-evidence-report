# Prompt: Extract Conformance Pack Rules

Create a Python script called `extract_conformance_pack_rules.py` that extracts Config rules from conformance pack YAML templates into CSV files.

## Requirements

### Purpose
Parse conformance pack YAML templates and extract the Config rules defined in each pack. This creates a quick reference for which rules are included in each conformance pack.

### Input
- YAML files from `conformance-pack-yamls/` folder (downloaded by `utility-scripts/download_conformance_pack_templates.py`)

### Output
- CSV files in `conformance-pack-rules/` folder, one per YAML file
- Columns: ConfigRuleName, SourceIdentifier

### YAML Structure

Conformance pack YAML files have this structure:

```yaml
Resources:
  RuleName:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: rule-name-in-lowercase
      Source:
        Owner: AWS
        SourceIdentifier: RULE_IDENTIFIER_IN_UPPERCASE
```

### Key Features

1. **YAML Parsing**
   - Use PyYAML to parse template files
   - Extract resources of type `AWS::Config::ConfigRule`
   - Get `ConfigRuleName` and `Source.SourceIdentifier`

2. **Batch Processing**
   - Process all YAML files in input folder
   - Or process a single specified file

3. **Output Format**
   ```csv
   ConfigRuleName,SourceIdentifier
   access-keys-rotated,ACCESS_KEYS_ROTATED
   acm-certificate-expiration-check,ACM_CERTIFICATE_EXPIRATION_CHECK
   ```

4. **Progress Output**
   ```
   Processing 117 YAML file(s)...

     AWS-Control-Tower-Detective-Guardrails.yaml: 30 rules
     Operational-Best-Practices-for-PCI-DSS.yaml: 145 rules
     ...

   Processing complete:
     Files processed: 117
     Files failed: 0
     Total rules extracted: 5,432
     Output folder: /path/to/conformance-pack-rules
   ```

### CLI Arguments
- `yaml_file` (positional, optional): Specific YAML file to process (processes all if not specified)
- `-i, --input-folder`: Input folder containing YAML files (default: `conformance-pack-yamls`)
- `-o, --output-folder`: Output folder for CSV files (default: `conformance-pack-rules`)

### Example Usage

```bash
# Process all YAML files
python extract_conformance_pack_rules.py

# Process a specific file
python extract_conformance_pack_rules.py AWS-Control-Tower-Detective-Guardrails.yaml

# Custom folders
python extract_conformance_pack_rules.py -i my-yamls -o my-rules
```

### Dependencies
- argparse
- csv
- os
- sys
- yaml (pyyaml)
