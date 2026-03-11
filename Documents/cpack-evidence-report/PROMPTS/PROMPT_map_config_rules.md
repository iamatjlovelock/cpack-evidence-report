# Prompt: Generate AWS Config Rule Mapper for Audit Manager Frameworks

Create a Python script called `map_config_rules.py` that maps AWS Audit Manager evidence sources to actual AWS Config rules deployed in an AWS account.

## Requirements

### Purpose
Take the output from `get_framework_controls.py` (a framework JSON file) and map all `AWS_Config` type evidence sources to the actual Config rules in the AWS account. This helps identify:
1. Which Config rules provide evidence for framework controls
2. Which expected Config rules are NOT deployed in the account (compliance gaps)

### Key Concept: The Mapping
AWS Audit Manager uses **Managed Rule Identifiers** (e.g., `CMK_BACKING_KEY_ROTATION_ENABLED`) to reference Config rules. These identifiers map to the `Source.SourceIdentifier` field in AWS Config rules.

| Audit Manager | AWS Config |
|---------------|------------|
| `sourceKeyword.keywordValue` | `Source.SourceIdentifier` |

One managed rule identifier can map to multiple Config rules (e.g., standalone rule, conformance pack rule, Security Hub rule).

### AWS APIs Used
1. `describe_config_rules` (paginated) - Get all Config rules and their SourceIdentifier

### Input
Framework JSON file from `get_framework_controls.py` containing:
- Controls with `controlMappingSources`
- Core Control evidence sources in `coreControlEvidenceSources`
- Evidence sources with `sourceType: "AWS_Config"` and `sourceKeyword.keywordValue`

### Key Behavior

1. **Load Framework JSON**: Read the framework file and extract all unique `AWS_Config` evidence sources by their `keywordValue`

2. **Track Control References**: For each `keywordValue`, track which controls use it (for traceability)

3. **Fetch Config Rules**: Call `describe_config_rules` (paginated) and index all rules by their `Source.SourceIdentifier`

4. **Build Mapping**: Match each framework `keywordValue` to Config rules with the same `SourceIdentifier`

5. **Identify Gaps**: Flag identifiers that have no matching Config rules in the account

### Evidence Source Extraction
Extract AWS_Config sources from two locations in the framework JSON:
1. **Direct sources**: `controlMappingSources` where `sourceType == "AWS_Config"`
2. **Core Control sources**: `controlMappingSources[].coreControlEvidenceSources` where `sourceType == "AWS_Config"`

### Output Structure (JSON)

```json
{
  "frameworkName": "Payment Card Industry Data Security Standard (PCI DSS) v4.0",
  "frameworkId": "...",
  "mappings": [
    {
      "managedRuleIdentifier": "CMK_BACKING_KEY_ROTATION_ENABLED",
      "controlsUsingThis": [
        {
          "controlId": "...",
          "controlName": "...",
          "controlSetName": "...",
          "sourceName": "Rotate AWS Key Management Service (KMS) keys",
          "coreControlSourceName": null,
          "sourceLevel": "coreControl"
        }
      ],
      "configRulesInAccount": [
        {
          "ConfigRuleName": "cmk-backing-key-rotation-enabled",
          "SourceIdentifier": "CMK_BACKING_KEY_ROTATION_ENABLED",
          "SourceOwner": "AWS",
          "Description": "...",
          "ConfigRuleState": "ACTIVE",
          "ConfigRuleArn": "arn:aws:config:..."
        },
        {
          "ConfigRuleName": "cmk-backing-key-rotation-enabled-conformance-pack-xyz",
          "SourceIdentifier": "CMK_BACKING_KEY_ROTATION_ENABLED",
          "SourceOwner": "AWS",
          "Description": "",
          "ConfigRuleState": "ACTIVE",
          "ConfigRuleArn": "arn:aws:config:..."
        }
      ],
      "isMapped": true
    }
  ],
  "summary": {
    "totalEvidenceSourceIdentifiers": 202,
    "mappedToConfigRules": 169,
    "notMappedToConfigRules": 33,
    "totalConfigRulesMatched": 336
  }
}
```

### Console Output

Display progress and summary:
```
Loading framework from: PCI DSS v4.json
Framework: Payment Card Industry Data Security Standard (PCI DSS) v4.0

Extracting AWS_Config evidence sources from framework...
  Found 202 unique Config rule identifiers referenced

Fetching AWS Config rules...
  Found 650 Config rules
  Covering 389 unique managed rule identifiers

Mapping evidence sources to Config rules...

================================================================================
MAPPING SUMMARY
================================================================================
Framework: Payment Card Industry Data Security Standard (PCI DSS) v4.0
Total evidence source identifiers: 202
Mapped to Config rules: 169
NOT mapped (no matching rules): 33
Total Config rules matched: 336

================================================================================
UNMAPPED IDENTIFIERS (no Config rules found in account)
================================================================================
  - APPROVED_AMIS_BY_ID
  - APPROVED_AMIS_BY_TAG
  ...

================================================================================
MAPPED IDENTIFIERS
================================================================================

  ACCESS_KEYS_ROTATED:
    -> access-keys-rotated-conformance-pack-nnnc374ig
    -> securityhub-access-keys-rotated-2281de0a
  ...

Full mapping written to: PCI DSS v4_config_mapping.json
```

### CLI Arguments

- `framework_file` (positional, required): Path to framework JSON file
- `-o, --output`: Output file path (default: `<framework_file>_config_mapping.json`)
- `-r, --region`: AWS region (optional)
- `--stdout`: Print full JSON to stdout instead of file

### Dependencies

- boto3
- botocore (for ClientError, NoCredentialsError)
- argparse
- json
- collections (defaultdict)

### Example Usage

```bash
# Map PCI DSS framework to Config rules
python map_config_rules.py "PCI DSS v4.json"

# Specify output file
python map_config_rules.py "PCI DSS v4.json" -o pci_config_mapping.json

# Use specific region
python map_config_rules.py "PCI DSS v4.json" -r us-east-1

# Output to stdout
python map_config_rules.py "PCI DSS v4.json" --stdout
```

### Use Cases

1. **Compliance Gap Analysis**: Identify which Config rules need to be deployed to achieve full evidence coverage for a framework

2. **Evidence Traceability**: Understand which Config rules provide evidence for which framework controls

3. **Multi-Account Comparison**: Run against different accounts to compare Config rule deployment

4. **Conformance Pack Planning**: Identify which managed rules to include in a conformance pack for a specific compliance framework
