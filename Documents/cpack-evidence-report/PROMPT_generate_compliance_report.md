# Prompt: Generate Compliance Report from AWS Config Conformance Pack

Create a Python script called `generate_compliance_report.py` that generates a compliance report for an AWS Audit Manager framework based on AWS Config conformance pack evaluation results.

## Requirements

### Purpose
Generate a compliance report that shows the compliance status of an AWS account against framework controls (e.g., PCI DSS v4.0) by evaluating AWS Config conformance pack results. The report maps framework controls to Config rules and retrieves actual resource evaluation results.

### Inputs
1. **Conformance Pack Name**: The name of the AWS Config conformance pack to evaluate
2. **Framework JSON**: Output from `get_framework_controls.py` containing controls and evidence sources
3. **Config Mapping JSON**: Output from `map_config_rules.py` mapping keyword values to Config rules

### AWS APIs Used
1. `describe_conformance_pack_compliance` - Get list of Config rules in the conformance pack
2. `get_conformance_pack_compliance_details` - Get resource-level evaluation results for a rule

**Note**: These APIs do NOT support boto3 paginators. Use manual pagination with `NextToken`.

### Key Behavior

1. **Get Conformance Pack Rules**: Call `describe_conformance_pack_compliance` to get all Config rule names in the conformance pack

2. **Build Keyword-to-Rule Mapping**: Using the config mapping JSON, create a lookup from `keywordValue` to the conformance pack rule name (filter to only rules that exist in the conformance pack)

3. **Process Framework Controls**: For each control in the framework:
   - Iterate through `controlMappingSources`
   - For each `coreControlEvidenceSources` entry:
     - If `sourceType == "AWS_Config"`:
       - Look up the Config rule using `sourceKeyword.keywordValue`
       - Call `get_conformance_pack_compliance_details` to get evaluation results
       - Generate `resourceKey` for each result using `make_resource_key(resourceType, resourceId)`
       - Aggregate compliance counts (COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE)

4. **Cache Results**: Cache compliance details by Config rule name to avoid duplicate API calls (multiple controls may reference the same rule)

5. **Generate Report**: Build a hierarchical report grouped by Control Set → Control → Evidence Source

### Output Structure (JSON)

```json
{
  "reportGeneratedAt": "2024-01-15T10:30:00+00:00",
  "conformancePackName": "PCI-DSS-CPAC",
  "frameworkName": "Payment Card Industry Data Security Standard (PCI DSS) v4.0",
  "frameworkId": "...",
  "controlSets": [
    {
      "controlSetId": "Requirement 1: ...",
      "controlSetName": "Requirement 1: Install and Maintain Network Security Controls",
      "controls": [
        {
          "controlId": "...",
          "controlName": "1.2.1: Network security controls (NSCs) are configured...",
          "controlDescription": "...",
          "evidenceSources": [
            {
              "sourceName": "Configure VPC security groups...",
              "sourceType": "AWS_Config",
              "keywordValue": "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS",
              "configRuleName": "vpc-sg-open-only-to-authorized-ports-conformance-pack-xyz",
              "inConformancePack": true,
              "evaluationResults": [
                {
                  "resourceKey": "AWS::EC2::SecurityGroup|sg-0123456789abcdef0",
                  "resourceType": "AWS::EC2::SecurityGroup",
                  "resourceId": "sg-0123456789abcdef0",
                  "complianceType": "NON_COMPLIANT",
                  "configRuleName": "vpc-sg-open-only-to-authorized-ports-conformance-pack-xyz",
                  "resultRecordedTime": "2024-01-15T09:00:00+00:00",
                  "annotation": "Security group allows unrestricted access"
                }
              ],
              "complianceSummary": {
                "compliant": 5,
                "nonCompliant": 2,
                "notApplicable": 0
              }
            }
          ],
          "summary": {
            "totalEvidenceSources": 3,
            "awsConfigSources": 2,
            "mappedToConformancePack": 2,
            "compliantResources": 10,
            "nonCompliantResources": 2,
            "notApplicableResources": 0
          }
        }
      ],
      "summary": {
        "totalControls": 15,
        "compliantResources": 100,
        "nonCompliantResources": 5
      }
    }
  ],
  "summary": {
    "totalControlSets": 15,
    "totalControls": 280,
    "totalEvidenceSources": 687,
    "awsConfigEvidenceSources": 450,
    "mappedToConformancePack": 200,
    "notMappedToConformancePack": 250,
    "compliantResources": 1500,
    "nonCompliantResources": 87,
    "notApplicableResources": 23
  }
}
```

### Resource Key for Cross-Referencing

Each evaluation result includes a `resourceKey` field that can be used to cross-reference with the resource configurations file (output from `get_resource_configurations.py`).

```python
def make_resource_key(resource_type: str, resource_id: str) -> str:
    """Create a unique key for cross-referencing with resource configurations."""
    return f"{resource_type}|{resource_id}"

# Example:
# "AWS::S3::Bucket|my-bucket-name"
# "AWS::EC2::SecurityGroup|sg-0123456789abcdef0"
```

**Cross-Reference Usage:**
```python
# In compliance report evaluationResults:
evaluation_result = {
    "resourceKey": "AWS::EC2::SecurityGroup|sg-0123456789abcdef0",
    "resourceType": "AWS::EC2::SecurityGroup",
    "resourceId": "sg-0123456789abcdef0",
    "complianceType": "NON_COMPLIANT"
}

# Look up configuration from get_resource_configurations.py output:
resource_key = evaluation_result["resourceKey"]
config = configurations["configurations"][resource_key]
```

### Console Output

Display progress and summary:
```
Loading framework file: PCI DSS v4.json
Loading config mapping file: PCI DSS v4_config_mapping.json
Fetching rules from conformance pack: PCI-DSS-CPAC...
  Found 107 rules in conformance pack

Building keyword to conformance pack rule mapping...
  Mapped 72 keywords to conformance pack rules

Processing 280 controls...
  Processing control 1/280: A2.1.3: POI terminals using SSL and/or early TLS...
  Processing control 2/280: A3.1.1: A PCI DSS compliance program is implemented...
  ...

====================================================================================================
COMPLIANCE REPORT SUMMARY
====================================================================================================
Framework: Payment Card Industry Data Security Standard (PCI DSS) v4.0
Conformance Pack: PCI-DSS-CPAC
Generated At: 2024-01-15T10:30:00+00:00

Total Control Sets: 15
Total Controls: 280
Total Evidence Sources: 687
AWS Config Evidence Sources: 450
Mapped to Conformance Pack: 200
NOT Mapped to Conformance Pack: 250

RESOURCE COMPLIANCE:
  Compliant Resources: 1500
  Non-Compliant Resources: 87
  Not Applicable: 23

====================================================================================================
CONTROL SETS WITH NON-COMPLIANT RESOURCES
====================================================================================================

Requirement 1: Install and Maintain Network Security Controls
  Compliant: 50, Non-Compliant: 2

  Control: 1.3.1: Network access to and from the cardholder data environment is restricted.
    Non-Compliant Resources: 2
      - vpc-sg-open-only-to-authorized-ports-conformance-pack-xyz: 2 non-compliant
        * AWS::EC2::SecurityGroup: sg-05cb542a1b7519f25
        * AWS::EC2::SecurityGroup: sg-0b765293b58195055

...

Full report written to: compliance_report_PCI-DSS-CPAC.json
```

### CLI Arguments

- `conformance_pack_name` (positional, required): Name of the AWS Config conformance pack
- `framework_file` (positional, required): Path to framework JSON file
- `config_mapping_file` (positional, required): Path to config mapping JSON file
- `-o, --output`: Output file path (default: `compliance_report_<conformance_pack>.json`)
- `-r, --region`: AWS region (optional)
- `--stdout`: Print full JSON to stdout instead of file

### Dependencies

- boto3
- botocore (for ClientError, NoCredentialsError)
- argparse
- json
- collections (defaultdict)
- datetime

### Example Usage

```bash
# Generate compliance report for PCI DSS conformance pack
python generate_compliance_report.py "PCI-DSS-CPAC" "PCI DSS v4.json" "PCI DSS v4_config_mapping.json"

# Specify output file
python generate_compliance_report.py "PCI-DSS-CPAC" "PCI DSS v4.json" "PCI DSS v4_config_mapping.json" -o my_report.json

# Use specific region
python generate_compliance_report.py "PCI-DSS-CPAC" "PCI DSS v4.json" "PCI DSS v4_config_mapping.json" -r us-east-1
```

### Use Cases

1. **Compliance Reporting**: Generate evidence-based compliance reports for auditors showing control status

2. **Gap Analysis**: Identify which controls have non-compliant resources requiring remediation

3. **Resource Remediation**: Get specific resource IDs that need to be fixed for each control

4. **Continuous Compliance**: Run periodically to track compliance posture over time

5. **Multi-Framework Assessment**: Run against different framework JSONs to assess compliance against multiple standards

### Important Implementation Notes

1. **Manual Pagination**: The AWS Config APIs `describe_conformance_pack_compliance` and `get_conformance_pack_compliance_details` do NOT support boto3 paginators. Implement manual pagination using `NextToken`.

2. **Caching**: Cache compliance details by Config rule name since multiple controls may reference the same rule.

3. **Evidence Source Extraction**: Extract `AWS_Config` sources from `controlMappingSources[].coreControlEvidenceSources` where `sourceType == "AWS_Config"`.

4. **Rule Filtering**: Only map keywords to rules that exist in the specified conformance pack (filter using the conformance pack rule list).

5. **Resource Key Generation**: Generate a `resourceKey` for each evaluation result using the format `{resourceType}|{resourceId}`. This key enables cross-referencing with the resource configurations file generated by `get_resource_configurations.py`.
