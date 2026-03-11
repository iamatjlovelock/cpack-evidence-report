# Prompt: Generate Resource Configuration Extractor

Create a Python script called `get_resource_configurations.py` that retrieves AWS Config configuration items for all resources listed in a compliance report.

## Requirements

### Purpose
Extract AWS Config configuration items for all unique resources found in a compliance report. The output file is designed for cross-referencing with the compliance report - each resource appears only once regardless of how many rules evaluated it, avoiding data duplication.

### Input
Compliance report JSON file (output from `generate_compliance_report.py`) containing `evaluationResults` with `resourceType` and `resourceId` fields.

### AWS APIs Used
1. `batch_get_resource_config` - Efficiently retrieve configurations for up to 100 resources per call
2. `get_resource_config_history` - Fallback for resources not retrieved via batch API

### Key Behavior

1. **Extract Unique Resources**: Parse the compliance report and extract all unique resources based on `resourceType` and `resourceId`. Generate a `resourceKey` for each resource using the format `{resourceType}|{resourceId}`.

2. **Batch Retrieval**: Use `batch_get_resource_config` API for efficiency (100 resources per call limit)

3. **Fallback to Individual Queries**: For any resources not retrieved via batch, use `get_resource_config_history` with `limit=1` to get the latest configuration

4. **Cross-Reference Key**: Each configuration is stored in a dictionary keyed by `resourceKey` for easy lookup from the compliance report

5. **Parse Configuration JSON**: The `configuration` field from AWS Config may be a JSON string - parse it into a proper object

### Resource Key Format

```python
def make_resource_key(resource_type: str, resource_id: str) -> str:
    """Create a unique key for cross-referencing."""
    return f"{resource_type}|{resource_id}"

# Example:
# "AWS::S3::Bucket|my-bucket-name"
# "AWS::EC2::SecurityGroup|sg-0123456789abcdef0"
```

### Output Structure (JSON)

```json
{
  "generatedAt": "2024-01-15T10:30:00+00:00",
  "sourceReport": "compliance_report_PCI-DSS-CPAC.json",
  "frameworkName": "Payment Card Industry Data Security Standard (PCI DSS) v4.0",
  "conformancePackName": "PCI-DSS-CPAC",
  "configurations": {
    "AWS::S3::Bucket|my-bucket-name": {
      "resourceKey": "AWS::S3::Bucket|my-bucket-name",
      "resourceType": "AWS::S3::Bucket",
      "resourceId": "my-bucket-name",
      "configurationFound": true,
      "configuration": {
        "configurationItemCaptureTime": "2024-01-15T09:00:00+00:00",
        "configurationStateId": "1234567890",
        "arn": "arn:aws:s3:::my-bucket-name",
        "resourceName": "my-bucket-name",
        "awsRegion": "us-east-1",
        "availabilityZone": null,
        "resourceCreationTime": "2023-06-01T12:00:00+00:00",
        "configuration": {
          "name": "my-bucket-name",
          "creationDate": "2023-06-01T12:00:00.000Z",
          "versioningConfiguration": {
            "status": "Enabled"
          }
        },
        "supplementaryConfiguration": {
          "BucketPolicy": "...",
          "PublicAccessBlockConfiguration": "..."
        },
        "tags": {
          "Environment": "Production"
        }
      }
    },
    "AWS::EC2::SecurityGroup|sg-0123456789abcdef0": {
      "resourceKey": "AWS::EC2::SecurityGroup|sg-0123456789abcdef0",
      "resourceType": "AWS::EC2::SecurityGroup",
      "resourceId": "sg-0123456789abcdef0",
      "configurationFound": true,
      "configuration": { ... }
    }
  },
  "summary": {
    "totalResources": 144,
    "configurationsRetrieved": 97,
    "configurationsNotFound": 47,
    "resourceTypes": {
      "AWS::S3::Bucket": {
        "total": 25,
        "configurationsFound": 25
      },
      "AWS::Logs::LogGroup": {
        "total": 46,
        "configurationsFound": 0
      }
    }
  }
}
```

### Cross-Referencing with Compliance Report

The compliance report includes a `resourceKey` in each evaluation result:

```json
// In compliance report evaluationResults:
{
  "resourceKey": "AWS::S3::Bucket|my-bucket-name",
  "resourceType": "AWS::S3::Bucket",
  "resourceId": "my-bucket-name",
  "complianceType": "NON_COMPLIANT",
  "configRuleName": "s3-bucket-ssl-requests-only"
}
```

To look up the configuration:
```python
resource_key = evaluation_result["resourceKey"]
config = configurations["configurations"][resource_key]
```

### Console Output

```
Loading compliance report: compliance_report_PCI-DSS-CPAC.json
Extracting resources from report...
  Found 144 unique resources

Resources by type:
  AWS::S3::Bucket: 25
  AWS::Lambda::Function: 34
  AWS::Logs::LogGroup: 46
  ...

Fetching configurations for 144 resources...
  Retrieved 97 configurations via batch API
  Fetching 47 resources individually...
    Processing 10/47...
    Processing 20/47...
    ...

================================================================================
RESOURCE CONFIGURATION SUMMARY
================================================================================
Framework: Payment Card Industry Data Security Standard (PCI DSS) v4.0
Conformance Pack: PCI-DSS-CPAC
Source Report: compliance_report_PCI-DSS-CPAC.json

Total Resources: 144
Configurations Retrieved: 97
Configurations Not Found: 47

By Resource Type:
  AWS::S3::Bucket: 25/25 configurations found
  AWS::Lambda::Function: 34/34 configurations found
  AWS::Logs::LogGroup: 0/46 configurations found
  ...

Full results written to: resource_configurations.json
```

### CLI Arguments

- `report_file` (positional, required): Path to compliance report JSON file
- `-o, --output`: Output file path (default: `<report_file>_configurations.json`)
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
# Get configurations for resources in compliance report
python get_resource_configurations.py compliance_report_PCI-DSS-CPAC.json

# Specify output file
python get_resource_configurations.py compliance_report_PCI-DSS-CPAC.json -o resource_configs.json

# Use specific region
python get_resource_configurations.py compliance_report_PCI-DSS-CPAC.json -r us-east-1

# Output to stdout
python get_resource_configurations.py compliance_report_PCI-DSS-CPAC.json --stdout
```

### Resources That May Not Have Configurations

Some resource types may not be tracked by AWS Config or may not return configurations:

- `AWS::::Account` - Account-level resources
- `AWS::Logs::LogGroup` - May require explicit recording configuration
- Resources deleted after evaluation but before configuration retrieval

### Use Cases

1. **Compliance Evidence**: Provide detailed resource configurations as evidence for compliance audits

2. **Root Cause Analysis**: Understand why specific resources are non-compliant by examining their configuration

3. **Configuration Snapshots**: Capture point-in-time configuration state for all evaluated resources

4. **Cross-Reference Reporting**: Join configuration data with compliance results for detailed reports

### Important Implementation Notes

1. **Batch API Limit**: `batch_get_resource_config` accepts max 100 resources per call - implement batching

2. **Error Handling**: Handle `ResourceNotDiscoveredException` and `NoAvailableConfigurationRecorderException` gracefully

3. **JSON Parsing**: The `configuration` field from AWS Config is often a JSON string - parse it into an object

4. **Dictionary Output**: Store configurations in a dictionary keyed by `resourceKey` for O(1) lookup performance
