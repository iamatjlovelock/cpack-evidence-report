# Prompt: Export Control Catalog

Create a Python script called `export_control_catalog.py` that exports all Config rules from AWS Control Catalog to a JSON file.

## Requirements

### Purpose
Create a cached copy of all Config rules from the AWS Control Catalog for use by other scripts in the workflow. This avoids redundant API calls when generating multiple reports.

### AWS APIs Used
1. `controlcatalog.list_controls()` - Paginate through all controls
2. `controlcatalog.list_control_mappings()` - Get framework mappings for all controls

### Output Structure

```json
{
  "exportedAt": "2024-01-15T12:00:00Z",
  "totalControls": 540,
  "controls": {
    "ACCESS_KEYS_ROTATED": {
      "arn": "arn:aws:controlcatalog::aws:control/...",
      "name": "Access keys should be rotated...",
      "description": "This control checks whether...",
      "behavior": "DETECTIVE",
      "severity": "MEDIUM",
      "governedResources": ["AWS::IAM::User"],
      "implementationType": "AWS::Config::ConfigRule",
      "identifier": "ACCESS_KEYS_ROTATED",
      "mappings": [
        {
          "frameworkName": "PCI DSS",
          "item": "8.2.4"
        }
      ]
    }
  }
}
```

### Key Features

1. **Full Catalog Export**
   - Paginate through all controls (MaxResults=100)
   - Filter for `implementationType: "AWS::Config::ConfigRule"`
   - Extract: ARN, name, description, severity, behavior, governed resources

2. **Framework Mappings**
   - Paginate through all control mappings
   - Associate mappings with controls by ARN
   - Include framework name and item reference

3. **Progress Output**
   ```
   Fetching all Config rules from AWS Control Catalog...
     Found 540 Config rule controls in catalog
   Fetching control mappings...
     Found mappings for 864 controls

   Control Catalog exported to: control-catalog/detective-controls.json
     Total controls: 540
     Exported at: 2024-01-15T12:00:00Z
   ```

### CLI Arguments
- `-o, --output`: Output JSON file path (default: `control-catalog/detective-controls.json`)
- `-r, --region`: AWS region

### Example Usage

```bash
# Export to default location
python export_control_catalog.py

# Export to custom location
python export_control_catalog.py -o my-catalog/controls.json
```

### Dependencies
- argparse
- json
- os
- sys
- datetime
- boto3
- botocore
