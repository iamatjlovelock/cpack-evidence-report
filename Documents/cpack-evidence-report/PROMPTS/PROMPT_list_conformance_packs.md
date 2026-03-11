# Prompt: List Conformance Packs

Create a Python script called `list_conformance_packs.py` that lists all AWS Config conformance packs deployed in the account.

## Requirements

### Purpose
Discover deployed conformance packs and their names for use with the compliance workflow.

### AWS APIs Used
1. `config.describe_conformance_packs()` - List all conformance packs

### Output
- JSON file with conformance pack details
- Console summary

### Output Structure

```json
{
  "conformancePacks": [
    {
      "conformancePackName": "PCI-DSS-v4-CPAC",
      "conformancePackArn": "arn:aws:config:...",
      "conformancePackId": "...",
      "deliveryS3Bucket": "...",
      "lastUpdateRequestedTime": "..."
    }
  ],
  "totalCount": 5
}
```

### Example Console Output

```
Deployed Conformance Packs:
  1. PCI-DSS-v4-CPAC
  2. HIPAA-Security-CPAC
  3. CIS-AWS-Foundations-v1.4
  ...

Total: 5 conformance packs
Output written to: conformance_packs.json
```

### CLI Arguments
- `-r, --region`: AWS region
- `-o, --output`: Output JSON file path (default: `conformance_packs.json`)

### Example Usage

```bash
# List conformance packs
python list_conformance_packs.py

# Save to custom file
python list_conformance_packs.py -o my_packs.json
```

### Dependencies
- argparse
- json
- boto3
- botocore
