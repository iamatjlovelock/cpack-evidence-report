# Prompt: List Audit Manager Frameworks

Create a Python script called `list_audit_manager_frameworks.py` that lists all available AWS Audit Manager frameworks.

## Requirements

### Purpose
Discover available Audit Manager frameworks and their IDs for use with the compliance workflow. Lists both AWS standard frameworks and custom frameworks.

### AWS APIs Used
1. `auditmanager.list_assessment_frameworks(frameworkType='Standard')` - List AWS standard frameworks
2. `auditmanager.list_assessment_frameworks(frameworkType='Custom')` - List custom frameworks

### Output
Display frameworks grouped by type with ID and name.

### Example Output

```
AWS Standard Frameworks:
  1f50f59a-fc3c-4b99-be05-6a79cf3f9538: PCI DSS v4.0
  2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d: HIPAA Security Rule
  ...

Custom Frameworks:
  abc12345-def6-7890-ghij-klmnopqrstuv: My Custom Framework
  ...

Total: 45 standard frameworks, 2 custom frameworks
```

### CLI Arguments
- `-r, --region`: AWS region
- `-o, --output`: Output JSON file path (optional)
- `--json`: Output as JSON instead of formatted text

### Example Usage

```bash
# List frameworks
python list_audit_manager_frameworks.py

# Save to JSON
python list_audit_manager_frameworks.py -o frameworks.json

# Use specific region
python list_audit_manager_frameworks.py -r us-west-2
```

### Dependencies
- argparse
- json
- boto3
- botocore
