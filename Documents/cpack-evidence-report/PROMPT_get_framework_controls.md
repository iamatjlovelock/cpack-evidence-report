# Prompt: Generate AWS Audit Manager Framework Controls Extractor

Create a Python script called `get_framework_controls.py` that extracts controls and their evidence sources from an AWS Audit Manager framework.

## Requirements

### Purpose
Extract all controls from an AWS Audit Manager framework, including the underlying evidence sources for each control. The script should resolve nested Core Control references to get the actual automated evidence sources (AWS Config rules, Security Hub findings, CloudTrail events, etc.).

### AWS APIs Used
1. `get_assessment_framework(frameworkId)` - Get framework metadata and list of control sets/controls
2. `get_control(controlId)` - Get full control details including controlMappingSources

### Key Behavior

1. **Fetch Framework**: Call `get_assessment_framework` to get the framework structure with control sets and controls

2. **Fetch Control Details**: For each control in the framework, call `get_control` to get the full control details including `controlMappingSources`

3. **Resolve Core Controls**: When a `controlMappingSource` has `sourceType: "Core_Control"`:
   - First try using `sourceId` to call `get_control`
   - If that fails with ResourceNotFoundException, fall back to using `sourceKeyword.keywordValue` as the control ID
   - Extract the Core Control's `controlMappingSources` as the actual evidence sources
   - Add these as `coreControlEvidenceSources` in the output

4. **Caching**: Cache Core Control responses to avoid duplicate API calls (many controls reference the same Core Controls)

5. **Natural Sorting**: Sort output using natural sort order:
   - Control sets sorted by `controlSetName` with natural sorting (numbers sorted numerically)
   - Appendices are always sorted to the end
   - Controls within each set sorted by `controlName` with natural sorting
   - Example order: Requirement 1, Requirement 2, ... Requirement 10, Requirement 11, Appendix A1, Appendix A2

6. **Error Handling**:
   - Handle `ResourceNotFoundException` gracefully when Core Control IDs are invalid
   - Handle expired credentials and other AWS errors

### Natural Sort Implementation

Implement a `natural_sort_key` function that:
- Splits strings into chunks of digits and non-digits
- Converts digit chunks to integers for proper numerical sorting
- Optionally places items starting with "Appendix" at the end

```python
def natural_sort_key(text: str, appendix_last: bool = False) -> tuple:
    """
    Generate a sort key for natural sorting (numbers sorted numerically).
    """
    is_appendix = text.lower().startswith("appendix")
    chunks = re.split(r'(\d+)', text)

    key_parts = []
    for chunk in chunks:
        if chunk.isdigit():
            key_parts.append(int(chunk))
        else:
            key_parts.append(chunk.lower())

    if appendix_last:
        return (1 if is_appendix else 0, key_parts)

    return tuple(key_parts)
```

### Output Structure (JSON)

```json
{
  "frameworkId": "...",
  "frameworkName": "...",
  "frameworkDescription": "...",
  "frameworkType": "Standard",
  "complianceType": "...",
  "createdAt": "...",
  "lastUpdatedAt": "...",
  "extractedAt": "...",
  "controlSets": [
    {
      "controlSetId": "...",
      "controlSetName": "Requirement 1: Install and Maintain Network Security Controls",
      "controls": [
        {
          "controlId": "...",
          "controlName": "1.1.1: Processes and mechanisms for installing...",
          "controlDescription": "...",
          "controlType": "...",
          "testingInformation": "...",
          "actionPlanTitle": "...",
          "actionPlanInstructions": "...",
          "controlMappingSources": [
            {
              "sourceId": "...",
              "sourceName": "...",
              "sourceDescription": "...",
              "sourceType": "Core_Control | MANUAL | AWS_Config | AWS_Security_Hub | AWS_API_Call | AWS_CloudTrail",
              "sourceSetUpOption": "...",
              "sourceFrequency": "...",
              "sourceKeyword": {
                "keywordInputType": "...",
                "keywordValue": "..."
              },
              "coreControlEvidenceSources": [
                {
                  "sourceId": "...",
                  "sourceName": "...",
                  "sourceDescription": "...",
                  "sourceType": "AWS_Config | AWS_Security_Hub | AWS_API_Call | AWS_CloudTrail",
                  "sourceSetUpOption": "...",
                  "sourceFrequency": "...",
                  "sourceKeyword": {
                    "keywordInputType": "...",
                    "keywordValue": "..."
                  }
                }
              ]
            }
          ]
        }
      ]
    }
  ],
  "summary": {
    "totalControlSets": 15,
    "totalControls": 280,
    "totalMappingSources": 486,
    "totalCoreControlsReferenced": 196,
    "totalCoreControlEvidenceSources": 687
  }
}
```

### CLI Arguments

- `framework_id` (positional, required): The Audit Manager framework ID
- `-o, --output`: Output file path (default: `<framework_id>_controls.json`)
- `-r, --region`: AWS region (optional)
- `--pretty`: Pretty-print JSON output (default: True)
- `--stdout`: Print to stdout instead of file

### Progress Output

Display progress while fetching controls:
```
Retrieving framework: <framework_id>...
  Fetching control 1/280: 1.1.1: Processes and mechanisms for installing...
  Fetching control 2/280: 1.1.2: Processes and mechanisms for installing...
  ...
Successfully wrote controls to: <output_file>
Summary: 15 control sets, 280 controls, 486 mapping sources, 196 unique Core Controls, 687 Core Control evidence sources
```

### Dependencies

- boto3
- botocore (for ClientError, NoCredentialsError)
- argparse
- json
- re (for natural sorting)
- datetime

### Example Usage

```bash
# Extract PCI DSS v4.0 framework
python get_framework_controls.py 1f50f59a-fc3c-4b99-be05-6a79cf3f9538 -o "PCI_DSS_v4.json"

# Extract to stdout
python get_framework_controls.py <framework_id> --stdout

# Use specific region
python get_framework_controls.py <framework_id> -r us-west-2
```

### Example Output Order

With natural sorting and appendices last, control sets appear in this order:
1. Requirement 1: Install and Maintain Network Security Controls
2. Requirement 2: Apply Secure Configurations to All System Components
3. Requirement 3: Protect Stored Account Data
4. ...
5. Requirement 10: Log and Monitor All Access to System Components
6. Requirement 11: Test Security of Systems and Networks Regularly
7. Requirement 12: Support Information Security with Organizational Policies
8. Appendix A1: Additional PCI DSS Requirements for Multi-Tenant Service Providers
9. Appendix A2: Additional PCI DSS Requirements for Entities Using SSL/Early TLS
10. Appendix A3: Designated Entities Supplemental Validation (DESV)

Controls within each set follow the same natural sort order:
- 1.1.1, 1.1.2, 1.2.1, 1.2.2, ... 1.2.8, 1.3.1, ... 1.5.1
- 10.1.1, 10.1.2, 10.2.1, 10.2.1.1, 10.2.1.2, ... 10.7.3
