# Prompt: Download Conformance Pack Templates

Create a Python script called `download_conformance_pack_templates.py` that downloads conformance pack YAML templates from the AWS Config Rules GitHub repository.

## Requirements

### Purpose
Download all conformance pack templates from the official AWS repository for reference and analysis. These templates define the Config rules included in each conformance pack.

### Source
GitHub repository: https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs

### APIs Used
1. GitHub API: `GET /repos/awslabs/aws-config-rules/contents/aws-config-conformance-packs`
2. Raw content: `https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/{filename}`

### Key Features

1. **Fetch File List**
   - Use GitHub API to list directory contents
   - Filter for `.yaml` files only

2. **Parallel Downloads**
   - Use ThreadPoolExecutor for concurrent downloads
   - Configurable number of parallel workers (default: 10)

3. **Progress Output**
   ```
   Fetching file list from GitHub API...
     Found 117 YAML files

   Downloading 117 files to conformance-pack-yamls...
     Downloaded: AWS-Control-Tower-Detective-Guardrails.yaml
     Downloaded: Operational-Best-Practices-for-PCI-DSS.yaml
     ...

   Download complete:
     Success: 117
     Failed: 0
     Output folder: /path/to/conformance-pack-yamls
   ```

### CLI Arguments
- `-o, --output`: Output folder (default: `conformance-pack-yamls`)
- `-j, --jobs`: Number of parallel downloads (default: 10)
- `--list-only`: List available templates without downloading

### Example Usage

```bash
# Download all templates
python download_conformance_pack_templates.py

# List available templates
python download_conformance_pack_templates.py --list-only

# Download to custom folder with more parallelism
python download_conformance_pack_templates.py -o my-templates -j 20
```

### Dependencies
- argparse
- json
- os
- sys
- urllib.request
- concurrent.futures
