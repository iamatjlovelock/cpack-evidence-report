import boto3


def list_supported_frameworks():
    """List all supported frameworks from AWS Audit Manager."""
    client = boto3.client('auditmanager')

    frameworks = []
    next_token = None

    # Paginate through all standard (AWS-managed) frameworks
    while True:
        if next_token:
            response = client.list_assessment_frameworks(
                frameworkType='Standard',
                nextToken=next_token
            )
        else:
            response = client.list_assessment_frameworks(
                frameworkType='Standard'
            )

        frameworks.extend(response.get('frameworkMetadataList', []))
        next_token = response.get('nextToken')

        if not next_token:
            break

    return frameworks


def main():
    frameworks = list_supported_frameworks()

    print(f"Found {len(frameworks)} supported frameworks:\n")
    print(f"{'ID':<40} {'Name'}")
    print("-" * 100)

    for framework in frameworks:
        framework_id = framework.get('id', 'N/A')
        framework_name = framework.get('name', 'N/A')
        print(f"{framework_id:<40} {framework_name}")


if __name__ == '__main__':
    main()
