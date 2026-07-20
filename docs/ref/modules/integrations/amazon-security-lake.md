# Amazon Security Lake

## Introduction

The Wazuh AWS module can retrieve security data from Amazon Security Lake through an SQS subscriber. Amazon Security Lake automatically centralizes security data from AWS services, SaaS providers, and third-party sources into a purpose-built data lake stored in S3, using the Open Cybersecurity Schema Framework (OCSF).

Wazuh subscribes to an SQS queue that receives notifications when new data is available in Security Lake, retrieves the corresponding log files from S3, and processes them through the Wazuh rule engine.

## Prerequisites

- An AWS account with Amazon Security Lake enabled.
- An SQS queue configured as a subscriber source for Security Lake.
- AWS credentials or an IAM role with permissions to read from the SQS queue and the Security Lake S3 bucket.
- Python 3 and the `boto3` library installed on the Wazuh agent.

## Configuration

Configure the AWS module in the Wazuh agent `ossec.conf` file using the `subscriber` element with `type="security_lake"`:

```xml
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <subscriber type="security_lake">
      <sqs_name>wazuh-security-lake-queue</sqs_name>
      <aws_profile>default</aws_profile>
      <iam_role_arn>arn:aws:iam::123456789012:role/WazuhSecurityLakeRole</iam_role_arn>
    </subscriber>
  </wodle>
```

Alternatively, Security Lake data can be accessed via the S3 bucket type:

```xml
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>10m</interval>
    <run_on_start>yes</run_on_start>
    <bucket type="security_lake">
      <name>aws-security-data-lake-bucket</name>
      <aws_profile>default</aws_profile>
      <iam_role_arn>arn:aws:iam::123456789012:role/WazuhSecurityLakeRole</iam_role_arn>
      <regions>us-east-1</regions>
    </bucket>
  </wodle>
```

### Subscriber configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `disabled` | No | `no` | Disables the AWS module when set to `yes`. |
| `interval` | No | `5s` | Time interval between SQS polling requests. |
| `run_on_start` | No | `yes` | Poll the queue immediately when the module starts. |
| `skip_on_error` | No | `yes` | Continue processing on error instead of stopping. |
| `subscriber type` | Yes | — | Set to `security_lake` for Security Lake integration. |
| `sqs_name` | Yes | — | Name of the SQS queue configured for Security Lake notifications. |
| `aws_profile` | No | — | AWS CLI profile name for authentication. |
| `iam_role_arn` | No | — | ARN of an IAM role to assume. |
| `iam_role_duration` | No | — | Duration in seconds for the assumed IAM role session. |
| `external_id` | No | — | External ID for cross-account role assumption. |
| `discard_field` | No | — | JSON field name to evaluate for discarding events. |
| `discard_regex` | No | — | Regular expression for filtering out matching events. |
| `sts_endpoint` | No | — | Custom AWS STS endpoint URL. |
| `service_endpoint` | No | — | Custom AWS endpoint URL. |

## AWS setup

### Enable Amazon Security Lake

1. In the AWS Management Console, navigate to **Amazon Security Lake**.
2. Enable Security Lake and select the AWS regions and log sources.
3. Configure a subscriber with an SQS queue for data access notifications.

### IAM permissions

The IAM user or role needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueUrl"
      ],
      "Resource": "arn:aws:sqs:*:*:wazuh-security-lake-queue"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::aws-security-data-lake-*",
        "arn:aws:s3:::aws-security-data-lake-*/*"
      ]
    }
  ]
}
```

## Verify the integration

Restart the Wazuh agent after applying the configuration:

```bash
systemctl restart wazuh-agent
```

Check the module logs:

```bash
grep "aws-s3" /var/ossec/logs/ossec.log
```

Security Lake events generate alerts with the `aws` data field containing the OCSF-formatted event data.
