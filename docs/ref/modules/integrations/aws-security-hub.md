# AWS Security Hub

## Introduction

The Wazuh AWS module can ingest findings from AWS Security Hub through an SQS (Simple Queue Service) subscriber. AWS Security Hub aggregates security findings from multiple AWS services (such as GuardDuty, Inspector, and Macie) and third-party tools into a centralized dashboard.

Wazuh subscribes to an SQS queue that receives Security Hub findings notifications, processes them through the Wazuh rule engine, and generates alerts with enriched security context.

## Prerequisites

- An AWS account with Security Hub enabled.
- An SQS queue configured to receive Security Hub findings (via EventBridge or direct integration).
- AWS credentials (access key and secret key) or an IAM role with permissions to read from the SQS queue and associated S3 buckets.
- Python 3 and the `boto3` library installed on the Wazuh agent.

## Configuration

Configure the AWS module in the Wazuh agent `ossec.conf` file using the `subscriber` element with `type="security_hub"`:

```xml
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <subscriber type="security_hub">
      <sqs_name>wazuh-security-hub-queue</sqs_name>
      <aws_profile>default</aws_profile>
      <iam_role_arn>arn:aws:iam::123456789012:role/WazuhRole</iam_role_arn>
    </subscriber>
  </wodle>
```

### Configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `disabled` | No | `no` | Disables the AWS module when set to `yes`. |
| `interval` | No | `5s` | Time interval between SQS polling requests. |
| `run_on_start` | No | `yes` | Poll the queue immediately when the module starts. |
| `skip_on_error` | No | `yes` | Continue processing on error instead of stopping. |
| `subscriber type` | Yes | — | Set to `security_hub` for Security Hub integration. |
| `sqs_name` | Yes | — | Name of the SQS queue receiving Security Hub findings. |
| `aws_profile` | No | — | AWS CLI profile name for authentication. |
| `iam_role_arn` | No | — | ARN of an IAM role to assume. |
| `iam_role_duration` | No | — | Duration in seconds for the assumed IAM role session. |
| `external_id` | No | — | External ID for cross-account role assumption. |
| `discard_field` | No | — | JSON field name to evaluate for discarding events. |
| `discard_regex` | No | — | Regular expression applied to `discard_field` to filter out matching events. |
| `sts_endpoint` | No | — | Custom AWS STS endpoint URL. |
| `service_endpoint` | No | — | Custom AWS SQS/S3 endpoint URL. |

## AWS setup

### Enable Security Hub

1. In the AWS Management Console, navigate to **Security Hub**.
2. Enable Security Hub and configure the desired security standards.

### Configure event forwarding to SQS

1. Create an SQS queue (for example, `wazuh-security-hub-queue`).
2. Create an EventBridge rule that forwards Security Hub findings to the SQS queue:
   - **Event source**: AWS services > Security Hub
   - **Event type**: Security Hub Findings - Imported
   - **Target**: The SQS queue created in step 1.

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
      "Resource": "arn:aws:sqs:*:*:wazuh-security-hub-queue"
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

Security Hub findings generate alerts with the `aws` data field containing the original finding information.
