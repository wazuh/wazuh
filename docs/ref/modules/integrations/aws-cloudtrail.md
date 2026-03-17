# AWS CloudTrail

## Introduction

The Wazuh AWS module can collect and analyze AWS CloudTrail logs stored in S3 buckets. CloudTrail records API calls and account activity across an AWS infrastructure, providing audit logs for governance, compliance, and security monitoring.

Wazuh retrieves CloudTrail logs from S3, analyzes them using the Wazuh rule engine, and generates alerts for events such as unauthorized API calls, IAM changes, security group modifications, and other suspicious activity.

## Prerequisites

- An AWS account with CloudTrail enabled and configured to deliver logs to an S3 bucket.
- AWS credentials (access key and secret key) or an IAM role with permissions to read from the S3 bucket.
- Python 3 and the `boto3` library installed on the Wazuh agent.

## Configuration

Configure the AWS module in the Wazuh agent `ossec.conf` file:

```xml
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>10m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <bucket type="cloudtrail">
      <name>my-cloudtrail-bucket</name>
      <access_key>YOUR_ACCESS_KEY</access_key>
      <secret_key>YOUR_SECRET_KEY</secret_key>
      <regions>us-east-1</regions>
      <path>AWSLogs/</path>
      <only_logs_after>2024-01-01</only_logs_after>
      <remove_from_bucket>no</remove_from_bucket>
    </bucket>
  </wodle>
```

### Configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `disabled` | No | `no` | Disables the AWS module when set to `yes`. |
| `interval` | No | `5s` | Time interval between S3 bucket scans. |
| `run_on_start` | No | `yes` | Process logs immediately when the module starts. |
| `skip_on_error` | No | `yes` | Continue processing on error instead of stopping. |
| `bucket` | Yes | — | Defines an S3 bucket to monitor. Set `type="cloudtrail"` for CloudTrail logs. |
| `name` | Yes | — | Name of the S3 bucket. |
| `access_key` | No | — | AWS access key ID. Not required if using IAM roles. |
| `secret_key` | No | — | AWS secret access key. Not required if using IAM roles. |
| `aws_profile` | No | — | AWS CLI profile name for authentication. |
| `iam_role_arn` | No | — | ARN of an IAM role to assume for cross-account access. |
| `iam_role_duration` | No | — | Duration in seconds for the assumed IAM role session. |
| `aws_organization_id` | No | — | AWS organization ID to filter logs by. |
| `aws_account_id` | No | — | Specific AWS account ID to filter logs by. |
| `aws_account_alias` | No | — | Alias for the AWS account (used in alert enrichment). |
| `regions` | No | — | Comma-separated list of AWS regions to monitor. |
| `path` | No | — | S3 key prefix filter for CloudTrail log files. |
| `path_suffix` | No | — | S3 key suffix filter. |
| `only_logs_after` | No | — | Only process logs created after this date (`YYYY-MM-DD`). |
| `remove_from_bucket` | No | `no` | Delete log files from the bucket after processing. |
| `discard_field` | No | — | JSON field name to evaluate for discarding events. |
| `discard_regex` | No | — | Regular expression applied to `discard_field` to filter out matching events. |
| `sts_endpoint` | No | — | Custom AWS STS endpoint URL. |
| `service_endpoint` | No | — | Custom AWS S3 endpoint URL. |

### Authentication using IAM role

Instead of using access keys, you can authenticate using an IAM role:

```xml
<bucket type="cloudtrail">
  <name>my-cloudtrail-bucket</name>
  <aws_profile>default</aws_profile>
  <iam_role_arn>arn:aws:iam::123456789012:role/WazuhRole</iam_role_arn>
  <regions>us-east-1,eu-west-1</regions>
</bucket>
```

## AWS setup

### Enable CloudTrail

1. In the AWS Management Console, navigate to **CloudTrail**.
2. Create a trail and configure it to deliver logs to an S3 bucket.
3. Ensure the trail is enabled for all regions if multi-region monitoring is needed.

### IAM permissions

The IAM user or role used by Wazuh needs the following permissions on the S3 bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-cloudtrail-bucket",
        "arn:aws:s3:::my-cloudtrail-bucket/*"
      ]
    }
  ]
}
```

If using `remove_from_bucket`, add the `s3:DeleteObject` permission.

## Verify the integration

Restart the Wazuh agent after applying the configuration:

```bash
systemctl restart wazuh-agent
```

Check the module logs:

```bash
grep "aws-s3" /var/ossec/logs/ossec.log
```

CloudTrail events generate alerts with the `aws` data field containing the original event information.
