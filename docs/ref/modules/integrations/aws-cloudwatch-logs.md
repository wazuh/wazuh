# AWS CloudWatch Logs

## Introduction

The Wazuh AWS module can retrieve logs from AWS CloudWatch log groups. CloudWatch Logs centralizes logs from AWS services and applications, making it possible to monitor and analyze them in one place.

Wazuh connects to the CloudWatch Logs API to pull log events from specified log groups, processes them through the Wazuh rule engine, and generates alerts for relevant security events.

## Prerequisites

- An AWS account with CloudWatch Logs enabled and log groups configured.
- AWS credentials (access key and secret key) or an IAM role with permissions to read CloudWatch log groups.
- Python 3 and the `boto3` library installed on the Wazuh agent.

## Configuration

Configure the AWS module in the Wazuh agent `ossec.conf` file using the `service` element with `type="cloudwatchlogs"`:

```xml
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <service type="cloudwatchlogs">
      <access_key>YOUR_ACCESS_KEY</access_key>
      <secret_key>YOUR_SECRET_KEY</secret_key>
      <regions>us-east-1</regions>
      <aws_log_groups>my-log-group</aws_log_groups>
      <only_logs_after>2024-01-01</only_logs_after>
      <remove_log_streams>no</remove_log_streams>
    </service>
  </wodle>
```

### Configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `disabled` | No | `no` | Disables the AWS module when set to `yes`. |
| `interval` | No | `5s` | Time interval between CloudWatch Logs API queries. |
| `run_on_start` | No | `yes` | Pull logs immediately when the module starts. |
| `skip_on_error` | No | `yes` | Continue processing on error instead of stopping. |
| `service type` | Yes | — | Set to `cloudwatchlogs` to monitor CloudWatch Logs. |
| `access_key` | No | — | AWS access key ID. Not required if using IAM roles. |
| `secret_key` | No | — | AWS secret access key. Not required if using IAM roles. |
| `aws_profile` | No | — | AWS CLI profile name for authentication. |
| `iam_role_arn` | No | — | ARN of an IAM role to assume. |
| `iam_role_duration` | No | — | Duration in seconds for the assumed IAM role session. |
| `aws_account_id` | No | — | AWS account ID for alert enrichment. |
| `aws_account_alias` | No | — | Alias for the AWS account. |
| `regions` | Yes | — | Comma-separated list of AWS regions containing the log groups. |
| `aws_log_groups` | Yes | — | Comma-separated list of CloudWatch log group names to monitor. |
| `only_logs_after` | No | — | Only retrieve logs generated after this date (`YYYY-MM-DD`). |
| `remove_log_streams` | No | `no` | Delete log streams after processing. |
| `discard_field` | No | — | JSON field name to evaluate for discarding events. |
| `discard_regex` | No | — | Regular expression applied to `discard_field` to filter out matching events. |
| `sts_endpoint` | No | — | Custom AWS STS endpoint URL. |
| `service_endpoint` | No | — | Custom CloudWatch Logs endpoint URL. |

### Authentication using IAM role

```xml
<service type="cloudwatchlogs">
  <aws_profile>default</aws_profile>
  <iam_role_arn>arn:aws:iam::123456789012:role/WazuhRole</iam_role_arn>
  <regions>us-east-1</regions>
  <aws_log_groups>my-log-group-1,my-log-group-2</aws_log_groups>
</service>
```

## IAM permissions

The IAM user or role needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:FilterLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:my-log-group:*"
    }
  ]
}
```

If using `remove_log_streams`, add the `logs:DeleteLogStream` permission.

## Verify the integration

Restart the Wazuh agent after applying the configuration:

```bash
systemctl restart wazuh-agent
```

Check the module logs:

```bash
grep "aws-s3" /var/ossec/logs/ossec.log
```

CloudWatch log events generate alerts with the `aws` data field.
