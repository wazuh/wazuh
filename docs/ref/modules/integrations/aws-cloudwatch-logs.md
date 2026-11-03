# AWS CloudWatch Logs

## Introduction

The AWS module (`<wodle name="aws-s3">`) can read log events from CloudWatch Logs log groups, using a
`<service type="cloudwatchlogs">` block.

It is an agent module, configured in the agent's `ossec.conf`, and is not available on Windows agents
(see [Integrations](README.md)). On each run the agent's `wazuh-modulesd` invokes the
`wodles/aws/aws-s3` Python script, which reads the new events of every log stream of the configured
log groups, region by region, and sends each event's message to the manager as is (it is not wrapped
in an `aws` object).

## Prerequisites

- An AWS account with CloudWatch Logs log groups.
- AWS credentials that can read those log groups (see
  [Authentication](aws-cloudtrail.md#authentication)).
- The `boto3` Python package installed for the agent host's `python3`.

## Configuration

Configure the module in the agent's `ossec.conf`, inside `<ossec_config>`:

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <service type="cloudwatchlogs">
    <aws_profile>default</aws_profile>
    <regions>us-east-1</regions>
    <aws_log_groups>my-log-group</aws_log_groups>
    <only_logs_after>2024-JAN-01</only_logs_after>
    <remove_log_streams>no</remove_log_streams>
  </service>
</wodle>
```

The module options (`disabled`, `interval`, `run_on_start`, `skip_on_error`) are described in
[AWS CloudTrail](aws-cloudtrail.md#module-options).

### Service options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `service` | Yes | — | The `type` attribute is required: `cloudwatchlogs` here (`inspector` is the other valid value). |
| `aws_log_groups` | Yes | — | Comma-separated list of log group names. Cannot be empty; without it nothing is read. |
| `regions` | No | — | Comma-separated list of regions. When unset, the region of the profile in `~/.aws/config` of the user running the agent is used (`default` when no `aws_profile` is set), and failing that every region. An invalid region stops the run. |
| `aws_profile` | No | — | Profile from the agent host's AWS credentials and config files used to authenticate. |
| `iam_role_arn` | No | — | ARN of an IAM role to assume. |
| `iam_role_duration` | No | — | Session duration of the assumed role, in seconds, from `900` to `3600`. Requires `iam_role_arn`. |
| `access_key` | No | — | AWS access key ID. Deprecated since 4.4: a warning is logged. |
| `secret_key` | No | — | AWS secret access key. Deprecated since 4.4: a warning is logged. |
| `aws_account_id` | No | — | AWS account ID. Cannot be empty when given. |
| `aws_account_alias` | No | — | Alias of the account. |
| `only_logs_after` | No | — | Only read events from this date on, in `YYYY-MMM-DD` format (for example `2024-JAN-01`). |
| `remove_log_streams` | No | `no` | Delete each log stream after reading it. |
| `discard_regex` | No | — | Skip matching events. A JSON message is skipped when the `field` attribute's value (dots for nested fields) matches the regex; with no `field` a JSON message is never skipped. A non-JSON message is skipped when the whole message matches. Format: `<discard_regex field="fieldName">regex</discard_regex>` or `<discard_regex>regex</discard_regex>`. |
| `sts_endpoint` | No | — | Custom STS endpoint (for example a VPC endpoint) used to assume `iam_role_arn`. |
| `service_endpoint` | No | — | Custom CloudWatch Logs endpoint URL. |

Any other element makes the configuration fail to load.

### Authentication using IAM role

```xml,fragment
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
        "logs:DescribeLogStreams",
        "logs:GetLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:my-log-group:*"
    }
  ]
}
```

If using `remove_log_streams`, add the `logs:DeleteLogStream` permission.

## Verify the integration

Restart the agent and look for the module's lines (tag `wazuh-modulesd:aws-s3`):

```bash
systemctl restart wazuh-agent
grep "aws-s3" /var/ossec/logs/ossec.log
```

Each run logs `Executing Service Analysis: (Service: cloudwatchlogs, …)`; script errors are logged
under the same tag.
