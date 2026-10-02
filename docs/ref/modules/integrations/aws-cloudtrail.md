# AWS CloudTrail

## Introduction

The AWS module (`<wodle name="aws-s3">`) can read the CloudTrail logs that a trail delivers to an S3
bucket. CloudTrail records API calls and account activity across an AWS account.

It is an agent module, configured in the agent's `ossec.conf`, and is not available on Windows agents
(see [Integrations](README.md)). On each run the agent's `wazuh-modulesd` invokes the
`wodles/aws/aws-s3` Python script once per configured bucket; the script lists the new log files,
and sends each CloudTrail record to the manager with `integration` set to `aws` and the record under
`aws`.

## Prerequisites

- An AWS account with a CloudTrail trail delivering logs to an S3 bucket.
- AWS credentials that can read the bucket (see [Authentication](#authentication)).
- The `boto3` Python package installed for the agent host's `python3`.

## Configuration

Configure the module in the agent's `ossec.conf`, inside `<ossec_config>`:

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>yes</skip_on_error>
  <bucket type="cloudtrail">
    <name>my-cloudtrail-bucket</name>
    <aws_profile>default</aws_profile>
    <regions>us-east-1</regions>
    <path>my-prefix/</path>
    <only_logs_after>2024-JAN-01</only_logs_after>
    <remove_from_bucket>no</remove_from_bucket>
  </bucket>
</wodle>
```

### Module options

These apply to every `<bucket>`, `<service>` and `<subscriber>` of the `aws-s3` block, and are the
same on the other AWS pages.

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `disabled` | No | `no` | Disables the AWS module when set to `yes`. |
| `interval` | No | `5` (seconds) | Time between runs. See [Scheduling](README.md#scheduling) for units and the `day`/`wday`/`time` alternatives. |
| `run_on_start` | No | `yes` | Run as soon as the module starts instead of waiting for the first `interval`. |
| `skip_on_error` | No | `no` | `yes`: a log file that cannot be read or parsed is skipped and the run continues. `no`: the run stops at that file with an error. |

### Bucket options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `bucket` | Yes | — | An S3 bucket to read. Several may be given. The `type` attribute selects the log format: `cloudtrail` here (other values in [Other AWS sources](README.md#other-aws-sources)). |
| `name` | Yes | — | Name of the S3 bucket. It must follow the S3 bucket naming rules. |
| `aws_profile` | No | — | Profile from the agent host's AWS credentials and config files used to authenticate. |
| `iam_role_arn` | No | — | ARN of an IAM role to assume to read the bucket. |
| `iam_role_duration` | No | — | Session duration of the assumed role, in seconds, from `900` to `3600`. Requires `iam_role_arn`. |
| `access_key` | No | — | AWS access key ID. Deprecated since 4.4: a warning is logged; use another [authentication](#authentication) method. |
| `secret_key` | No | — | AWS secret access key. Deprecated since 4.4, as `access_key`. |
| `aws_organization_id` | No | — | AWS Organizations ID, for an organization trail: the logs are read under `AWSLogs/<organization ID>/`. |
| `aws_account_id` | No | — | Comma-separated list of 12-digit account IDs to read. By default every account found in the bucket. |
| `aws_account_alias` | No | — | Alias of the account, added to the events. |
| `regions` | No | — | Comma-separated list of regions to read (for example `us-east-1,eu-west-1`). By default every region found in the bucket. An unknown region stops the run. |
| `path` | No | — | Prefix the trail writes under, before `AWSLogs/` (the trail's S3 key prefix). The logs are read from `<path>AWSLogs/<path_suffix>[<organization ID>/]<account ID>/CloudTrail/<region>/`. |
| `path_suffix` | No | — | Extra path segment right after `AWSLogs/`, in the layout above. |
| `only_logs_after` | No | — | Only read logs from this date on, in `YYYY-MMM-DD` format (for example `2024-JAN-01`). |
| `remove_from_bucket` | No | `no` | Delete each log file from the bucket after processing it. |
| `discard_regex` | No | — | Skip the events whose `field` matches this regular expression: `<discard_regex field="eventName">^Describe</discard_regex>`. The `field` attribute is required (the configuration fails to load without it) and may name a nested field with dots. |
| `sts_endpoint` | No | — | Custom STS endpoint (for example a VPC endpoint) used to assume `iam_role_arn`. |
| `service_endpoint` | No | — | Custom S3 endpoint URL. |

Any other element makes the configuration fail to load.

### Authentication

Without `aws_profile`, `iam_role_arn` or the deprecated keys, the script uses the default AWS
credential chain of the agent host (environment, credentials files, instance role). To read through a
role instead:

```xml,fragment
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

The IAM user or role used by the module needs the following permissions on the S3 bucket:

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

Restart the agent and look for the module's lines (tag `wazuh-modulesd:aws-s3`):

```bash
systemctl restart wazuh-agent
grep "aws-s3" /var/ossec/logs/ossec.log
```

Each run logs `Executing Bucket Analysis: (Bucket: <name>, …)` for every bucket; script errors are
logged under the same tag.
