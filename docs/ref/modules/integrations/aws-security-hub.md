# AWS Security Hub

## Introduction

The AWS module (`<wodle name="aws-s3">`) can collect AWS Security Hub findings through a
`<subscriber type="security_hub">` block. The findings are not read from Security Hub directly: they
must be exported as EventBridge events into files in an S3 bucket, and that bucket must send its
object-created notifications to an SQS queue. The module reads the queue, downloads each notified
file and forwards its events.

It is an agent module, configured in the agent's `ossec.conf`, and is not available on Windows agents
(see [Integrations](README.md)). On each run the agent's `wazuh-modulesd` invokes the
`wodles/aws/aws-s3` Python script, which:

1. Receives the messages of the queue (up to 10 per request) until it is empty.
2. For each message in the S3 event-notification format (`Records[0].s3.bucket.name` and
   `Records[0].s3.object.key`), downloads the object, sends one event per EventBridge event in the
   file, and deletes the message from the queue. A message in any other format is skipped and **left
   in the queue**.

Each event is sent with `integration` set to `aws` and, under `aws`: `source` (`securityhub`),
`detail_type` (the EventBridge `detail-type`), `log_info` (`log_file`, `s3bucket`), and the event's
`finding` (the first entry of the event's `findings` list) or its `actionName`,
`actionDescription`, `insightName`, `insightArn`, `resultType` and `insightResults` fields.

## Prerequisites

- An AWS account with Security Hub enabled.
- An S3 bucket receiving Security Hub findings as EventBridge events, with object-created
  notifications sent to an SQS queue (see [AWS setup](#aws-setup)).
- AWS credentials that can read the queue and the bucket (see
  [Authentication](aws-cloudtrail.md#authentication)).
- The `boto3` Python package installed for the agent host's `python3`.

## Configuration

Configure the module in the agent's `ossec.conf`, inside `<ossec_config>`:

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <subscriber type="security_hub">
    <sqs_name>wazuh-security-hub-queue</sqs_name>
    <aws_profile>default</aws_profile>
    <iam_role_arn>arn:aws:iam::123456789012:role/WazuhRole</iam_role_arn>
  </subscriber>
</wodle>
```

The module options (`disabled`, `interval`, `run_on_start`, `skip_on_error`) are described in
[AWS CloudTrail](aws-cloudtrail.md#module-options).

### Subscriber options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `subscriber` | Yes | — | The `type` attribute is required: `security_hub` here (`security_lake` and `buckets` are the other valid values). |
| `sqs_name` | Yes | — | Name of the SQS queue receiving the bucket's notifications: up to 80 letters, digits, hyphens and underscores. Cannot be empty. |
| `aws_profile` | No | — | Profile from the agent host's AWS credentials and config files used to authenticate. |
| `iam_role_arn` | No | — | ARN of an IAM role to assume. Cannot be empty when given. |
| `iam_role_duration` | No | — | Session duration of the assumed role, in seconds, from `900` to `3600`. Requires `iam_role_arn`. |
| `external_id` | No | — | External ID passed when assuming `iam_role_arn`. Cannot be empty when given. |
| `discard_regex` | No | — | Skip the events whose `field` matches this regular expression (dots for nested fields): `<discard_regex field="fieldName">regex</discard_regex>`. Without the `field` attribute the option is accepted but no event is discarded. |
| `sts_endpoint` | No | — | Custom STS endpoint (for example a VPC endpoint) used to assume `iam_role_arn`. |
| `service_endpoint` | No | — | Custom endpoint URL for the SQS and S3 clients. |

A subscriber accepts no other element (`access_key`, `secret_key` and `regions` included): any other
element makes the configuration fail to load.

## AWS setup

### Enable Security Hub

1. In the AWS Management Console, navigate to **Security Hub**.
2. Enable Security Hub and configure the desired security standards.

### Deliver the findings to S3 and notify SQS

1. Create an S3 bucket for the findings and an EventBridge rule for the Security Hub events
   (**Event source**: Security Hub; for example **Security Hub Findings - Imported**) whose target
   writes the events into that bucket, for example through an Amazon Data Firehose stream. Each file
   must hold the EventBridge events as JSON objects, plain or compressed as `.gz` or `.zip`.
2. Create an SQS queue (for example, `wazuh-security-hub-queue`) whose access policy lets the bucket
   send messages to it.
3. In the bucket, add an event notification for object-created events with the queue as destination.

### IAM permissions

The IAM user or role used by the module needs the following permissions:

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
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::my-security-hub-findings-bucket/*"
    }
  ]
}
```

## Verify the integration

Restart the agent and look for the module's lines (tag `wazuh-modulesd:aws-s3`):

```bash
systemctl restart wazuh-agent
grep "aws-s3" /var/ossec/logs/ossec.log
```

Each run logs `Executing Subscriber fetch: (Type and SQS: security_hub <sqs_name> )`. A wrong queue name is
reported as `Queue does not exist, verify the given name`.
