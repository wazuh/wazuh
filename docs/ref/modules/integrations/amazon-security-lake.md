# Amazon Security Lake

## Introduction

The AWS module (`<wodle name="aws-s3">`) can collect data from Amazon Security Lake as a Security
Lake **subscriber**, through a `<subscriber type="security_lake">` block. Security Lake stores the
data in S3 as Parquet files in the Open Cybersecurity Schema Framework (OCSF), and notifies the
subscriber's SQS queue of every new object.

It is an agent module, configured in the agent's `ossec.conf`, and is not available on Windows agents
(see [Integrations](README.md)). On each run the agent's `wazuh-modulesd` invokes the
`wodles/aws/aws-s3` Python script, which assumes the subscriber role and then:

1. Receives the messages of the queue (up to 10 per request) until it is empty.
2. For each message carrying the notified object (`detail.bucket.name` and `detail.object.key`),
   downloads the Parquet file, sends every record to the manager, and deletes the message from the
   queue. A message in any other format is skipped and **left in the queue**.

Each record is sent as the OCSF JSON object itself; it is not wrapped in an `aws` object.

## Prerequisites

- An AWS account with Amazon Security Lake enabled.
- A Security Lake subscriber with **data access** through SQS notifications, which gives you the
  subscriber role ARN, the external ID and the queue.
- AWS credentials on the agent host that are allowed to assume that role (see
  [Authentication](aws-cloudtrail.md#authentication)).
- The `boto3` and `pyarrow` Python packages installed for the agent host's `python3`.

## Configuration

Configure the module in the agent's `ossec.conf`, inside `<ossec_config>`:

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <subscriber type="security_lake">
    <sqs_name>wazuh-security-lake-queue</sqs_name>
    <iam_role_arn>arn:aws:iam::123456789012:role/WazuhSecurityLakeRole</iam_role_arn>
    <external_id>wazuh-external-id</external_id>
    <aws_profile>default</aws_profile>
  </subscriber>
</wodle>
```

The module options (`disabled`, `interval`, `run_on_start`, `skip_on_error`) are described in
[AWS CloudTrail](aws-cloudtrail.md#module-options). Security Lake has no `<bucket>` type: a
`<bucket type="security_lake">` makes the configuration fail to load.

### Subscriber options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `subscriber` | Yes | — | The `type` attribute is required: `security_lake` here. |
| `sqs_name` | Yes | — | Name of the subscriber's SQS queue: up to 80 letters, digits, hyphens and underscores. Cannot be empty. |
| `iam_role_arn` | Yes | — | ARN of the subscriber role to assume. Without it the run stops with `Used a subscriber but no --iam_role_arn provided.` |
| `external_id` | Yes | — | External ID of the subscriber, passed when assuming the role. Without it the run stops with `Used a subscriber but no --external_id provided.` |
| `aws_profile` | No | — | Profile from the agent host's AWS credentials and config files used to assume the role. |
| `iam_role_duration` | No | — | Session duration of the assumed role, in seconds, from `900` to `3600`. |
| `sts_endpoint` | No | — | Custom STS endpoint (for example a VPC endpoint) used to assume the role. |
| `service_endpoint` | No | — | Custom endpoint URL for the SQS and S3 clients. |
| `discard_regex` | — | — | Not supported for Security Lake: setting it, with or without the `field` attribute, makes the configuration fail to load (`The 'discard_regex' parameter is not available for Security Lake.`). |

A subscriber accepts no other element: any other element makes the configuration fail to load.

## AWS setup

1. In the AWS Management Console, navigate to **Amazon Security Lake**.
2. Enable Security Lake and select the AWS regions and log sources.
3. Create a subscriber with **data access** and **SQS queue** notifications, and set an external ID.
   Security Lake creates the queue and a role that can read it and the Security Lake bucket.
4. Allow the credentials the agent uses to assume that role (`sts:AssumeRole`), and use the role ARN,
   the external ID and the queue name in the configuration above.

The role must be able to read the queue and the Security Lake objects:

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
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::aws-security-data-lake-*/*"
      ]
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

Each run logs `Executing Subscriber fetch: (Type and SQS: security_lake <sqs_name> )`. A wrong
queue name is reported as `Queue does not exist, verify the given name`.
