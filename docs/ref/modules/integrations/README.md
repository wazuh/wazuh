# Integrations

The cloud and third-party integrations collect logs from external services and forward them to the
manager as events. They are **agent modules**: they run inside the agent's `wazuh-modulesd` (inside
the `wazuh-agent` service on Windows) and are configured in the agent's `ossec.conf`. The manager has
no integration modules: `wazuh-manager-modulesd` reads only its own sections of
`etc/wazuh-manager.conf`, and the manager schema has no section for any integration, so an
integration block in `wazuh-manager.conf` fails validation (a `(1244): Invalid configuration` error)
and the manager does not start. To monitor a service, install an agent on a host that can reach it.

- [GCP (Google Cloud Platform)](gcp.md) – Pull Google Cloud logs from Pub/Sub and Cloud Storage access-log buckets.
- [AWS CloudTrail](aws-cloudtrail.md) – Collect CloudTrail logs from an S3 bucket.
- [AWS CloudWatch Logs](aws-cloudwatch-logs.md) – Collect events from CloudWatch log groups.
- [AWS Security Hub](aws-security-hub.md) – Collect Security Hub findings delivered to S3 through an SQS queue.
- [Amazon Security Lake](amazon-security-lake.md) – Collect OCSF data from Amazon Security Lake through an SQS queue.
- [Office 365](office365.md) – Collect audit logs from the Office 365 Management Activity API.
- [GitHub](github.md) – Collect GitHub organization audit logs.
- [Azure](azure.md) – Collect Azure Log Analytics, Microsoft Graph and Azure Storage logs.
- [Microsoft Graph Security API](microsoft-graph.md) – Collect Microsoft Graph resources such as security alerts and incidents.
- [Docker Listener](docker.md) – Forward Docker daemon events.

## Where each integration runs

| Integration | Configuration block | Implementation | Agent platforms |
|-------------|---------------------|----------------|-----------------|
| AWS | `<wodle name="aws-s3">` | Python script `wodles/aws/aws-s3` | Linux and other Unix agents (ignored with a warning on Windows) |
| Azure | `<wodle name="azure-logs">` | Python script `wodles/azure/azure-logs` | Linux and other Unix agents |
| Docker | `<wodle name="docker-listener">` | Python script `wodles/docker/DockerListener` | Linux and other Unix agents (ignored with a warning on Windows) |
| GCP | `<gcp-pubsub>`, `<gcp-bucket>` | Python script `wodles/gcloud/gcloud` | Linux and other Unix agents (ignored with a warning on Windows) |
| GitHub | `<github>` | Built into `wazuh-modulesd` | Linux, macOS and Windows agents |
| Office 365 | `<office365>` | Built into `wazuh-modulesd` | Linux, macOS and Windows agents |
| Microsoft Graph | `<ms-graph>` | Built into `wazuh-modulesd` | Linux, macOS and Windows agents |

The Python scripts are installed under `/var/ossec/wodles/` by the agent installer only, and run with
the agent host's `python3` (`/usr/bin/env python3`), so the Python libraries each page lists must be
installed for that interpreter.

The blocks go inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`. They can also be pushed from
the manager through [centralized configuration](../agent-management/centralized-configuration.md)
(`agent.conf`): the agent reads the same blocks from its shared `agent.conf`.

## Scheduling

The AWS, Azure, GCP, Docker and Microsoft Graph modules share one scheduler. `interval` takes a
number with an optional unit: `s` (or no unit) for seconds, `m` minutes, `h` hours, `d` days, `w`
weeks, `M` months. They also accept `day` (day of the month, 1–31), `wday` (day of the week) and
`time` (`hh:mm`) to run at a fixed moment instead of every interval; `day` and `wday` cannot be
combined. GitHub and Office 365 have their own `interval` parser (units `s`, `m`, `h`, `d`, `w`; no
`day`/`wday`/`time`).

## Logs and debugging

Every integration logs to the agent log (`/var/ossec/logs/ossec.log`; `ossec.log` in the agent
installation directory on Windows) with the tag `wazuh-modulesd:<module>` (`wazuh-agent:<module>`
on Windows), where `<module>` is
`aws-s3`, `azure-logs`, `docker-listener`, `gcp-pubsub`, `gcp-bucket`, `github`, `office365` or
`ms-graph`. To see the scripts' and modules' debug output, set `wazuh_modules.debug` (`1` or `2`) in
the agent's `local_internal_options.conf` and restart the agent — see
[Common Internal Options](../../configuration/agent/README.md#common-internal-options).

## Other AWS sources

The `aws-s3` module accepts more sources than the four that have their own page. They are configured
with the same options as the closest page:

| Element | Accepted `type` values | Options as in |
|---------|------------------------|---------------|
| `<bucket>` | `cloudtrail`, `config`, `vpcflow`, `guardduty`, `waf`, `alb`, `clb`, `nlb`, `server_access`, `cisco_umbrella`, `custom` | [AWS CloudTrail](aws-cloudtrail.md) |
| `<service>` | `cloudwatchlogs`, `inspector` | [AWS CloudWatch Logs](aws-cloudwatch-logs.md) |
| `<subscriber>` | `security_hub`, `security_lake`, `buckets` | [AWS Security Hub](aws-security-hub.md), [Amazon Security Lake](amazon-security-lake.md) |

Any other `type` makes the configuration fail to load. A `<wodle name="aws-s3">` with no `<bucket>`,
`<service>` or `<subscriber>` also fails to load. The old module name `aws-cloudtrail` is still
accepted, with a deprecation warning.
