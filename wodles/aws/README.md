# AWS module maintenance notes

## CloudWatch Logs checkpoint account isolation

CloudWatch collection stores its progress in `aws_services.db`. The
`cloudwatch_logs` table identifies each checkpoint by AWS account ID, region,
log group and log stream. Every checkpoint lookup, update and cleanup uses
that scope. When `iam_role_arn` is configured, the account is taken from the
successfully assumed role ARN; otherwise it is the account returned by STS
for the configured credentials/profile. Different roles in the same account
share progress for the same region, group and stream.

### Upgrading an existing database

Older versions keyed checkpoints only by region, group and stream. Those rows
contain no account ID, and a multi-account installation may already have lost
or overwritten some checkpoints. The module cannot safely infer their owner.

On the first collection using the new schema, the module atomically renames
the old table to `cloudwatch_logs_legacy` and creates an empty, account-scoped
`cloudwatch_logs` table. The legacy rows remain unchanged for inspection and
recovery. Other services' tables are not modified. Subsequent runs detect
the account column and do not repeat the migration. A conflicting legacy
backup table or an SQL error aborts the migration without replacing the
original table.

Each account then collects from `only_logs_after`, or from the current UTC
day when that option is absent. Previously collected events in that range
can be emitted again once, including on a single-account installation. A
historical `only_logs_after` can therefore cause substantial replay. The
default does not recover uncollected events from before the current UTC day.
Review the collection start date and back up the database before upgrading.
The module logs a warning when it migrates the legacy table; it does not
silently assign unowned checkpoints to the first account that runs.

No new configuration or AWS permissions are required. This change does not
delete indexed alerts, change retention or deduplicate old alerts. The new
schema is not compatible with the older collector: downgrading requires a
planned database restore and can replay events processed since the backup.

### Regression coverage

`tests/test_cloudwatchlogs_accounts.py` uses temporary SQLite databases and
mocked AWS clients, including botocore response validation. It covers account
isolation, cleanup, assumed roles, repeated collection, restart, fresh installs,
legacy preservation, transaction rollback and collection bounds after upgrade.
It does not contact AWS or modify an installed Wazuh service.
