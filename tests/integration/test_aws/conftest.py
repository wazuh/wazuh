# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
This module contains all necessary components (fixtures, classes, methods) to configure the test for its execution.
"""

import os
import time
import random
import pytest
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

# qa-integration-framework imports
from wazuh_testing.logger import logger
from wazuh_testing.modules.aws.utils import (
    upload_log_events,
    create_log_group,
    create_log_stream,
    delete_bucket,
    delete_log_group,
    delete_log_stream,
    delete_s3_db,
    delete_services_db,
    upload_bucket_file,
    generate_file,
    create_sqs_queue,
    get_sqs_queue_arn,
    set_sqs_policy,
    set_bucket_event_notification_configuration,
    delete_sqs_queue,
    delete_bucket_file
)
from wazuh_testing.utils.services import control_service
from wazuh_testing.constants.aws import US_EAST_1_REGION

# Keys permanently seeded by DevOps in the shared bucket that tests must never delete.
_SEED_CLOUDTRAIL = ('AWSLogs/819751203818/CloudTrail/us-east-1/2022/11/20/'
                    '819751203818_CloudTrail_us-east-1_20221120T0000Z_372406355707169122.json')
_SEED_ELB = ('AWSLogs/819751203818/elasticloadbalancing/us-east-1/2022/11/20/'
             '819751203818_elasticloadbalancing_us-east-1_net.qatests_'
             '20221120T0000Z_1412953514070675864_29.145.39.119.log')

# Seeds DevOps keeps in the bucket: no test may ever delete them (guards _safe_delete_key and the
# stale-orphan auto-heal in _assert_prefix_clean against wiping them in a local, non-namespaced run).
_PERMANENT_SEED_KEYS = frozenset({_SEED_CLOUDTRAIL, _SEED_ELB})

# Subset mirrored into the run namespace. The ELB seed is left out on purpose: it would land in the
# elasticloadbalancing/.../2022/11/20/ prefix the alb/clb/nlb tests read and inflate their count.
_MIRRORED_SEED_KEYS = frozenset({_SEED_CLOUDTRAIL})
# VPC permanent seed is identified by this flow-log-ID substring in its S3 key.
_PERMANENT_SEED_FLOW_LOG_IDS = frozenset({'fl-0754d951c16f517fa'})

# An unexpected object at a test prefix is either a live sibling run's in-flight upload (still
# within its own job's execution window) or an orphan a prior run's cleanup never reached (a hard
# cancel skips pytest teardown; see _record_uploaded_key). The two look identical except for age.
# Longer than the largest timeout_minutes across .github/test_modules_linux.json's aws* entries
# (120 min) so a legitimate concurrent run is never mistaken for an orphan and deleted out from
# under it; comfortably shorter than "the mess just sits there until someone notices manually".
_ORPHAN_STALENESS_THRESHOLD = timedelta(hours=3)

# Per-run S3 namespace to isolate concurrent AWS IT runs on the shared bucket (issue #38194).
# Every key a run uploads - and the module's configured path - is placed under "<GITHUB_RUN_ID>/",
# so two runs executing at the same time never share keys/prefixes. Empty locally (no GITHUB_RUN_ID),
# which keeps the current bucket layout for local runs.
_RUN_ID = os.environ.get('GITHUB_RUN_ID', '')

_GUARDDUTY_SHARED_BUCKET_INCOMPATIBLE = {
    'guardduty_discard_regex',
    'guardduty_without_only_logs_after',
    'guardduty_with_only_logs_after',
    'guardduty_only_logs_after_multiple_calls',
    'guardduty_remove_from_bucket',
}


def _namespaced(path):
    """Prefix a bucket path with the per-run namespace: '<run>/<path>' in CI, '<path>' locally.

    The original path's trailing-slash semantics are preserved (only the run id is prepended): the module
    builds its base prefix as '{path}AWSLogs/' (string concat, not a path join), so an empty path must map
    to '<run>/' - WITH the trailing slash - to read '<run>/AWSLogs/...'. Stripping it would yield
    '<run>AWSLogs/' and the module would find nothing. os.path.join in generate_file tolerates either form.
    """
    path = path or ''
    if not _RUN_ID:
        return path
    return f"{_RUN_ID}/{path}"


def _copy_seeds_into_namespace(s3_client, bucket_name):
    """Mirror the permanent seeds under the per-run namespace so the module's check_bucket /
    find_account_ids see the expected AWSLogs/ structure at '<run>/AWSLogs/...'. The originals at the
    bucket root are never modified; the copies live under '<run>/' and are removed with the namespace.
    """
    if not _RUN_ID:
        return
    copied = 0
    for key in _MIRRORED_SEED_KEYS:
        try:
            s3_client.Object(bucket_name, f"{_RUN_ID}/{key}").copy_from(
                CopySource={'Bucket': bucket_name, 'Key': key})
            copied += 1
        except Exception as exc:
            # Tolerate a per-seed copy failure; the fail-fast below only triggers if nothing seeded.
            logger.warning("Could not copy seed '%s' into run namespace '%s/': %s", key, _RUN_ID, exc)
    if not copied:
        # Nothing seeded: the module's check_bucket/find_account_ids would find no AWSLogs/ structure and
        # the suite would fail with unrelated messages. Fail fast, here, instead of masking it downstream.
        raise RuntimeError(
            f"No permanent seed could be copied into run namespace '{_RUN_ID}/' "
            f"(all {len(_MIRRORED_SEED_KEYS)} failed); the namespace has no AWSLogs/ structure to read."
        )


def _delete_run_namespace(s3_client, bucket_name):
    """Delete the whole per-run namespace '<run>/' (test data + seed copies). Never touches the root."""
    if not _RUN_ID:
        return
    try:
        s3_client.Bucket(bucket_name).objects.filter(Prefix=f"{_RUN_ID}/").delete()
    except Exception as exc:
        logger.warning("Could not delete run namespace '%s/': %s", _RUN_ID, exc)


def _notif_rule_id():
    return f"wazuh-it-{_RUN_ID}"


def _rule_prefix(queue_config):
    """Return the S3 key prefix filter of a QueueConfiguration rule, or '' if it has no prefix filter."""
    for fr in queue_config.get('Filter', {}).get('Key', {}).get('FilterRules', []):
        if fr.get('Name', '').lower() == 'prefix':
            return fr.get('Value', '')
    return ''


def _prefixes_overlap(a, b):
    """S3 rejects two notification rules for the same event whose prefixes overlap (one is a prefix of the
    other). Distinct per-run '<run>/' namespaces never overlap; an empty prefix (a legacy no-filter rule)
    overlaps everything."""
    return a.startswith(b) or b.startswith(a)


def _queue_exists(sqs_client, queue_arn):
    """True if the SQS queue behind an ARN still exists. S3 validates EVERY destination on a notification
    PUT, so a single dangling destination (a queue swept after its run was hard-cancelled) rejects the
    whole config with InvalidArgument, bricking the shared bucket until someone edits it by hand."""
    if not queue_arn:
        return False
    try:
        sqs_client.get_queue_url(QueueName=queue_arn.rsplit(':', 1)[-1])
        return True
    except ClientError as exc:
        # Only a confirmed 'gone' drops a foreign rule; any other error keeps it.
        return not exc.response['Error']['Code'].endswith('NonExistentQueue')


def _merge_queue_configs(cfg, add_rule=None, sqs_client=None):
    """Rebuild a bucket notification config from an existing one: drop our own rule, any rule whose prefix
    OVERLAPS ours (a legacy no-filter rule; S3 forbids overlapping prefixes for the same event), and any
    stale per-run rule whose SQS queue no longer exists (left by a hard-cancelled run; keeping it makes
    every later PUT fail). Optionally add ours; preserve Topic/Lambda/EventBridge configs. Distinct
    '<run>/' prefixes never overlap, so concurrent runs survive."""
    rule_id = _notif_rule_id()
    own_prefix = f"{_RUN_ID}/"
    queues = []
    for q in cfg.get('QueueConfigurations', []):
        if q.get('Id') == rule_id:
            continue
        if (_prefixes_overlap(_rule_prefix(q), own_prefix)
                and any(e.startswith('s3:ObjectCreated') for e in q.get('Events', []))):
            # Only overlaps that share our event type (ObjectCreated) are what S3 rejects; a rule on a
            # different event (e.g. ObjectRemoved) is left alone.
            logger.warning("Dropping notification rule %s: prefix overlaps ours for ObjectCreated "
                           "(S3 forbids overlapping prefixes per event type)", q.get('Id'))
            continue
        if (sqs_client is not None and str(q.get('Id', '')).startswith('wazuh-it-')
                and not _queue_exists(sqs_client, q.get('QueueArn', ''))):
            logger.warning("Dropping stale notification rule %s (its SQS queue no longer exists)", q.get('Id'))
            continue
        queues.append(q)
    if add_rule:
        queues.append(add_rule)
    out = {'QueueConfigurations': queues}
    for k in ('TopicConfigurations', 'LambdaFunctionConfigurations', 'EventBridgeConfiguration'):
        if k in cfg:  # keep by presence, not truthiness: EventBridge is '{}' (falsy) when enabled
            out[k] = cfg[k]
    return out


def _rule_ids(cfg):
    return {q.get('Id') for q in cfg.get('QueueConfigurations', [])}


def _put_notification(client, bucket_name, sqs_client, want_rule=None):
    """Read-modify-write the shared bucket->SQS notification config, converging on a concurrent run's
    racing put. S3 has no conditional/ETag put here, so verify BOTH directions: our own rule landed (or
    was removed) AND every foreign rule we snapshotted is still present; if a racing put clobbered one,
    retry and the merge restores it from a fresh snapshot. This narrows but does NOT fully close the
    window - a per-run bucket or an external lock would; good enough for the handful of concurrent AWS IT
    runs. Returns True on success."""
    rule_id = _notif_rule_id()
    for attempt in range(5):
        try:
            cfg = client.get_bucket_notification_configuration(Bucket=bucket_name)
            keep = _rule_ids(_merge_queue_configs(cfg, sqs_client=sqs_client))
            client.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=_merge_queue_configs(cfg, add_rule=want_rule, sqs_client=sqs_client))
            seen = _rule_ids(client.get_bucket_notification_configuration(Bucket=bucket_name))
        except ClientError as exc:
            # A racing run can delete its queue between our GET and PUT, leaving a dangling destination
            # S3 rejects; retrying re-reads and drops it. Never fail setup/teardown on a transient error.
            logger.warning("Notification put attempt %s failed for run %s: %s", attempt, _RUN_ID, exc)
            time.sleep(1 + attempt + random.random())
            continue
        own_ok = (rule_id in seen) if want_rule else (rule_id not in seen)
        if own_ok and keep <= seen:
            return True
        time.sleep(1 + attempt + random.random())  # jitter so two runs don't lock-step
    return False


def _set_run_bucket_notification(s3_resource, bucket_name, sqs_queue_arn, sqs_client):
    """Concurrency-safe bucket->SQS notification for the custom-bucket tests (issue #38194).

    The bucket notification config is a single shared resource and the framework helper REPLACES it, so
    two concurrent runs clobber each other. Instead register THIS run's queue with a '<run>/' prefix
    filter, merged into the existing config (dropping stale rules), so each run is only notified of its
    own uploads. Locally (no run id) fall back to a plain single-queue put (original behaviour).
    """
    client = s3_resource.meta.client
    if not _RUN_ID:
        client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={'QueueConfigurations': [
                {'QueueArn': sqs_queue_arn, 'Events': ['s3:ObjectCreated:*']}]})
        return
    rule = {'Id': _notif_rule_id(), 'QueueArn': sqs_queue_arn, 'Events': ['s3:ObjectCreated:*'],
            'Filter': {'Key': {'FilterRules': [{'Name': 'prefix', 'Value': f'{_RUN_ID}/'}]}}}
    if not _put_notification(client, bucket_name, sqs_client, want_rule=rule):
        # Fail setup loudly: a missing s3:GetBucketNotification permission looks exactly like this, and
        # without the rule the test would upload, wait 30s and die on failed_sqs_message_retrieval.
        raise RuntimeError(
            f"Could not persist the bucket notification rule for run {_RUN_ID} after retries; "
            "see the preceding warnings for the AWS error.")


def _remove_run_bucket_notification(s3_resource, bucket_name, sqs_client):
    """Remove THIS run's notification rule at teardown, preserving other runs' rules (verify+retry via
    _put_notification, which also drops stale rules whose queue is gone)."""
    if not _RUN_ID:
        return
    if not _put_notification(s3_resource.meta.client, bucket_name, sqs_client, want_rule=None):
        logger.warning("Bucket notification rule for run %s may persist after teardown", _RUN_ID)


_GUARDDUTY_SHARED_BUCKET_INCOMPATIBLE = {
    'guardduty_discard_regex',
    'guardduty_without_only_logs_after',
    'guardduty_with_only_logs_after',
    'guardduty_only_logs_after_multiple_calls',
    'guardduty_remove_from_bucket',
}


def _record_uploaded_key(key):
    """Append an uploaded key to the cleanup manifest, if one is configured.

    pytest teardown only deletes the keys of its own run and only runs after 'yield', so a hard-cancelled
    CI job (e.g. a new push cancelling the in-flight run) leaves the already-uploaded files as orphans.
    Recording every key here, at upload time, lets a CI step with 'if: always()' delete them even when the
    job is cancelled before teardown. The manifest path comes from AWS_IT_CLEANUP_MANIFEST; when it is not
    set (e.g. local runs) this is a no-op and normal teardown still applies.
    """
    manifest = os.environ.get('AWS_IT_CLEANUP_MANIFEST')
    if not manifest:
        return
    try:
        with open(manifest, 'a') as handle:
            handle.write(f"{key}\n")
            handle.flush()
    except OSError as exc:
        logger.warning("Could not record uploaded key '%s' to manifest '%s': %s", key, manifest, exc)


@pytest.fixture
def record_uploaded_key():
    """Expose _record_uploaded_key to test bodies that upload objects themselves.

    manage_bucket_files records the keys it uploads, but a few tests upload directly in their body
    (e.g. test_bucket_multiple_calls). Those must register their key too, otherwise a hard cancel
    during the test would orphan the object - the exact case this cleanup targets.
    """
    return _record_uploaded_key


def _is_permanent_seed(key):
    """True if key is a permanent seed - the root seed OR its per-run namespaced copy ('<run>/<seed>')."""
    candidate = key[len(_RUN_ID) + 1:] if _RUN_ID and key.startswith(f"{_RUN_ID}/") else key
    return (candidate in _PERMANENT_SEED_KEYS
            or any(fid in key for fid in _PERMANENT_SEED_FLOW_LOG_IDS))


def _safe_delete_key(key, bucket_name, s3_client):
    """Delete one key from the shared bucket; log failures; refuse to touch permanent seeds."""
    if _is_permanent_seed(key):
        logger.warning("TEARDOWN: skipping permanent seed key: %s", key)
        return
    try:
        delete_bucket_file(filename=key, bucket_name=bucket_name, client=s3_client)
        logger.debug("TEARDOWN: deleted key: %s", key)
    except ClientError as exc:
        logger.warning("TEARDOWN: failed to delete key %s from bucket %s: %s", key, bucket_name, exc)
    except Exception as exc:
        logger.warning("TEARDOWN: failed to delete key %s from bucket %s: %s", key, bucket_name, exc)


def _assert_prefix_clean(bucket_name, key, s3_client):
    """Raise RuntimeError at setup time if any unexpected object already occupies the exact prefix level of key.

    A single list_objects_v2 scoped to the exact prefix catches future seed collisions immediately,
    rather than letting them produce a confusing count mismatch downstream.

    The listing uses Delimiter='/' so it only inspects objects that live DIRECTLY under the prefix,
    not nested sub-"folders". This matters for bucket types whose key is '<path>/<file>' (e.g.
    server_access configured with a path, giving 'test_prefix/<file>'), where key.rsplit('/', 1)[0]
    collapses to the shared '<path>/' root:
    without the delimiter the guard would also scan unrelated objects nested deeper under that root
    (e.g. the load balancers' 'test_prefix/AWSLogs/.../elasticloadbalancing/...') and raise a false
    positive. Date-partitioned types (cloudtrail, ELB, umbrella, ...) keep their files directly at the
    date-level prefix, so they are still checked exactly as before.

    For flat, root-level keys (a pathless bucket type, e.g. server_access with no path, whose key has
    no '/') the prefix is '' so the listing scopes to root-level objects only (Prefix='' + Delimiter='/'
    returns just the bucket root, and the nested permanent seeds are excluded). Without this, the prefix
    would be '<filename>/' - a prefix nothing matches - and a root-level orphan would go undetected.
    """
    prefix = key.rsplit('/', 1)[0] + '/' if '/' in key else ''
    unexpected = [
        obj for obj in s3_client.Bucket(bucket_name).objects.filter(Prefix=prefix, Delimiter='/')
        if not _is_permanent_seed(obj.key)  # root seeds and their per-run namespaced copies
        and not obj.key.endswith('/')  # skip S3 folder-marker objects (empty keys ending with /)
    ]
    if not unexpected:
        return

    now = datetime.now(timezone.utc)
    stale = [obj for obj in unexpected if now - obj.last_modified > _ORPHAN_STALENESS_THRESHOLD]
    fresh = [obj for obj in unexpected if obj not in stale]

    if not fresh:
        # Every colliding object is older than any run (including a hard-cancelled one) could
        # still be alive for -- an orphan a prior cleanup never reached, not a live sibling.
        # Self-heal instead of failing the whole run over garbage nobody's still using.
        for obj in stale:
            logger.warning(
                "SETUP: deleting stale orphan '%s' in bucket '%s' (last modified %s, older than "
                "the %s staleness threshold) before uploading '%s'.",
                obj.key, bucket_name, obj.last_modified, _ORPHAN_STALENESS_THRESHOLD, key
            )
            _safe_delete_key(obj.key, bucket_name, s3_client)
        return

    colliding = "\n".join(
        f"  {obj.key} (last modified {obj.last_modified}, "
        f"{'stale orphan' if obj in stale else 'too recent to assume orphaned'})"
        for obj in unexpected
    )
    raise RuntimeError(
        f"SETUP COLLISION: unexpected object(s) already exist at prefix '{prefix}' "
        f"in bucket '{bucket_name}' before uploading '{key}'.\n"
        f"Colliding key(s):\n{colliding}\n"
        f"At least one is within the {_ORPHAN_STALENESS_THRESHOLD} staleness threshold, so this "
        "wasn't auto-cleaned as a likely orphan -- it may belong to a concurrently running job. "
        "If it's confirmed stale, action: add the key to _PERMANENT_SEED_KEYS in conftest.py, or "
        "change 'only_logs_after' in the relevant YAML to a date past these objects."
    )


@pytest.fixture
def mark_cases_as_skipped(metadata):
    if metadata['name'] in ['alb_remove_from_bucket', 'clb_remove_from_bucket', 'nlb_remove_from_bucket']:
        pytest.skip(reason='ALB, CLB and NLB integrations are removing older logs from other region')
    if metadata['name'] in _GUARDDUTY_SHARED_BUCKET_INCOMPATIBLE:
        pytest.skip(
            reason=(
                'GuardDuty Kinesis test data is incompatible with the shared bucket: '
                'check_guardduty_type() always returns GuardDutyNative because the shared bucket '
                'contains permanent AWSLogs/ seeds. These cases do not exist in the 5.x branch.'
            )
        )


"""Boto3 client fixtures"""
# Use the environment variable or default to 'dev'
aws_profile = os.environ.get("AWS_PROFILE", "default")


@pytest.fixture()
def boto_session():
    """Create a boto3 Session using the system defined AWS profile."""
    return boto3.Session(profile_name=f'{aws_profile}')


@pytest.fixture()
def s3_client(boto_session: boto3.Session):
    """Create an S3 client to manage bucket resources.

    Args:
        boto_session (boto3.Session): Session used to create the client.

    Returns:
        boto3.resources.base.ServiceResource: S3 client to manage bucket resources.
    """
    return boto_session.resource(service_name="s3", region_name=US_EAST_1_REGION)


@pytest.fixture()
def ec2_client(boto_session: boto3.Session):
    """Create an EC2 client to manage VPC resources.

    Args:
        boto_session (boto3.Session): Session used to create the client.

    Returns:
        Service client instance: EC2 client to manage VPC resources.
    """
    return boto_session.client(service_name="ec2", region_name=US_EAST_1_REGION)


@pytest.fixture()
def logs_clients(boto_session: boto3.Session, metadata: dict):
    """Create CloudWatch Logs clients per region to manage CloudWatch resources.

    Args:
        boto_session (boto3.Session): Session used to create the client.
        metadata (dict): Metadata from the module to obtain the defined regions.

    Returns:
        list(Service client instance): CloudWatch client list to manage the service's resources in multiple regions.
    """
    # A client for each region is required to generate logs accordingly
    return [boto_session.client(service_name="logs", region_name=region)
            for region in metadata.get('regions', US_EAST_1_REGION).split(',')]


@pytest.fixture()
def sqs_client(boto_session: boto3.Session):
    """Create an SQS client to manage queues.

    Args:
        boto_session (boto3.Session): Session used to create the client.

    Returns:
        Service client instance: SQS client to manage the queue resources.
    """
    return boto_session.client(service_name="sqs", region_name=US_EAST_1_REGION)


"""Session fixtures"""


@pytest.fixture()
def buckets_manager(s3_client):
    """Initializes a set to manage the creation and deletion of the buckets used throughout the test session.

    Args:
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage the bucket resources.

    Yields:
        buckets (set): Set of buckets.
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage the bucket resources.
    """
    # Create buckets set
    buckets: set = set()

    yield buckets, s3_client

    # Delete all buckets created during execution
    for bucket in buckets:
        try:
            # Delete the bucket
            delete_bucket(bucket_name=bucket, client=s3_client)
        except ClientError as error:
            logger.error({
                "message": "Client error deleting bucket, delete manually",
                "resource_name": bucket,
                "error": str(error)
            })

        except Exception as error:
            logger.error({
                "message": "Broad error deleting bucket, delete manually",
                "resource_name": bucket,
                "error": str(error)
            })


@pytest.fixture()
def log_groups_manager(logs_clients):
    """Initializes a set to manage the creation and deletion of the log groups used throughout the test session.

    Args:
        logs_clients (list(Service client instance)): CloudWatch Logs client list to manage the CloudWatch resources.

    Yields:
        log_groups (set): Set of log groups.
        logs_clients (list(Service client instance)): CloudWatch Logs client list to manage the CloudWatch resources.
    """
    # Create log groups set
    log_groups: set = set()

    yield log_groups, logs_clients

    # Delete all resources created during execution
    for log_group in log_groups:
        try:
            for logs_client in logs_clients:
                delete_log_group(log_group_name=log_group, client=logs_client)
        except ClientError as error:
            logger.error({
                "message": "Client error deleting log_group, delete manually",
                "resource_name": log_group,
                "error": str(error)
            })
            raise error

        except Exception as error:
            logger.error({
                "message": "Broad error deleting log_group, delete manually",
                "resource_name": log_group,
                "error": str(error)
            })
            raise error


@pytest.fixture()
def sqs_manager(sqs_client):
    """Initializes a set to manage the creation and deletion of the sqs queues used throughout the test session.

    Args:
        sqs_client (Service client instance): SQS client to manage the SQS resources.

    Yields:
        sqs_queues (set): Set of SQS queues.
        sqs_client (Service client instance): SQS client to manage the SQS resources.
    """
    # Create buckets set
    sqs_queues: set = set()

    yield sqs_queues, sqs_client

    # Delete all resources created during execution
    for sqs in sqs_queues:
        try:
            delete_sqs_queue(sqs_queue_url=sqs, client=sqs_client)
        except ClientError as error:
            logger.error({
                "message": "Client error deleting sqs queue, delete manually",
                "resource_name": sqs,
                "error": str(error)
            })

        except Exception as error:
            logger.error({
                "message": "Broad error deleting sqs queue, delete manually",
                "resource_name": sqs,
                "error": str(error)
            })


"""S3 fixtures"""


@pytest.fixture()
def test_configuration() -> dict:
    """Fallback for tests that do not parametrize test_configuration (e.g. multiple-calls tests).
    Parametrize overrides this fixture, so tests that do supply test_configuration still work.
    """
    return {}


@pytest.fixture(scope='session', autouse=True)
def aws_run_namespace(request):
    """Isolate this run under '<GITHUB_RUN_ID>/' on the shared bucket (issue #38194).

    Mirrors the permanent seeds into the namespace at session start so the module's check_bucket /
    find_account_ids find the AWSLogs/ structure under '<run>/', and deletes the whole namespace at the
    end. No-op locally (no GITHUB_RUN_ID). Uses its own S3 resource because it is session-scoped.
    """
    bucket = os.environ.get('AWS_BUCKET_NAME')
    # Matrix jobs share GITHUB_RUN_ID and the 'test_aws/' target (aws vs aws_inspector, split by -k), so a
    # session may run no bucket test at all (e.g. inspector). Skipping those keeps that session from
    # deleting the namespace out from under a sibling job still using it.
    needs_bucket = any('create_test_bucket' in i.fixturenames for i in request.session.items)
    if not _RUN_ID or not bucket or not needs_bucket:
        yield
        return
    profile = os.environ.get('AWS_PROFILE', 'default')
    s3 = boto3.Session(profile_name=profile).resource(service_name='s3', region_name=US_EAST_1_REGION)
    _copy_seeds_into_namespace(s3, bucket)
    yield
    _delete_run_namespace(s3, bucket)


@pytest.fixture()
def create_test_bucket(metadata: dict, test_configuration: dict, aws_run_namespace):
    """Use a pre-existing S3 bucket for tests.

    Args:
        metadata (dict): Bucket information.
        test_configuration (dict): Wazuh configuration template built at import time.
            Patched in-place so set_wazuh_configuration writes the shared bucket into ossec.conf.
        aws_run_namespace: ensures the per-run namespace (seeds) is set up before the test.
    """
    shared_bucket = os.environ.get('AWS_BUCKET_NAME')
    if not shared_bucket:
        raise EnvironmentError(
            "AWS_BUCKET_NAME is not set. A pre-existing S3 bucket is required. "
            "Set the IT_AWS_BUCKET_NAME GitHub secret."
        )
    # Preserve the original YAML bucket name so generate_file can resolve custom bucket types
    # (kms, macie, trusted_advisor) via bucket_name.split('-')[1] inside get_data_generator.
    metadata['original_bucket_name'] = metadata.get('bucket_name', shared_bucket)
    # Override so all S3 operations and the Wazuh module CLI use the shared bucket.
    metadata['bucket_name'] = shared_bucket

    # Namespace the bucket path under the per-run prefix so concurrent runs never share keys. The
    # uploaded keys (via manage_bucket_files -> generate_file) and the module's configured <path> both
    # use this value, so they stay aligned. No-op locally.
    namespaced_path = _namespaced(metadata.get('path', ''))
    # Only mutate metadata['path'] when a run namespace is active; otherwise (local, no GITHUB_RUN_ID)
    # leave it untouched so path-less cases keep no 'path' key and the tests don't emit a spurious
    # --trail_prefix "" that the module (empty path) never logs.
    if _RUN_ID:
        metadata['path'] = namespaced_path

    # Patch test_configuration so set_wazuh_configuration writes the shared bucket into ossec.conf.
    # Without this, ossec.conf keeps the YAML name (plus the session suffix added by _modify_metadata),
    # causing a mismatch with metadata['bucket_name'] and triggering incorrect_parameters failures.
    for section in test_configuration.get('sections', []):
        for element in section.get('elements', []):
            bucket_cfg = element.get('bucket')
            if isinstance(bucket_cfg, dict):
                bucket_elements = bucket_cfg.setdefault('elements', [])
                path_found = False
                for bucket_elem in bucket_elements:
                    if 'name' in bucket_elem:
                        bucket_elem['name']['value'] = shared_bucket
                    if 'path' in bucket_elem:
                        bucket_elem['path']['value'] = namespaced_path
                        path_found = True
                # A path-less bucket type (reads the bucket root) needs an explicit <path> so the
                # module reads under the run namespace instead of the shared root.
                if _RUN_ID and not path_found:
                    bucket_elements.append({'path': {'value': namespaced_path}})


@pytest.fixture
def manage_bucket_files(metadata: dict, s3_client, ec2_client, create_test_bucket):
    """Upload a file to S3 bucket and delete after the test ends.

    Args:
        metadata (dict): Metadata to get the parameters.
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage the bucket resources.
        ec2_client (Service client instance): EC2 client to manage VPC resources.
    """
    bucket_name = metadata['bucket_name']
    bucket_type = metadata['bucket_type']
    file_creation_date = metadata.get('only_logs_after')
    regions = metadata.get('regions', US_EAST_1_REGION).split(',')
    prefix = metadata.get('path', '')
    suffix = metadata.get('path_suffix', '')
    vpc_bucket = bucket_type == 'vpcflow'
    log_number = metadata.get("expected_results", 1) > 0

    # Use the original YAML bucket name for generate_file — the framework derives the
    # custom type (kms/macie/trusted) from bucket_name.split('-')[1], which breaks with
    # the shared bucket name. All actual S3 operations still use the shared bucket_name.
    data_bucket_name = metadata.get('original_bucket_name', bucket_name)
    uploaded_keys = []
    if log_number:
        files_to_upload = []
        metadata['uploaded_file'] = ''
        flow_log_id = None
        flow_log_owned = False
        try:
            if vpc_bucket:
                vpc_id = os.environ.get('AWS_VPC_ID')
                if not vpc_id:
                    raise EnvironmentError(
                        "AWS_VPC_ID is not set. A pre-existing VPC ID is required "
                        "for VPC flow log tests. Set the IT_AWS_VPC_ID GitHub secret."
                    )
                # Per-run destination (issue #38194): garbage falls under '<run>/' so _delete_run_namespace
                # removes it, and the dedup key (VPC, traffic type, destination) becomes unique per run so
                # concurrent runs no longer collide with FlowLogAlreadyExists. '_flowlogs/' keeps it out of
                # '<run>/AWSLogs/...' where the module reads. Root destination locally (no run id).
                log_destination = (f'arn:aws:s3:::{bucket_name}/{_RUN_ID}/_flowlogs/'
                                   if _RUN_ID else f'arn:aws:s3:::{bucket_name}')
                try:
                    response = ec2_client.create_flow_logs(
                        ResourceIds=[vpc_id],
                        ResourceType='VPC',
                        TrafficType='REJECT',
                        LogDestinationType='s3',
                        LogDestination=log_destination
                    )
                    unsuccessful = response.get('Unsuccessful', [])
                    if unsuccessful:
                        err = unsuccessful[0]['Error']
                        if err['Code'] == 'FlowLogAlreadyExists':
                            raise ClientError({'Error': err}, 'CreateFlowLogs')
                        raise RuntimeError(
                            f"Failed to create VPC flow log on {vpc_id}: "
                            f"[{err['Code']}] {err['Message']}"
                        )
                    flow_log_id = response['FlowLogIds'][0]
                    flow_log_owned = True
                except ClientError as fl_error:
                    if fl_error.response['Error']['Code'] != 'FlowLogAlreadyExists':
                        raise
                    existing = ec2_client.describe_flow_logs(
                        Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])
                    flow_logs = existing.get('FlowLogs', [])
                    if not flow_logs:
                        raise
                    flow_log_id = flow_logs[0]['FlowLogId']
                metadata['flow_log_id'] = flow_log_id
                for region in regions:
                    data, key = generate_file(bucket_type=bucket_type,
                                              bucket_name=data_bucket_name,
                                              date=file_creation_date,
                                              region=region,
                                              prefix=prefix,
                                              suffix=suffix,
                                              flow_log_id=flow_log_id)
                    files_to_upload.append((data, key))
            else:
                for region in regions:
                    data, key = generate_file(bucket_type=bucket_type,
                                              bucket_name=data_bucket_name,
                                              region=region,
                                              prefix=prefix,
                                              suffix=suffix,
                                              date=file_creation_date)
                    files_to_upload.append((data, key))

            for _, key in files_to_upload:
                _assert_prefix_clean(bucket_name, key, s3_client)

            for data, key in files_to_upload:
                # Record the key BEFORE uploading so a cancelled job can still clean it up.
                _record_uploaded_key(key)
                upload_bucket_file(bucket_name=bucket_name,
                                   data=data,
                                   key=key,
                                   client=s3_client)
                logger.debug('Uploaded file: %s to bucket "%s"', key, bucket_name)
                metadata['uploaded_file'] += key
                uploaded_keys.append(key)

        except ClientError as error:
            logger.error({
                "message": "Client error uploading file to bucket",
                "bucket_name": bucket_name,
                "error": str(error)
            })
            if flow_log_owned and flow_log_id is not None:
                try:
                    ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
                except Exception:
                    pass
            raise error

        except Exception as error:
            logger.error({
                "message": "Broad error uploading file to bucket",
                "bucket_name": bucket_name,
                "error": str(error)
            })
            if flow_log_owned and flow_log_id is not None:
                try:
                    ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
                except Exception:
                    pass
            raise error

    yield

    if log_number:
        # Collect every key this fixture or the test body uploaded.
        all_keys = list(uploaded_keys)
        extra_key = metadata.get('filename')
        if extra_key and extra_key not in uploaded_keys:
            all_keys.append(extra_key)

        for key in all_keys:
            _safe_delete_key(key, bucket_name, s3_client)

        if vpc_bucket and flow_log_owned and flow_log_id is not None:
            try:
                ec2_client.delete_flow_logs(FlowLogIds=[flow_log_id])
            except Exception as exc:
                logger.warning("TEARDOWN: failed to delete flow log %s: %s", flow_log_id, exc)


"""CloudWatch fixtures"""


@pytest.fixture()
def create_test_log_group(log_groups_manager,
                          metadata: dict) -> None:
    """Create a log group.

    Args:
        log_groups_manager (tuple): Log groups set and CloudWatch clients.
        metadata (dict): Log group information.
    """
    # Get log group names
    log_group_names = metadata["log_group_name"].split(',')

    # If the resource_type is defined, then the resource must be created
    resource_creation = 'resource_type' in metadata

    log_groups, logs_clients = log_groups_manager

    try:
        if resource_creation:
            # Create log group
            for log_group in log_group_names:
                for logs_client in logs_clients:
                    create_log_group(log_group_name=log_group, client=logs_client)
                    logger.debug(f"Created log group: {log_group}")

                # Append created log group to resource list
                log_groups.add(log_group)

    except ClientError as error:
        logger.error({
            "message": "Client error creating log group",
            "log_group": log_group,
            "error": str(error)
        })
        raise

    except Exception as error:
        logger.error({
            "message": "Broad error creating log group",
            "log_group": log_group,
            "error": str(error)
        })
        raise


@pytest.fixture()
def create_test_log_stream(metadata: dict, log_groups_manager) -> None:
    """Create a log stream.

    Args:
        metadata (dict): Log group information.
        log_groups_manager (tuple): Log groups set and CloudWatch clients.
    """
    # Get log group names
    log_group_names = metadata["log_group_name"].split(',')

    # Get log stream
    log_stream_name = metadata['log_stream_name']

    # If the resource_type is defined, then the resource must be created
    resource_creation = 'resource_type' in metadata

    _, logs_clients = log_groups_manager

    try:
        if resource_creation:
            # Create log stream for each log group defined
            for log_group in log_group_names:
                for logs_client in logs_clients:
                    create_log_stream(log_group=log_group,
                                      log_stream=log_stream_name,
                                      client=logs_client)
                    logger.debug(f'Created log stream {log_stream_name} within log group {log_group}')

    except ClientError as error:
        logger.error({
            "message": "Client error creating log stream",
            "log_group": log_group,
            "error": str(error)
        })
        raise

    except Exception as error:
        logger.error({
            "message": "Broad error creating log stream",
            "log_group": log_group,
            "error": str(error)
        })
        raise


def _wait_for_log_events(logs_client, log_group, log_stream, expected_events, timeout=60, interval=3):
    """Wait until the uploaded events are queryable through the CloudWatch Logs API.

    PutLogEvents is eventually consistent: the events are not immediately returned by
    filter_log_events. The AWS module queries CloudWatch only once at startup, so if the
    events have not propagated yet it reads 0 of them and the test times out waiting for
    the expected message. Poll until the expected number of events is visible (or until
    the timeout elapses) so the module always sees the data.

    Args:
        logs_client: boto3 CloudWatch Logs client.
        log_group (str): Log group to query.
        log_stream (str): Log stream to query.
        expected_events (int): Minimum number of events that must be visible.
        timeout (int): Maximum time to wait, in seconds.
        interval (int): Delay between polls, in seconds.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = logs_client.filter_log_events(logGroupName=log_group, logStreamNames=[log_stream])
            if len(response.get('events', [])) >= expected_events:
                return
        except ClientError as error:
            logger.debug(f"filter_log_events not ready yet for '{log_group}': {error}")
        time.sleep(interval)

    logger.warning(f"Timed out ({timeout}s) waiting for {expected_events} events to become queryable in "
                   f"'{log_group}/{log_stream}'")


@pytest.fixture
def manage_log_group_events(metadata: dict, logs_clients):
    """Upload events to a log stream inside a log group and delete the log stream after the test ends.

    Args:
        metadata (dict): Metadata to get the parameters.
        logs_clients (list(Service client instance)): CloudWatch Logs client list to manage the CloudWatch resources.
    """
    # Get log group names
    log_group_names = metadata["log_group_name"].split(',')

    # Get log stream name
    log_stream_name = metadata["log_stream_name"]

    # Get number of events
    event_number = metadata.get("expected_results", 1)

    # If the resource_type is defined, then the resource must be created
    resource_creation = 'resource_type' in metadata

    try:
        if resource_creation:
            log_creation_date = metadata.get('only_logs_after')
            for log_group in log_group_names:
                for logs_client in logs_clients:
                    # Create log events in log group
                    upload_log_events(
                        log_stream=log_stream_name,
                        log_group=log_group,
                        date=log_creation_date,
                        type_json='discard_field' in metadata,
                        events_number=event_number,
                        client=logs_client
                    )
                    # Wait for the events to be queryable before the module runs, otherwise
                    # CloudWatch eventual consistency can make the module read 0 events (flaky).
                    _wait_for_log_events(logs_client, log_group, log_stream_name, event_number)

    except ClientError as error:
        logger.error({
            "message": "Client error uploading events to log stream",
            "log_group": log_group,
            "log_stream_name": log_stream_name,
            "error": str(error)
        })
        raise error

    except Exception as error:
        logger.error({
            "message": "Broad error uploading events to log stream",
            "log_group": log_group,
            "log_stream_name": log_stream_name,
            "error": str(error)
        })
        raise error

    yield


"""SQS fixtures"""


@pytest.fixture
def set_test_sqs_queue(metadata: dict, sqs_manager, s3_client, create_test_bucket) -> None:
    """Create a test SQS queue.

    Args:
        metadata (dict): The metadata for the SQS queue.
        sqs_manager (fixture): The SQS set for the test.
        s3_client (boto3.resources.base.ServiceResource): S3 client used to manage bucket resources.
    """
    bucket_name = metadata["bucket_name"]
    # The queue name is already unique per run: configurator._modify_metadata appends a random per-session
    # '-<uuid>-todelete' suffix, so concurrent runs never share a queue. (Do NOT append GITHUB_RUN_ID here:
    # it would land after '-todelete' and fall outside the IAM policy's allowed queue-name pattern.) The
    # cross-run collision that issue #38194 fixes is the bucket notification, handled below.
    sqs_name = metadata["sqs_name"]

    sqs_queues, sqs_client = sqs_manager

    try:
        sqs_queue_url = create_sqs_queue(sqs_name=sqs_name, client=sqs_client)
        sqs_queues.add(sqs_queue_url)
        sqs_queue_arn = get_sqs_queue_arn(sqs_url=sqs_queue_url, client=sqs_client)
        set_sqs_policy(bucket_name=bucket_name,
                       sqs_queue_url=sqs_queue_url,
                       sqs_queue_arn=sqs_queue_arn,
                       client=sqs_client)
        _set_run_bucket_notification(s3_client, bucket_name, sqs_queue_arn, sqs_client)

    except ClientError as error:
        if error.response['Error']['Code'] == 'ResourceNotFound':
            logger.error(f"SQS Queue {sqs_name} already exists")
            raise error
        else:
            raise error

    except Exception as error:
        raise error

    yield

    # Remove only this run's notification rule so a concurrent run's rule survives.
    _remove_run_bucket_notification(s3_client, bucket_name, sqs_client)


"""DB fixtures"""


@pytest.fixture
def clean_s3_cloudtrail_db():
    """Delete the DB file before and after the test execution."""
    delete_s3_db()

    yield

    delete_s3_db()


@pytest.fixture
def clean_aws_services_db():
    """Delete the DB file before and after the test execution."""
    delete_services_db()

    yield

    delete_services_db()
