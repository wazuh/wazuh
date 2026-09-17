#!/usr/bin/env python3
"""
bench_samples.py — the manager_benchmark sample format: write it, read it, project it.

One NDJSON file (``samples/metrics.ndjson``) holds every daemon's ``/metrics`` scrape for
a run, losslessly and self-describing, and every flat or wide shape a consumer wants is
DERIVED from it at read time.

Why this exists
---------------
The collectors used to own a hand-maintained wide CSV header per daemon. A metric that
was not in the table was dropped; a metric in the table but absent from the dump was
written as a literal ``0``; and the whole untouched response was appended to every row as
``raw_response_json`` -- 83-88% of each file, read by nothing. The column set also drifted
with every instrumented change, so two runs of different vintages stopped lining up.

The split here is the fix: collection is lossless and schema-free, presentation is a
projection. The alias tables below moved OUT of the collector for exactly that reason.
They are no longer a filter that destroys what it does not name -- only a rename applied
when a consumer asks for short column names. A metric nobody has aliased yet is still in
the data, under its own name.

File format
-----------
Line-delimited JSON, one object per line, appended in scrape order and never rewritten.

  {"kind":"meta","src":"inventory-sync","socket":"/var/...","types":{"sync.docs.indexed":"counter",...}}
  {"ts":"2026-08-25T13:40:52Z","t":12.0,"src":"inventory-sync","ok":true,
   "m":{"sync.docs.indexed":1234,...},"h":{"vd.lane.time":{"count":9,"p99":150994944},...}}
  {"ts":"2026-08-25T13:40:53Z","t":13.0,"src":"inventory-sync","ok":false,"err":"connection refused"}

  ts   ISO-8601 UTC wall clock            t    seconds since the collector started
  src  which daemon (see SOURCES)         ok   whether the scrape answered
  m    metric name -> value, the module's OWN dotted names, no mangling
  h    metric name -> histogram summary ({count,sum,min,max,p50,p90,p99})
  err  present only when ok is false

A metric absent from a dump is ABSENT from ``m``. It is not zero: "this build does not
register it" and "this counter has not moved" are different facts, and the format keeps
them different -- the old wide CSV could not, and answered 0 to both. The ``meta`` line is
emitted once per source, on its first successful scrape, so a reader learns each metric's
type without a second source of truth.

Sources may interleave: four collector threads append to one file, so read with
``read_samples(path, src=...)`` rather than assuming the file is one daemon's.

Runs also accumulate. The file is opened in append mode and ``run_benchmark.sh`` reuses
``results_<label>/`` when a label is reused, so one file can hold several runs. Every line
carries ``r``, the id of the run that produced it, and each run opens with a ``run``
marker; ``read_samples`` returns only the LAST run by default, and ``run="all"`` asks for
the whole file.

That id is not a convenience. The charts used to recover a run boundary by looking for the
point where ``elapsed_s`` jumps backwards, and the summary did not look at all -- so a
reused label gave a delta over two runs in summary.json and a delta over one in the charts,
for the same file. The heuristic cannot be repaired either: four sources interleave here,
so ``elapsed_s`` is not monotonic in file order even within a single run.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Callable

# The run's sample file, relative to the samples directory run_benchmark.sh creates.
SAMPLES_FILENAME = "metrics.ndjson"

# Histogram summary fields promoted to their own aliased columns. The dump carries more
# (`sum`, `min`); they stay reachable under their raw names in a projection.
HIST_FIELDS: tuple[str, ...] = ("count", "p50", "p90", "p99", "max")


# ---------------------------------------------------------------------------
# Alias tables — metric name in the dump -> short column name
#
# Read-side only. Adding a metric to a module does NOT require touching these: the metric
# reaches the samples file, the summary and a projection under its own dotted name either
# way. An entry here only buys a short column name and whatever chart is keyed on it.
# ---------------------------------------------------------------------------

# inventory_sync_server, GET /metrics on its own UDS socket. The route is budget-exempt on
# purpose, so it keeps answering while the module sheds real traffic -- which is exactly
# when these numbers matter.
#
# The per-shard gauges (sync.shard.<i>.{depth,bytes}) get no alias: how many there are
# follows the configured worker count, so aliasing them would make two machines'
# projections differ in width. They are aggregated into shard_* below AND, unlike before,
# survive individually in the samples file under their own names.
INVSYNC_SCALARS: tuple[tuple[str, str], ...] = (
    ("sync.requests.total.200", "requests_200"),
    ("sync.requests.total.400", "requests_400"),
    ("sync.requests.total.403", "requests_403"),
    ("sync.requests.total.409", "requests_409"),
    ("sync.requests.total.500", "requests_500"),
    ("sync.requests.total.503", "requests_503"),
    ("sync.requests.total.other", "requests_other"),
    ("sync.docs.indexed", "docs_indexed"),
    ("sync.docs.skipped", "docs_skipped"),
    ("sync.bytes.ingested", "bytes_ingested"),
    ("sync.pipeline.shed.total", "pipeline_shed_total"),
    ("sync.bulk.flushes", "bulk_flushes"),
    ("sync.bulk.sessions.total", "bulk_sessions_total"),
    ("sync.bulk.bytes.total", "bulk_bytes_total"),
    ("vd.lane.depth", "vd_lane_depth"),
    ("vd.scans.ok", "vd_scans_ok"),
    ("vd.scans.failed", "vd_scans_failed"),
    ("vd.scans.skipped", "vd_scans_skipped"),
    ("vd.capacity.503.total", "vd_capacity_503_total"),
    ("vd.retry_after.total", "vd_retry_after_total"),
    ("vd.offset_mismatch.total", "vd_offset_mismatch_total"),
    # Transport diagnostics of the shared UDS server itself: a snapshot of the in-flight
    # byte budget and of how many connections each route class is holding. These say WHY a
    # session was shed -- budget exhausted vs a class at its cap -- and are instantaneous
    # levels (dump type "pull"), not counters, so read them as levels rather than growth.
    ("server.budget.available.bytes", "server_budget_available_bytes"),
    ("server.budget.inflight.bytes", "server_budget_inflight_bytes"),
    ("server.budget.inflight.requests", "server_budget_inflight_requests"),
    ("server.sessions.live", "server_sessions_live"),
    ("server.sessions.data", "server_sessions_data"),
    ("server.sessions.control", "server_sessions_control"),
    ("server.sessions.liveness", "server_sessions_liveness"),
)

# Histogram values are microseconds (see the module's metricNames.hpp).
INVSYNC_HISTOGRAMS: tuple[tuple[str, str], ...] = (
    ("sync.session.duration.bulk", "session_duration_bulk"),
    ("sync.session.duration.immediate", "session_duration_immediate"),
    ("vd.lane.time", "vd_lane_time"),
    ("vd.scan.duration", "vd_scan_duration"),
)

# remoted_module's registry, served by GET /metrics on the admin socket. Cumulative counters
# unless a comment says otherwise (the *.server.* transport blocks and the level-style pulls
# are instantaneous gauges -- read them as levels, not growth).
#
# The scanvd family is admission-only: remoted is a synchronous passthrough of VD's admission,
# so a request either came back 200 (accepted = VD queued it and WILL run it) or an honest 503
# (queue_full = VD's lane at capacity, indexer_unavailable = VD reports no healthy indexer
# host, vd_error = anything else). What became of an accepted
# scan is VD's to report -- the sender's scan_200/scan_503 columns now mean the same thing this
# family does, which is the whole point of the redesign.
#
# The http_<endpoint>_responses_* blocks share one closed status vocabulary across the four
# forwarded endpoints so their columns line up; some cells are structurally zero for a given
# endpoint (e.g. /stateless never answers 409, and 429 only ever moves on /enroll and /cacerts,
# the two rate-limited routes) -- kept for symmetry, like the admin lanes.
# Budget sheds never reach those cells (they are refused before any route runs); they are
# server_budget_rejected_total's alone. A deferred-limiter shed counts BOTH as the endpoint's
# 503 and in forwarder_deferred_rejected_total, and a rate-limit refusal counts BOTH as the
# endpoint's 429 and in <endpoint>_rate_limited even though the handler never ran.
REMOTED_MODULE_SCALARS: tuple[tuple[str, str], ...] = (
    ("remoted.control.startup", "control_startup"),
    ("remoted.control.notify", "control_notify"),
    ("remoted.control.shutdown", "control_shutdown"),
    ("remoted.control.wdb_error", "control_wdb_error"),
    ("remoted.control.task_fetch", "control_task_fetch"),
    ("remoted.control.task_fetch_error", "control_task_fetch_error"),
    ("remoted.control.rejected", "control_rejected"),
    ("remoted.control.registry.agents", "control_registry_agents"),  # level
    ("remoted.scanvd.requests.total", "scanvd_requests_total"),
    ("remoted.scanvd.accepted", "scanvd_accepted"),
    ("remoted.scanvd.queue_full", "scanvd_queue_full"),
    ("remoted.scanvd.version_mismatch", "scanvd_version_mismatch"),
    ("remoted.scanvd.invalid_agent", "scanvd_invalid_agent"),
    ("remoted.scanvd.vd_error", "scanvd_vd_error"),
    ("remoted.scanvd.indexer_unavailable", "scanvd_indexer_unavailable"),
    # Auth-gateway rejection taxonomy: the PRE-collapse cause of every client-visible auth
    # rejection (the wire response deliberately folds the credential failures into one 401).
    ("remoted.auth.reject.unknown_agent", "auth_reject_unknown_agent"),
    ("remoted.auth.reject.invalid_signature", "auth_reject_invalid_signature"),
    ("remoted.auth.reject.bad_token", "auth_reject_bad_token"),
    ("remoted.auth.reject.identity_mismatch", "auth_reject_identity_mismatch"),
    ("remoted.auth.reject.clock_skew", "auth_reject_clock_skew"),
    ("remoted.auth.reject.unusable_key", "auth_reject_unusable_key"),
    ("remoted.auth.reject.address_not_allowed", "auth_reject_address_not_allowed"),
    ("remoted.auth.reject.enrollment_key_unavailable", "auth_reject_enrollment_key_unavailable"),
    ("remoted.auth.reject.payload_mismatch", "auth_reject_payload_mismatch"),
    ("remoted.auth.reject.body_too_large", "auth_reject_body_too_large"),
    ("remoted.auth.reject.bad_encoding", "auth_reject_bad_encoding"),
    ("remoted.auth.reject.malformed", "auth_reject_malformed"),
    ("remoted.auth.reject.token_unknown", "auth_reject_token_unknown"),
    ("remoted.auth.reject.token_expired", "auth_reject_token_expired"),
    ("remoted.auth.reject.token_revoked", "auth_reject_token_revoked"),
    # Keystore health: agents and entries_skipped are levels, the totals are cumulative.
    ("remoted.auth.keystore.agents", "keystore_agents"),
    ("remoted.auth.keystore.entries_skipped", "keystore_entries_skipped"),
    ("remoted.auth.keystore.reloads.total", "keystore_reloads_total"),
    ("remoted.auth.keystore.reload_failures.total", "keystore_reload_failures_total"),
    # Per-endpoint response outcomes ("what the agent got"), one closed set x four endpoints.
    ("remoted.http.stateless.responses.2xx", "http_stateless_responses_2xx"),
    ("remoted.http.stateless.responses.400", "http_stateless_responses_400"),
    ("remoted.http.stateless.responses.403", "http_stateless_responses_403"),
    ("remoted.http.stateless.responses.409", "http_stateless_responses_409"),
    ("remoted.http.stateless.responses.413", "http_stateless_responses_413"),
    ("remoted.http.stateless.responses.429", "http_stateless_responses_429"),
    ("remoted.http.stateless.responses.500", "http_stateless_responses_500"),
    ("remoted.http.stateless.responses.503", "http_stateless_responses_503"),
    ("remoted.http.stateless.responses.other", "http_stateless_responses_other"),
    ("remoted.http.stateful.responses.2xx", "http_stateful_responses_2xx"),
    ("remoted.http.stateful.responses.400", "http_stateful_responses_400"),
    ("remoted.http.stateful.responses.403", "http_stateful_responses_403"),
    ("remoted.http.stateful.responses.409", "http_stateful_responses_409"),
    ("remoted.http.stateful.responses.413", "http_stateful_responses_413"),
    ("remoted.http.stateful.responses.429", "http_stateful_responses_429"),
    ("remoted.http.stateful.responses.500", "http_stateful_responses_500"),
    ("remoted.http.stateful.responses.503", "http_stateful_responses_503"),
    ("remoted.http.stateful.responses.other", "http_stateful_responses_other"),
    ("remoted.http.stats.responses.2xx", "http_stats_responses_2xx"),
    ("remoted.http.stats.responses.400", "http_stats_responses_400"),
    ("remoted.http.stats.responses.403", "http_stats_responses_403"),
    ("remoted.http.stats.responses.409", "http_stats_responses_409"),
    ("remoted.http.stats.responses.413", "http_stats_responses_413"),
    ("remoted.http.stats.responses.429", "http_stats_responses_429"),
    ("remoted.http.stats.responses.500", "http_stats_responses_500"),
    ("remoted.http.stats.responses.503", "http_stats_responses_503"),
    ("remoted.http.stats.responses.other", "http_stats_responses_other"),
    ("remoted.http.config.responses.2xx", "http_config_responses_2xx"),
    ("remoted.http.config.responses.400", "http_config_responses_400"),
    ("remoted.http.config.responses.403", "http_config_responses_403"),
    ("remoted.http.config.responses.409", "http_config_responses_409"),
    ("remoted.http.config.responses.413", "http_config_responses_413"),
    ("remoted.http.config.responses.429", "http_config_responses_429"),
    ("remoted.http.config.responses.500", "http_config_responses_500"),
    ("remoted.http.config.responses.503", "http_config_responses_503"),
    ("remoted.http.config.responses.other", "http_config_responses_other"),
    # POST /enroll: same closed set as the four above. Not forwarded (its downstream is authd),
    # so these are counted by the handler's MeteredResponder wrapper.
    ("remoted.http.enroll.responses.2xx", "http_enroll_responses_2xx"),
    ("remoted.http.enroll.responses.400", "http_enroll_responses_400"),
    ("remoted.http.enroll.responses.403", "http_enroll_responses_403"),
    ("remoted.http.enroll.responses.409", "http_enroll_responses_409"),
    ("remoted.http.enroll.responses.413", "http_enroll_responses_413"),
    ("remoted.http.enroll.responses.429", "http_enroll_responses_429"),
    ("remoted.http.enroll.responses.500", "http_enroll_responses_500"),
    ("remoted.http.enroll.responses.503", "http_enroll_responses_503"),
    ("remoted.http.enroll.responses.other", "http_enroll_responses_other"),
    # GET /cacerts (CA distribution): the one GET route, unauthenticated and body-less, so it is
    # the listener's fixed per-request cost floor. Its 404 (no CA file) lands in `other`.
    ("remoted.http.cacerts.responses.2xx", "http_cacerts_responses_2xx"),
    ("remoted.http.cacerts.responses.400", "http_cacerts_responses_400"),
    ("remoted.http.cacerts.responses.403", "http_cacerts_responses_403"),
    ("remoted.http.cacerts.responses.409", "http_cacerts_responses_409"),
    ("remoted.http.cacerts.responses.413", "http_cacerts_responses_413"),
    ("remoted.http.cacerts.responses.429", "http_cacerts_responses_429"),
    ("remoted.http.cacerts.responses.500", "http_cacerts_responses_500"),
    ("remoted.http.cacerts.responses.503", "http_cacerts_responses_503"),
    ("remoted.http.cacerts.responses.other", "http_cacerts_responses_other"),
    # GET /cacerts outcomes ("why"): served, no CA file, refused because the CA does not sign the
    # leaf, or refused by the route's rate limit before the CA was even read -- that last one is in
    # none of the other three for that reason. The rate_limit trio is the route's live budget:
    # available pinned at 0 while rate_limited climbs is a rate set below what the fleet needs.
    ("remoted.cacerts.served", "cacerts_served"),
    ("remoted.cacerts.not_found", "cacerts_not_found"),
    ("remoted.cacerts.ca_mismatch", "cacerts_ca_mismatch"),
    ("remoted.cacerts.rate_limited", "cacerts_rate_limited"),
    ("remoted.cacerts.rate_limit.limit", "cacerts_rate_limit_limit"),
    ("remoted.cacerts.rate_limit.burst", "cacerts_rate_limit_burst"),
    ("remoted.cacerts.rate_limit.available", "cacerts_rate_limit_available"),
    # Enrollment outcomes ("why"), the companion of the status cells above. The queue trio is
    # what separates a saturated authd queue from an unreachable authd inside authd_unavailable.
    ("remoted.enroll.accepted", "enroll_accepted"),
    ("remoted.enroll.rejected_auth", "enroll_rejected_auth"),
    ("remoted.enroll.rejected_validation", "enroll_rejected_validation"),
    ("remoted.enroll.disabled", "enroll_disabled"),
    ("remoted.enroll.authd_error", "enroll_authd_error"),
    ("remoted.enroll.authd_unavailable", "enroll_authd_unavailable"),
    ("remoted.enroll.authd.queue.depth", "enroll_authd_queue_depth"),
    ("remoted.enroll.authd.queue.capacity", "enroll_authd_queue_capacity"),
    ("remoted.enroll.authd.queue.rejected.total", "enroll_authd_queue_rejected_total"),
    # Refused by the endpoint's rate limit BEFORE the handler ran: no body decoded, no credential
    # read, no authd round trip -- so it is in none of the outcomes above, and the three authd_*
    # families staying flat while this climbs is the amplification being prevented.
    ("remoted.enroll.rate_limited", "enroll_rate_limited"),
    ("remoted.enroll.rate_limit.limit", "enroll_rate_limit_limit"),
    ("remoted.enroll.rate_limit.burst", "enroll_rate_limit_burst"),
    ("remoted.enroll.rate_limit.available", "enroll_rate_limit_available"),
    ("remoted.enroll.token.accepted", "enroll_token_accepted"),
    ("remoted.enroll.token.rejected_unknown", "enroll_token_rejected_unknown"),
    ("remoted.enroll.token.rejected_expired", "enroll_token_rejected_expired"),
    ("remoted.enroll.token.rejected_revoked", "enroll_token_rejected_revoked"),
    ("remoted.enroll.token.rejected_exhausted", "enroll_token_rejected_exhausted"),
    ("remoted.enroll.token_store.tokens", "enroll_token_store_tokens"),
    ("remoted.enroll.token_store.reloads.total", "enroll_token_store_reloads_total"),
    ("remoted.enroll.token_store.reload_failures.total", "enroll_token_store_reload_failures_total"),
    # Downstream failure taxonomy ("why the 503s"): aggregate across services -- the per-endpoint
    # 503 columns above already say which path is failing.
    ("remoted.forwarder.error.connect", "forwarder_error_connect"),
    ("remoted.forwarder.error.connect_timeout", "forwarder_error_connect_timeout"),
    ("remoted.forwarder.error.write_timeout", "forwarder_error_write_timeout"),
    ("remoted.forwarder.error.response_timeout", "forwarder_error_response_timeout"),
    ("remoted.forwarder.error.transport", "forwarder_error_transport"),
    ("remoted.forwarder.error.protocol", "forwarder_error_protocol"),
    ("remoted.forwarder.error.response_too_large", "forwarder_error_response_too_large"),
    ("remoted.forwarder.downstream_5xx", "forwarder_downstream_5xx"),
    ("remoted.forwarder.route_mismatch", "forwarder_route_mismatch"),
    # /download admission outcomes + started transfers (bytes counted once at start).
    ("remoted.download.rejected", "download_rejected"),
    ("remoted.download.not_found", "download_not_found"),
    ("remoted.download.open_error", "download_open_error"),
    ("remoted.download.started", "download_started"),
    ("remoted.download.bytes.total", "download_bytes_total"),
    # Backpressure of the PUBLIC transport: the byte budget (levels + a cumulative shed total),
    # the deferred-work limiter and the connection level. These are the numbers that size
    # 'max_inflight_bytes', 'max_deferred_requests' and 'max_parallel_connections'.
    #
    # connections.{open,max} is the odd one and has NO rejection counter, because reaching that
    # ceiling rejects nothing: the transport postpones the accept and the connection waits in the
    # kernel backlog, so saturation shows up as latency and this level is the only way to see it
    # coming. Not the same as budget.inflight.requests -- a connection is held from accept to
    # close, which for a streamed POST /download is the whole transfer.
    ("remoted.server.budget.available.bytes", "server_budget_available_bytes"),
    ("remoted.server.budget.inflight.bytes", "server_budget_inflight_bytes"),
    ("remoted.server.budget.inflight.requests", "server_budget_inflight_requests"),
    ("remoted.server.budget.rejected.total", "server_budget_rejected_total"),
    ("remoted.forwarder.deferred.inflight", "forwarder_deferred_inflight"),
    ("remoted.forwarder.deferred.capacity", "forwarder_deferred_capacity"),
    ("remoted.forwarder.deferred.rejected.total", "forwarder_deferred_rejected_total"),
    ("remoted.server.connections.open", "server_connections_open"),
    ("remoted.server.connections.max", "server_connections_max"),
    # The served TLS certificate: days to expiry (the catalog's one signed value -- negative once
    # expired; _as_int keeps the sign) and whether remote.https.ca_certificate signs it (0/1; 0
    # also while the listener is down). Levels, re-evaluated by remoted daily.
    ("remoted.server.tls.cert_expiry_days", "server_tls_cert_expiry_days"),
    ("remoted.server.tls.ca_matches_leaf", "server_tls_ca_matches_leaf"),
    # The admin server dogfooding its own transport. Both its routes are liveness-class, so
    # the budget and the data/control lanes are structurally zero -- only sessions.live and
    # sessions.liveness ever move. They are kept for symmetry with inventory sync's block.
    ("remoted.admin.server.budget.available.bytes", "admin_budget_available_bytes"),
    ("remoted.admin.server.budget.inflight.bytes", "admin_budget_inflight_bytes"),
    ("remoted.admin.server.budget.inflight.requests", "admin_budget_inflight_requests"),
    ("remoted.admin.server.sessions.live", "admin_sessions_live"),
    ("remoted.admin.server.sessions.data", "admin_sessions_data"),
    ("remoted.admin.server.sessions.control", "admin_sessions_control"),
    ("remoted.admin.server.sessions.liveness", "admin_sessions_liveness"),
)

# End-to-end latency histograms (microseconds, gateway receipt -> response delivery), only on
# the endpoints whose latency answers a tuning question, plus the wazuh-db round trip. Same
# {count,p50,p90,p99,max} expansion as inventory sync's block.
REMOTED_MODULE_HISTOGRAMS: tuple[tuple[str, str], ...] = (
    ("remoted.http.stateless.latency", "http_stateless_latency"),
    ("remoted.http.stateful.latency", "http_stateful_latency"),
    ("remoted.http.enroll.latency", "http_enroll_latency"),
    ("remoted.control.wdb.latency", "control_wdb_latency"),
)

# The engine running as analysisd, POST /metrics/dump on its API socket. Its dump splits
# into a `global` array and per-space arrays; the extractor below flattens a space's
# metrics to `spaces.<space>.<metric>`, so the "standard" space aliases like any other.
ANALYSISD_SCALARS: tuple[tuple[str, str], ...] = (
    ("server.events.received", "server_events_received"),
    ("router.queue.size", "router_queue_size"),
    ("router.queue.usage.percent", "router_queue_usage_percent"),
    ("router.queue.bytes.used", "router_queue_bytes_used"),
    ("router.queue.bytes.usage.percent", "router_queue_bytes_usage_percent"),
    ("router.events.processed", "router_events_processed"),
    ("router.events.dropped", "router_events_dropped"),
    ("indexer.queue.size", "indexer_queue_size"),
    ("indexer.queue.usage.percent", "indexer_queue_usage_percent"),
    ("indexer.events.dropped", "indexer_events_dropped"),
    ("router.eps.1m", "router_eps_1m"),
    # Agent metadata cache: entries is an instantaneous gauge, the rest are cumulative.
    ("agent.cache.entries", "agent_cache_entries"),
    ("agent.cache.hits", "agent_cache_hits"),
    ("agent.cache.insertions", "agent_cache_insertions"),
    ("agent.cache.updates", "agent_cache_updates"),
    ("agent.cache.evictions", "agent_cache_evictions"),
    ("spaces.standard.events.unclassified", "spaces_standard_events_unclassified"),
)

# remoted's C statistics over the legacy framed `getstats` socket. Disjoint from the C++
# module's registry above -- different plane, different socket, no overlap. The dump is a
# nested JSON document rather than a metrics array, so the extractor flattens it to dotted
# paths and these aliases are just those paths' short names.
REMOTED_SCALARS: tuple[tuple[str, str], ...] = (
    ("error", "error"),
    ("message", "message"),
    ("data.name", "data_name"),
    ("data.timestamp", "data_timestamp"),
    ("data.uptime", "data_uptime"),
    ("data.metrics.bytes.received", "metrics_bytes_received"),
    ("data.metrics.bytes.sent", "metrics_bytes_sent"),
    ("data.metrics.keys_reload_count", "metrics_keys_reload_count"),
    ("data.metrics.messages.received_breakdown.control", "messages_received_breakdown_control"),
    ("data.metrics.messages.received_breakdown.dequeued_after", "messages_received_breakdown_dequeued_after"),
    ("data.metrics.messages.received_breakdown.discarded", "messages_received_breakdown_discarded"),
    ("data.metrics.messages.received_breakdown.events", "messages_received_breakdown_events"),
    ("data.metrics.messages.received_breakdown.events_failed", "messages_received_breakdown_events_failed"),
    ("data.metrics.messages.received_breakdown.ping", "messages_received_breakdown_ping"),
    ("data.metrics.messages.received_breakdown.unknown", "messages_received_breakdown_unknown"),
    ("data.metrics.messages.received_breakdown.control_breakdown.keepalive", "messages_received_breakdown_control_breakdown_keepalive"),
    ("data.metrics.messages.received_breakdown.control_breakdown.request", "messages_received_breakdown_control_breakdown_request"),
    ("data.metrics.messages.received_breakdown.control_breakdown.shutdown", "messages_received_breakdown_control_breakdown_shutdown"),
    ("data.metrics.messages.received_breakdown.control_breakdown.startup", "messages_received_breakdown_control_breakdown_startup"),
    ("data.metrics.messages.sent_breakdown.ack", "messages_sent_breakdown_ack"),
    ("data.metrics.messages.sent_breakdown.discarded", "messages_sent_breakdown_discarded"),
    ("data.metrics.messages.sent_breakdown.shared", "messages_sent_breakdown_shared"),
    ("data.metrics.queues.received.size", "queues_received_size"),
    ("data.metrics.queues.received.usage", "queues_received_usage"),
    ("data.metrics.tcp_sessions", "tcp_sessions"),
    ("data.metrics.control_messages_queue_usage", "control_messages_queue_usage"),
    ("data.metrics.control_messages_queue_breakdown.inserted", "control_messages_queue_breakdown_inserted"),
    ("data.metrics.control_messages_queue_breakdown.replaced", "control_messages_queue_breakdown_replaced"),
    ("data.metrics.control_messages_queue_breakdown.processed", "control_messages_queue_breakdown_processed"),
)


# remoted's framed `getstats` is a plain document: unlike the wazuh_metrics registries it
# declares no types, so they are declared here instead. The document's shape is fixed and
# ours, which is why this can be a table rather than a guess -- and a guess is what it used
# to be: an undeclared series was called a counter when it happened not to go down during
# the run, so `tcp_sessions` landed in `counters` with a delta under steady load and in
# `levels` under a load that closed connections. The same metric changed category between
# runs, which makes two summaries incomparable.
#
# Anything not named here is treated as a level and gets no delta, because an unjustified
# delta is worse than a missing one.
REMOTED_TYPES: dict[str, str] = {
    # Cumulative since the daemon started.
    "data.metrics.bytes.received": "counter",
    "data.metrics.bytes.sent": "counter",
    "data.metrics.keys_reload_count": "counter",
    "data.metrics.messages.received_breakdown.control": "counter",
    "data.metrics.messages.received_breakdown.dequeued_after": "counter",
    "data.metrics.messages.received_breakdown.discarded": "counter",
    "data.metrics.messages.received_breakdown.events": "counter",
    "data.metrics.messages.received_breakdown.events_failed": "counter",
    "data.metrics.messages.received_breakdown.ping": "counter",
    "data.metrics.messages.received_breakdown.unknown": "counter",
    "data.metrics.messages.received_breakdown.upgrade_ack": "counter",
    "data.metrics.messages.received_breakdown.control_breakdown.keepalive": "counter",
    "data.metrics.messages.received_breakdown.control_breakdown.request": "counter",
    "data.metrics.messages.received_breakdown.control_breakdown.shutdown": "counter",
    "data.metrics.messages.received_breakdown.control_breakdown.startup": "counter",
    "data.metrics.messages.sent_breakdown.ack": "counter",
    "data.metrics.messages.sent_breakdown.discarded": "counter",
    "data.metrics.messages.sent_breakdown.shared": "counter",
    "data.metrics.control_messages_queue_breakdown.inserted": "counter",
    "data.metrics.control_messages_queue_breakdown.replaced": "counter",
    "data.metrics.control_messages_queue_breakdown.processed": "counter",
    # Instantaneous: live connections, the queue's configured capacity and its occupancy.
    "data.metrics.tcp_sessions": "gauge_int",
    "data.metrics.queues.received.size": "gauge_int",
    "data.metrics.queues.received.usage": "pull",
    "data.metrics.control_messages_queue_usage": "pull",
    # The daemon's own clocks, which are readings about the process, not about traffic.
    "data.uptime": "gauge_int",
    "data.timestamp": "gauge_int",
    "error": "gauge_int",
}


# ---------------------------------------------------------------------------
# Extractors — one dump shape -> one Extraction
#
# Each returns the module's OWN names. No renaming happens here: renaming is the
# projection's job, and a name that only this function knows would be a name no consumer
# could ask for.
# ---------------------------------------------------------------------------
@dataclass
class Extraction:
    """Everything one dump said, split by how often it changes.

    `metrics` and `histograms` are the readings. `types`, `units` and `descriptions` are
    registration-time descriptors, constant for the life of a metric, so they are written
    once to the `meta` line instead of on every scrape. `doc` is what the dump said about
    itself (the daemon's name, its uptime, its own clock) and goes on each sample, because
    the server's timestamp is the one field in it that moves.

    `disabled` is neither: a metric can be turned off at runtime (`IMetric::disable()`) and
    `jsonDump` writes its `value` anyway, so a disabled metric reports whatever it last
    held. Recording which metrics were off during a scrape is what keeps that stale value
    from being read as a live one. Normal scrapes have none, and it costs nothing then.
    """

    metrics: dict[str, Any] = field(default_factory=dict)
    histograms: dict[str, Any] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    units: dict[str, str] = field(default_factory=dict)
    descriptions: dict[str, str] = field(default_factory=dict)
    disabled: list[str] = field(default_factory=list)
    doc: dict[str, Any] = field(default_factory=dict)

    @property
    def descriptors(self) -> dict[str, dict]:
        """The parts that belong on a `meta` line, for comparing against the last one."""
        return {"types": self.types, "units": self.units, "descriptions": self.descriptions}


def _doc_scalars(raw: dict, skip: tuple[str, ...]) -> dict[str, Any]:
    """The dump's own top-level scalars — what it says about itself, not about a metric."""
    return {k: v for k, v in raw.items()
            if k not in skip and not isinstance(v, (dict, list))}


def _flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten a nested JSON document to dotted paths, keeping every scalar leaf."""
    out: dict[str, Any] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            out.update(_flatten(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            out.update(_flatten(value, f"{prefix}.{idx}" if prefix else str(idx)))
    elif prefix:
        out[prefix] = node
    return out


def _take_item(out: Extraction, item: dict, prefix: str = "") -> None:
    """Fold one {name,type,enabled,value,unit?,description?,summary?} entry into a record."""
    name = f"{prefix}{item['name']}"
    if item.get("type") is not None:
        out.types[name] = item["type"]
    if item.get("unit"):
        out.units[name] = item["unit"]
    if item.get("description"):
        out.descriptions[name] = item["description"]
    # `enabled` is absent from older dumps; only an explicit false means "turned off".
    if item.get("enabled") is False:
        out.disabled.append(name)
    if item.get("value") is not None:
        out.metrics[name] = item["value"]
    if isinstance(item.get("summary"), dict):
        out.histograms[name] = item["summary"]


def extract_metrics_array(raw: dict) -> Extraction:
    """wazuh_metrics dumpJson: {"metrics":[{name,type,enabled,value,unit?,...}]}.

    Shared by inventory_sync_server and remoted_module -- the shape is the module's, not
    the endpoint's, so one extractor serves both.
    """
    out = Extraction(doc=_doc_scalars(raw, skip=("metrics",)))
    for item in raw.get("metrics") or []:
        if isinstance(item, dict) and "name" in item:
            _take_item(out, item)
    return out


def extract_analysisd(raw: dict) -> Extraction:
    """The engine's dump: a `global` array plus one metrics array per space."""
    out = Extraction(doc=_doc_scalars(raw, skip=("global", "spaces")))

    def take(items: Any, prefix: str = "") -> None:
        for item in items or []:
            if isinstance(item, dict) and "name" in item:
                _take_item(out, item, prefix)

    take(raw.get("global"))
    for space in raw.get("spaces") or []:
        if isinstance(space, dict) and space.get("name"):
            take(space.get("metrics"), f"spaces.{space['name']}.")
    return out


def extract_remoted(raw: dict) -> Extraction:
    """remoted's framed `getstats`: a nested document, flattened to dotted paths.

    Every leaf becomes a metric -- the document IS the reading, and flattening it keeps all
    of it. The types it does not declare come from REMOTED_TYPES, so a consumer classifies
    this source from a table rather than from how its readings happened to move.
    """
    metrics = _flatten(raw)
    return Extraction(metrics=metrics,
                      types={n: t for n, t in REMOTED_TYPES.items() if n in metrics})


# ---------------------------------------------------------------------------
# Derived columns — aggregates that are not a metric in the dump
# ---------------------------------------------------------------------------
def _invsync_shard_aggregates(metrics: dict) -> dict[str, Any]:
    """Aggregate the per-shard gauges into a fixed, machine-independent set.

    depth_max against depth_sum shows imbalance without letting the shard count (which
    follows the configured worker count) into the column set. The per-shard detail is not
    lost the way it used to be -- it is in the samples file under its own names.

    A family with no entries yields NO aggregate, rather than zeros. These are derived
    columns, so they are as capable of inventing a measurement as a raw one: a scrape that
    carried no shard gauges at all used to produce `shard_depth_sum=0`, which plots as a
    real, measured zero for a scrape that observed nothing. The two families are aggregated
    independently for the same reason -- observing depths says nothing about bytes.
    """
    depths: dict[str, int] = {}
    sizes: dict[str, int] = {}
    for name, value in metrics.items():
        if not name.startswith("sync.shard."):
            continue
        if name.endswith(".depth"):
            depths[name[len("sync.shard."):-len(".depth")]] = value
        elif name.endswith(".bytes"):
            sizes[name[len("sync.shard."):-len(".bytes")]] = value

    out: dict[str, Any] = {}
    shards = set(depths) | set(sizes)
    if shards:
        # Every shard seen in either family, so the count matches the data rather than
        # whichever family happened to be the one this build publishes.
        out["shard_count"] = len(shards)
    if depths:
        out["shard_depth_max"] = max(depths.values())
        out["shard_depth_sum"] = sum(depths.values())
    if sizes:
        out["shard_bytes_max"] = max(sizes.values())
        out["shard_bytes_sum"] = sum(sizes.values())
    return out


class Source:
    """One daemon's scrape: how to read its dump and how to name its columns."""

    def __init__(self, name: str, csv_name: str, extract: Callable[[dict], tuple[dict, dict, dict]],
                 scalars: tuple[tuple[str, str], ...] = (),
                 histograms: tuple[tuple[str, str], ...] = (),
                 derived: Callable[[dict], dict] | None = None,
                 derived_columns: tuple[str, ...] = (),
                 static_types: dict[str, str] | None = None) -> None:
        self.name = name
        self.csv_name = csv_name
        self.extract = extract
        self.scalars = scalars
        self.histograms = histograms
        self.derived = derived
        self.derived_columns = derived_columns
        # Types for a source that declares none on the wire. Applied when reading as well
        # as when writing, so a run recorded before the table existed still classifies.
        self.static_types = static_types or {}



SOURCES: dict[str, Source] = {
    "inventory-sync": Source(
        "inventory-sync", "stats-api-inventory-sync.csv", extract_metrics_array,
        INVSYNC_SCALARS, INVSYNC_HISTOGRAMS,
        derived=_invsync_shard_aggregates,
        derived_columns=("shard_count", "shard_depth_max", "shard_depth_sum",
                         "shard_bytes_max", "shard_bytes_sum"),
    ),
    "remoted-module": Source(
        "remoted-module", "stats-api-remoted-module.csv", extract_metrics_array,
        REMOTED_MODULE_SCALARS, REMOTED_MODULE_HISTOGRAMS,
    ),
    "analysisd": Source(
        "analysisd", "stats-api-analysisd.csv", extract_analysisd, ANALYSISD_SCALARS,
    ),
    "remoted": Source(
        "remoted", "stats-api-remoted.csv", extract_remoted, REMOTED_SCALARS,
        static_types=REMOTED_TYPES,
    ),
}

# Reverse lookup for readers handed a legacy CSV rather than a samples file.
CSV_NAME_TO_SOURCE: dict[str, str] = {s.csv_name: name for name, s in SOURCES.items()}


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def new_run_id() -> str:
    """A sortable, unique id for one run of the collectors.

    Time-ordered so that "the last run" is the same answer whether a reader takes the last
    marker in the file or the highest id, and suffixed so two runs started in the same
    second are still distinct.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:4]}"


class NdjsonWriter:
    """Append-only NDJSON sink shared by every collector thread.

    One file, four writers. Each line is serialised fully before the lock is taken and
    written in a single call, so a line is never interleaved with another source's; the
    flush keeps the file readable by `tail -f` while a run is in flight, which is most of
    what a samples file is for during a long benchmark.

    Opening the sink starts a run: it writes a `run` marker and stamps `r` on every line it
    writes afterwards. Callers do not pass the id around -- a line that forgot it would be
    invisible to every reader asking for the last run, so the writer is the only thing that
    can attach it.
    """

    def __init__(self, path: str, run_id: str | None = None, label: str | None = None) -> None:
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._fh = open(path, "a", buffering=1)
        self.path = path
        self.run_id = run_id or new_run_id()
        marker = {"kind": "run", "r": self.run_id,
                  "started": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if label:
            marker["label"] = label
        self._write_raw(marker)

    def _write_raw(self, obj: dict) -> None:
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=True, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def write(self, obj: dict) -> None:
        self._write_raw({**obj, "r": self.run_id})

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except OSError:
                pass


def sample_line(src: str, timestamp: str, elapsed_s: float, metrics: dict,
                hists: dict | None = None, disabled: list[str] | None = None,
                doc: dict | None = None) -> dict:
    """Build a successful scrape's line.

    `h`, `off` and `d` are omitted when empty rather than written as empty objects, so the
    common scrape -- everything enabled -- pays nothing for the two fields that exist for
    the uncommon one.

      m    metric name -> value            h   metric name -> histogram summary
      off  metrics reporting enabled=false in THIS scrape; their `m` value is whatever
           they last held, since jsonDump writes a value either way
      d    what the dump said about itself (daemon name, uptime, its own clock)
    """
    line: dict[str, Any] = {"ts": timestamp, "t": elapsed_s, "src": src, "ok": True, "m": metrics}
    if hists:
        line["h"] = hists
    if disabled:
        line["off"] = sorted(disabled)
    if doc:
        line["d"] = doc
    return line


def sample_line_from(src: str, timestamp: str, elapsed_s: float,
                     extraction: Extraction) -> dict:
    """The line for one extraction -- the form a collector should use, so that a field
    added to Extraction reaches the file without every call site being revisited."""
    return sample_line(src, timestamp, elapsed_s, extraction.metrics, extraction.histograms,
                       extraction.disabled, extraction.doc)


def error_line(src: str, timestamp: str, elapsed_s: float, error: str) -> dict:
    """Build a failed scrape's line. It carries NO metrics -- a failed scrape observed
    nothing, and writing zeros would fake a counter reset in every consumer's delta."""
    return {"ts": timestamp, "t": elapsed_s, "src": src, "ok": False, "err": error}


def meta_line(src: str, socket_path: str, types: dict, units: dict | None = None,
              descriptions: dict | None = None) -> dict:
    """The registration-time descriptors of a source's metrics.

    Written once per run rather than on every scrape: a unit and a description are fixed
    when the metric is registered, and repeating 54 of each across 400 scrapes would cost
    more than the readings do. A collector re-emits this line if a descriptor ever changes,
    so "written once" is the normal case and not an assumption the format depends on.
    """
    line: dict[str, Any] = {"kind": "meta", "src": src, "socket": socket_path, "types": types}
    if units:
        line["units"] = units
    if descriptions:
        line["descriptions"] = descriptions
    return line


def meta_line_from(src: str, socket_path: str, extraction: Extraction) -> dict:
    return meta_line(src, socket_path, extraction.types, extraction.units,
                     extraction.descriptions)


def read_descriptors(path: str, src: str, run: str | None = "last") -> dict[str, dict]:
    """A source's per-metric descriptors for a run: {metric: {type, unit, description}}.

    Folded over every `meta` line in the run, latest wins. Manifests are revisions, not a
    one-shot header: a module may register a metric after the collector has started, and the
    collector re-emits the manifest whenever the descriptors change. Reading only the first
    one -- which this module used to do in read_types() -- loses the type of everything
    registered later while keeping its readings, so the file stops being self-describing
    precisely for the metrics a reader is least likely to already know about.

    Folding accumulates: a metric that appears and is later unregistered keeps the type it
    declared, because the run still holds readings for it and those readings still need
    classifying.
    """
    out: dict[str, dict] = {}
    for obj in read_samples(path, src=src, run=run, include_meta=True):
        if obj.get("kind") != "meta":
            continue
        for key, field_name in (("types", "type"), ("units", "unit"),
                                ("descriptions", "description")):
            for metric, value in (obj.get(key) or {}).items():
                out.setdefault(metric, {})[field_name] = value
    return out


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def samples_path(results_dir: str) -> str:
    """Where run_benchmark.sh puts a run's samples file."""
    return os.path.join(results_dir, "samples", SAMPLES_FILENAME)


def _iter_lines(path: str) -> Iterator[dict]:
    """Every well-formed object in the file, in order.

    A truncated last line is skipped rather than raised on: the collector appends and
    flushes per scrape, so a run killed mid-write leaves one partial line, and the other
    thousands are still perfectly good data.
    """
    if not os.path.isfile(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                yield obj


def last_run_id(path: str) -> str | None:
    """The id of the most recent run in the file, or None if it records no run.

    File order decides, not the id's own ordering: a reader must agree with whatever was
    appended last even if a clock moved.
    """
    run_id = None
    for obj in _iter_lines(path):
        if obj.get("r"):
            run_id = obj["r"]
    return run_id


def read_samples(path: str, src: str | None = None, run: str | None = "last",
                 include_meta: bool = False) -> Iterator[dict]:
    """Yield a samples file's sample lines, by default only the last run's.

    `run` is "last" (the default), "all", or an explicit run id. The default is "last"
    because the file accumulates: run_benchmark.sh reuses `results_<label>/` for a reused
    label and the collectors append, so a whole-file read silently spans runs and turns a
    delta into the sum of two.
    """
    wanted = None
    if run == "last":
        wanted = last_run_id(path)
    elif run not in (None, "all"):
        wanted = run

    for obj in _iter_lines(path):
        if obj.get("kind") == "run":
            continue
        if wanted is not None and obj.get("r") != wanted:
            continue
        if obj.get("kind") == "meta":
            if include_meta and (src is None or obj.get("src") == src):
                yield obj
            continue
        if src is None or obj.get("src") == src:
            yield obj


def read_types(path: str, src: str, run: str | None = "last") -> dict[str, str]:
    """The declared type of every metric the source described during the run.

    A projection of read_descriptors(), not a second walk of the file. It used to be its
    own loop that returned the FIRST manifest and stopped, which quietly undid the point of
    re-emitting one: a metric registered after the first scrape kept its readings and lost
    its type, and a consumer classifying by type then treated it as undeclared.
    """
    return {metric: d["type"] for metric, d in read_descriptors(path, src, run).items()
            if d.get("type")}


# How a metric's declared type decides what may be computed from a series of its readings.
# The vocabulary is wazuh::metrics::typeName() (jsonDump.cpp): counter, gauge_int, pull,
# histogram -- plus "unknown", which that function also emits.
#
#   counter  cumulative and monotonic, so a DELTA is the work done during the run
#   level    an instantaneous reading, so a delta is meaningless: 5 sessions then 2 is not
#            "-3 sessions", it is a level that moved. first/last/min/max are what it has.
#   text     not a number at all
#
# A source whose dump declares no types (remoted's framed getstats is a plain document) is
# classified from what its readings do; see classify().
KIND_COUNTER = "counter"
KIND_LEVEL = "level"
KIND_TEXT = "text"

_TYPE_KINDS = {
    "counter": KIND_COUNTER,
    "gauge_int": KIND_LEVEL,
    "pull": KIND_LEVEL,
}


def is_numeric(value: Any) -> bool:
    """Whether a reading is a number. bool is excluded: True is not a measurement."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def type_of(src: str, metric: str, descriptors: dict[str, dict] | None = None) -> str | None:
    """The declared type of a metric: what the file says, else what the source knows.

    The file is the first authority, so a module that starts publishing a type is believed
    over any table here. The fallback covers the source that declares none on the wire
    (remoted's `getstats` is a plain document) and runs recorded before its table existed.
    """
    from_file = ((descriptors or {}).get(metric) or {}).get("type")
    if from_file:
        return from_file
    source = SOURCES.get(src)
    return source.static_types.get(metric) if source else None


def classify(declared_type: str | None, sample_value: Any) -> str:
    """The kind of a metric: what may legitimately be computed from its readings.

    The declared type decides, and every source declares one: the wazuh_metrics registries
    publish it on the wire, and remoted's document gets it from REMOTED_TYPES.

    An undeclared numeric metric is a LEVEL. It used to be called a counter when its
    readings happened never to go down over the run, which made the classification depend
    on the load rather than on the metric: `tcp_sessions` was a counter with a delta under
    steady traffic and a level under traffic that closed connections, so the same series
    changed category between two runs of the same scenario. A delta nobody can justify is
    worse than a delta nobody gets.
    """
    if not is_numeric(sample_value):
        return KIND_TEXT
    if declared_type in _TYPE_KINDS:
        return _TYPE_KINDS[declared_type]
    if declared_type == "histogram":
        return KIND_COUNTER  # its scalar value is the observation count, which only rises
    return KIND_LEVEL


def observed(sample: dict) -> tuple[dict[str, Any], dict[str, Any]]:
    """What a sample actually MEASURED: its `m` and its `h`, minus anything it reported off.

    Every consumer goes through this rather than reading `m` and `h` directly, because both
    hold values for a disabled metric -- jsonDump emits a value and a summary regardless of
    `isEnabled()` -- and a stale reading counted as a measurement is worse than a gap.

    It returns BOTH on purpose. This used to filter only `m` and leave each caller to take
    `h` for itself, and every caller duly took it unfiltered: a disabled histogram's p99
    reached the charts and the summary as if it had been measured. Handing back one object
    per kind is what stops a consumer from remembering one and forgetting the other.
    """
    metrics = sample.get("m") or {}
    hists = sample.get("h") or {}
    off = sample.get("off")
    if not off:
        return metrics, hists
    off = set(off)
    return ({k: v for k, v in metrics.items() if k not in off},
            {k: v for k, v in hists.items() if k not in off})


def project(path: str, src: str, run: str | None = "last"):
    """Read a samples file into the wide table the charts and `export_csv()` consume.

    Columns come in two layers. First the ALIASED names (`docs_indexed`,
    `vd_lane_time_p99`) the chart definitions are keyed on, from the source's alias tables.
    Then every metric the dump carried under its own name with dots turned into
    underscores -- including the ones no alias mentions, which a fixed wide header could
    never hold. The aliased layer wins a collision: that is the name a consumer asked for
    by putting it in the table.

    Scoped to one run (the last, by default). The caller must NOT apply the
    `elapsed_s`-goes-backwards heuristic on top: four sources interleave in this file, so
    that signal does not mean what it means in a single-source CSV.

    A metric that is absent, disabled, or belongs to a failed scrape simply has no entry
    and lands as NaN -- which keeps it out of every plot and every aggregate, as not having
    measured something should.
    """
    import pandas as pd  # optional dependency: only a projection needs it

    source = SOURCES.get(src)
    if source is None:
        raise KeyError(f"unknown source {src!r}; known: {sorted(SOURCES)}")

    rows: list[dict[str, Any]] = []
    for sample in read_samples(path, src=src, run=run):
        ok = bool(sample.get("ok"))
        row: dict[str, Any] = {
            "timestamp": sample.get("ts", ""),
            "elapsed_s": sample.get("t"),
            "query_ok": 1 if ok else 0,
            "query_error": "" if ok else str(sample.get("err", "")),
        }
        metrics, hists = observed(sample)

        for metric_name, column in source.scalars:
            if metric_name in metrics:
                row[column] = metrics[metric_name]
        if ok and source.derived:
            row.update(source.derived(metrics))
        for metric_name, prefix in source.histograms:
            summary = hists.get(metric_name)
            if isinstance(summary, dict):
                for field in HIST_FIELDS:
                    if field in summary:
                        row[f"{prefix}_{field}"] = summary[field]

        for name, value in metrics.items():
            row.setdefault(name.replace(".", "_"), value)
        for name, summary in hists.items():
            if isinstance(summary, dict):
                for field, value in summary.items():
                    row.setdefault(f"{name.replace('.', '_')}_{field}", value)
        rows.append(row)

    return _frame(pd, rows)


# Widths the daemons actually publish. wazuh_metrics writes counters and histogram counts
# through writer.Uint64() and signed gauges through writer.Int64(), so a column can legally
# hold anything from INT64_MIN to UINT64_MAX -- and no single numpy integer type covers
# both ends. The width is therefore chosen per column, from the values in it.
_INT64_MIN, _INT64_MAX = -(2 ** 63), 2 ** 63 - 1
_UINT64_MAX = 2 ** 64 - 1


def _int_column(pd, values: list, present: list):
    """An integer column in the narrowest exact dtype that holds every value in it.

    Picking int64 unconditionally raised OverflowError on a counter past INT64_MAX, which
    is not a rounding error but a dead projection: the exception propagates out of
    project(), so that daemon vanishes from the charts and cannot be exported at all.

    A gap forces pandas' nullable variant (Int64/UInt64), which holds the value and the gap
    at once; without one the plain numpy dtype is kept, so the common case reads exactly as
    it did before.
    """
    low, high = min(present), max(present)
    has_gap = len(present) < len(values)

    if low >= 0 and high > _INT64_MAX:
        if high > _UINT64_MAX:
            # Outside anything exact. Float is lossy above 2**53 and says so here rather
            # than failing: a value this large is not a counter any daemon of ours emits.
            return pd.array([float(v) if v is not None else float("nan") for v in values],
                            dtype="float64")
        return pd.array(values, dtype="UInt64") if has_gap \
            else pd.array(present, dtype="uint64")

    if low < _INT64_MIN:
        return pd.array([float(v) if v is not None else float("nan") for v in values],
                        dtype="float64")

    return pd.array(values, dtype="Int64") if has_gap else pd.array(present, dtype="int64")


def _frame(pd, rows: list[dict]):
    """Build the DataFrame column by column, choosing each dtype from the raw values.

    `pd.DataFrame(rows)` cannot be used directly: a column of Python ints with one missing
    entry is inferred as float64, and float64 stops being able to tell consecutive integers
    apart at 2**53. A counter that crossed that boundary across a failed scrape came out
    with both ends equal -- the projection reported no movement where the summary, which
    never leaves Python ints, reported one. Integral columns with gaps therefore get
    pandas' nullable Int64, which holds the value and the gap at once.
    """
    if not rows:
        return pd.DataFrame()

    # dict.fromkeys keeps first-seen order: aliased columns first, then the raw names.
    keys = list(dict.fromkeys(key for row in rows for key in row))
    data = {}
    for key in keys:
        values = [row.get(key) for row in rows]
        present = [v for v in values if v is not None]

        if key in ("timestamp", "query_error"):
            data[key] = pd.array(["" if v is None else str(v) for v in values], dtype=object)
        elif present and all(isinstance(v, int) and not isinstance(v, bool) for v in present):
            data[key] = _int_column(pd, values, present)
        elif present and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                             for v in present):
            data[key] = pd.array([float(v) if v is not None else float("nan") for v in values],
                                 dtype="float64")
        elif present:
            # Not numbers: remoted publishes a daemon name and a status among its readings.
            data[key] = pd.array(values, dtype=object)
        else:
            data[key] = pd.array([None] * len(values), dtype="Float64")
    return pd.DataFrame(data)


# ---------------------------------------------------------------------------
# Export
#
# The collectors used to write a wide CSV per daemon on every run, next to the samples
# file it was derived from. Nothing read them -- the charts and the summary both prefer the
# samples file -- and they carried strictly LESS than it: 57 columns against 126 for
# inventory sync, because a fixed header can only hold what somebody aliased. Their whole
# cost, including a file-rotation subsystem to survive the header changing between builds,
# bought a table that was already a subset of the data next to it.
#
# So the CSV stopped being an artifact of the run and became something you ask for.
# ---------------------------------------------------------------------------
def export_csv(results_dir: str, src: str, out_path: str | None = None,
               run: str | None = "last") -> str:
    """Write one source's projection of a run to CSV and return the path.

    The full projection, not the old 57-column subset: every metric the daemon published,
    aliased names included.
    """
    df = project(samples_path(results_dir), src, run=run)
    if out_path is None:
        out_path = os.path.join(results_dir, SOURCES[src].csv_name)
    df.to_csv(out_path, index=False)
    return out_path


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Export a benchmark run's samples file to CSV, one file per daemon.")
    parser.add_argument("results_dir", help="results_<label>/ directory of a run")
    parser.add_argument("--src", action="append", choices=sorted(SOURCES),
                        help="Daemon to export (repeatable; default: all with samples)")
    parser.add_argument("--out-dir", default=None,
                        help="Where to write (default: the results directory itself)")
    parser.add_argument("--run", default="last",
                        help='Which run in the file: "last" (default), "all", or a run id')
    args = parser.parse_args()

    path = samples_path(args.results_dir)
    if not os.path.isfile(path):
        print(f"no samples file at {path}", file=sys.stderr)
        return 1

    out_dir = args.out_dir or args.results_dir
    os.makedirs(out_dir, exist_ok=True)
    written = 0
    for src in args.src or sorted(SOURCES):
        df = project(path, src, run=args.run)
        if df.empty:
            continue
        out = os.path.join(out_dir, SOURCES[src].csv_name)
        df.to_csv(out, index=False)
        print(f"{out}  ({len(df)} rows x {len(df.columns)} columns)")
        written += 1
    if not written:
        print("nothing to export: the samples file holds no readings for those sources",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
