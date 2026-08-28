/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP

#include "common/metricNames.hpp" // invsync::metrics::RequestCounters
#include "indexer/IIndexerConnectorAsync.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/syncPipeline.hpp"
#include <uds_http_server/IUdsHttpServer.hpp>

#include <cstddef>
#include <memory>

namespace invsync::endpoints::delete_agent
{

    /**
     * @brief Whole-agent state deletion: `DELETE /agents` (design doc 04).
     *
     * UDS-local only (D15): the sole production caller is authd, after it removes the agent from
     * client.keys and wazuh-db. The target agent travels in the same `X-Wazuh-Agent-Id` header the
     * sync route uses; the body is ignored. The deletion is DEFERRED to the SyncPipeline on the
     * agent's shard, so it orders FIFO against any in-flight session of that same agent -- the
     * legacy path raced them on a lock (RF-10's footgun), and lost deletions were silent.
     *
     * ANSWERED AT ADMISSION: the 200 means "recorded and queued, it WILL be purged", not "already
     * purged". Waiting for the flush is what wedged the caller: authd relays deletions from the one
     * thread that persists client.keys, and on populated wazuh-states-* a single delete-by-query
     * legitimately outlives authd's 30 s budget -- so it timed out, retried into the very same
     * running purge, and blocked every key write meanwhile (no new agent could enroll). The purge's
     * own outcome stays observable in this module's log, never on this wire; the same contract
     * POST /vulnerability-detector/scan already moved to, for the same reason.
     *
     * TWO HALVES, ONE PER WRITER (see AGENT_DELETION_SCOPE_BY_QUERY / _BY_ID):
     *
     *  - `wazuh-states-*` is written by the sync pipeline, so the pipeline item above deletes it by
     *    query, ordered behind that agent's in-flight sessions by the shard FIFO.
     *  - `wazuh-agent-config` and `wazuh-agent-stats` are written by POST /config and POST /stats
     *    through the ASYNC connector, which accumulates reports and pushes them in batches. This
     *    route queues a by-id delete for each of them ON THAT SAME QUEUE, which is the only way to
     *    order them after a report the queue has accepted but not yet pushed: it is FIFO. Deleting
     *    them from the pipeline instead is what let a report in flight outlive the agent -- the
     *    delete-by-query could neither drain that queue nor, being a SEARCH, see a document that had
     *    not been refreshed yet.
     */

    /// @brief The verb of the canonical route.
    constexpr wazuh::uds_http::Method method()
    {
        return wazuh::uds_http::Method::Delete;
    }

    /// @brief The canonical path.
    constexpr const char* path()
    {
        return "/agents";
    }

    /// @brief POST alias of the same handler, for C callers whose HTTP helper (uhttp_*) only
    /// speaks POST -- authd uses this one (design doc 04 §2's sanctioned alternative).
    constexpr wazuh::uds_http::Method altMethod()
    {
        return wazuh::uds_http::Method::Post;
    }

    /// @brief The POST alias' path. Distinct from /agents so a POST there stays a 404 instead of
    /// silently meaning something else later.
    constexpr const char* altPath()
    {
        return "/agents/delete";
    }

    /**
     * @brief The EXECUTION route: `POST /_internal/agents/delete`, answered AT COMPLETION.
     *
     * Same work as the routes above, opposite answer. The Task Manager's dispatcher drives this one,
     * and it writes a manager-task row `completed` on a 200 -- so a 200 that meant "queued" would
     * record a purge that has not happened, and a modulesd crash right after it would lose the
     * queued deletion while the row already read `completed`. The item therefore carries its
     * responder and the pipeline's own respond() answers, after executeDeleteAgent() has run its
     * delete-by-query AND flushed it. That is what makes `completed` mean purged.
     *
     * WHY BOTH EXIST AT ONCE. The admission routes above keep authd's current path working until it
     * moves to creating a task row; removing them here would land a change in which agent deletion
     * stops purging documents entirely. They go away with the relay thread, not before.
     *
     * THE AGENT ID TRAVELS IN THE BODY, not in `X-Wazuh-Agent-Id`. The dispatcher POSTs a row's
     * PAYLOAD verbatim and sets no headers of its own -- the payload IS the consumer's request body,
     * authored by whoever created the row -- so the body is the only place an id can arrive:
     *
     *     {"agent_id": "7"}
     *
     * WHAT `completed` DOES NOT COVER. The by-id half (`wazuh-agent-config`, `wazuh-agent-stats`)
     * is queued on the async connector at admission and is fire-and-forget by construction: that
     * queue is FIFO, which is the only thing that can order those deletes after a report it has
     * already accepted, and it exposes no seam to wait on. So a 200 promises the state documents
     * were deleted and flushed, and promises only that the other two deletions were queued. Closing
     * that would mean giving up the ordering property the by-id half exists for. What limits the
     * exposure is idempotency: a retried deletion re-queues them, and deleting an absent document is
     * a no-op everywhere in the chain.
     *
     * CAPACITY. RouteClass::Control requires a route doing real work to shed its own capacity
     * module-side. This one has no queue of its own; the bound is the dispatcher's delete-lane depth
     * of 4, so at most four deletions are ever in flight.
     */

    /// @brief The verb of the execution route. POST for the same reason as the alias above: the
    /// caller's C-side HTTP helper (uhttp_*) only speaks POST.
    constexpr wazuh::uds_http::Method internalMethod()
    {
        return wazuh::uds_http::Method::Post;
    }

    /// @brief The execution route's path. `_internal` marks it as a manager-internal contract
    /// between two daemons of the same version -- nothing outside the manager may target it, and it
    /// carries no compatibility promise.
    constexpr const char* internalPath()
    {
        return "/_internal/agents/delete";
    }

    /**
     * @brief This route's own response backstop, overriding the server-wide 300 s.
     *
     * A CROSS-DAEMON COUPLING, and the only one this route has. The transport's backstop is written
     * around the peer's deadline being the shorter one, so that the peer gives up first; the Task
     * Manager gives this route 600 s (`manager_task_delete_timeout`), deliberately longer than the
     * scan route's 300 s because a scan can park a deletion behind it on this module's per-agent
     * queue. With the server-wide 300 s that ordering is inverted: a purge that legitimately runs
     * past five minutes gets a synthesized 504, the dispatcher reads it as retryable, and the
     * deletion re-queues forever while every attempt very nearly succeeds. This type has no attempt
     * budget, so "forever" is literal.
     *
     * 900 s keeps the intended ordering with room to spare. It must stay above
     * `manager_task_delete_timeout`: raising that knob past this value re-inverts the pair, which is
     * why the number is stated here rather than buried at the registration site.
     */
    constexpr std::size_t internalResponseTimeoutSeconds()
    {
        return 900;
    }

    /**
     * @brief Everything the handler needs, captured by value at registration.
     *
     * All weak, like every other route: the facade's stop() resets them and the weak capture keeps
     * that reset destructive. `indexer` is only the admission availability check; the pipeline
     * worker re-checks its own at dispatch. `asyncIndexer` is the connector that WROTE the two
     * AGENT_DELETION_SCOPE_BY_ID documents, and the only one whose queue can order their deletion
     * after a report it has already accepted -- it is not availability-checked, because that queue
     * is designed to buffer through an outage and the check above already covers "the indexer is
     * unreachable".
     *
     * requestCounters is the same sync.requests.total.* family the sync route holds (dedupe by
     * name on one manager). This route answers AT ADMISSION, so every response it produces is sent
     * from here -- the inline 400/503 rejections and the 200 that accepts the deletion alike; the
     * queued item carries no responder, so the pipeline counts nothing for it. Each response is
     * still counted exactly once, at the site that sends it. Default-constructed it counts nothing
     * (the null object the tests rely on).
     */
    struct Dependencies
    {
        std::weak_ptr<invsync::sync::SyncPipeline> pipeline;
        std::weak_ptr<invsync::indexer::IIndexerConnectorSync> indexer;
        std::weak_ptr<invsync::indexer::IIndexerConnectorAsync> asyncIndexer;
        invsync::metrics::RequestCounters requestCounters;
    };

    /**
     * @brief Build the route handler: validate the header (400), gate on availability (503),
     *        enqueue a DeleteAgent item on the agent's shard and answer 200 right there.
     */
    wazuh::uds_http::RouteHandler makeHandler(Dependencies dependencies);

    /**
     * @brief Build the execution route's handler: validate the body (400), gate on availability
     *        (503), enqueue the SAME DeleteAgent item WITH its responder, and answer nothing --
     *        the pipeline answers once the purge has flushed.
     *
     * Takes the same Dependencies, and `requestCounters` still counts every response this handler
     * sends itself. The terminal response is counted by the pipeline, at the site that sends it, so
     * an accepted deletion is counted exactly once here too.
     */
    wazuh::uds_http::RouteHandler makeCompletionHandler(Dependencies dependencies);

} // namespace invsync::endpoints::delete_agent

#endif // _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP
