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
     * @brief Whole-agent state deletion: `POST /_internal/agents/delete` (design doc 04).
     *
     * UDS-local only (D15) and manager-internal: the sole caller is the Task Manager's dispatcher,
     * executing a durable `agent_delete_indexer` row that authd created after removing the agent
     * from client.keys and wazuh-db. The deletion is DEFERRED to the SyncPipeline on the agent's
     * shard, so it orders FIFO against any in-flight session of that same agent -- the legacy path
     * raced them on a lock (RF-10's footgun), and lost deletions were silent.
     *
     * TWO HALVES, ONE PER WRITER (see AGENT_DELETION_SCOPE_BY_QUERY / _BY_ID):
     *
     *  - `wazuh-states-*` is written by the sync pipeline, so the pipeline item deletes it by query,
     *    ordered behind that agent's in-flight sessions by the shard FIFO.
     *  - `wazuh-agent-config` and `wazuh-agent-stats` are written by POST /config and POST /stats
     *    through the ASYNC connector, which accumulates reports and pushes them in batches. This
     *    route queues a by-id delete for each of them ON THAT SAME QUEUE, which is the only way to
     *    order them after a report the queue has accepted but not yet pushed: it is FIFO. Deleting
     *    them from the pipeline instead is what let a report in flight outlive the agent -- the
     *    delete-by-query could neither drain that queue nor, being a SEARCH, see a document that had
     *    not been refreshed yet.
     *
     * WHAT REPLACED WHAT. `DELETE /agents` and its `POST /agents/delete` alias stood here until
     * authd stopped relaying deletions itself. They answered AT ADMISSION -- the 200 meant "queued,
     * it WILL be purged" -- because authd relayed from the one thread that persists client.keys,
     * and on populated wazuh-states-* a single delete-by-query legitimately outlives a 30 s budget:
     * it timed out, retried into the very same running purge, and blocked every key write meanwhile,
     * so no agent could enroll. Nothing waits on that thread now; a dispatcher lane does, and it is
     * built to.
     */

    /**
     * @brief ANSWERED AT COMPLETION, which is the whole reason this route replaced the two before
     *        it.
     *
     * The dispatcher writes its manager-task row `completed` on the 200, so a 200 meaning "queued"
     * would record a purge that has not happened -- and a modulesd crash right after it would lose
     * the queued deletion while the row already read `completed`. The item therefore carries its
     * responder, and the pipeline's own respond() answers after executeDeleteAgent() has run its
     * delete-by-query AND flushed it. That is what makes `completed` mean purged.
     *
     * It needed no pipeline change: the worker has always answered a `DeleteAgent` item, there has
     * just never been anyone to answer.
     *
     * THE AGENT ID TRAVELS IN THE BODY, not in `X-Wazuh-Agent-Id`. The dispatcher POSTs a row's
     * PAYLOAD verbatim and sets no headers of its own -- the payload IS the consumer's request body,
     * authored by whoever created the row -- so the body is the only place an id can arrive:
     *
     *     {"agent_id": "7"}
     *
     * The header is ignored here deliberately: honouring it would hide a producer that forgot to
     * write the id into the payload, and would work in a test while failing in production.
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

    /// @brief The verb. POST because the caller's C-side HTTP helper (uhttp_*) only speaks POST.
    constexpr wazuh::uds_http::Method method()
    {
        return wazuh::uds_http::Method::Post;
    }

    /// @brief The path. `_internal` marks it as a manager-internal contract between two daemons of
    /// the same version -- nothing outside the manager may target it, and it carries no
    /// compatibility promise.
    constexpr const char* path()
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
    constexpr std::size_t responseTimeoutSeconds()
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
     * name on one manager). The handler counts only what IT sends -- the inline 400/503 rejections;
     * the terminal response is counted by the pipeline, at the site that sends it, so an accepted
     * deletion is counted exactly once. Default-constructed it counts nothing (the null object the
     * tests rely on).
     */
    struct Dependencies
    {
        std::weak_ptr<invsync::sync::SyncPipeline> pipeline;
        std::weak_ptr<invsync::indexer::IIndexerConnectorSync> indexer;
        std::weak_ptr<invsync::indexer::IIndexerConnectorAsync> asyncIndexer;
        invsync::metrics::RequestCounters requestCounters;
    };

    /**
     * @brief Build the route handler: validate the body (400), gate on availability (503), enqueue
     *        a DeleteAgent item WITH its responder, and answer nothing -- the pipeline answers once
     *        the purge has flushed.
     */
    wazuh::uds_http::RouteHandler makeHandler(Dependencies dependencies);

} // namespace invsync::endpoints::delete_agent

#endif // _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP
