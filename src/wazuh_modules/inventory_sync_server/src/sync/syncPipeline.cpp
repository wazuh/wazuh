/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync/syncPipeline.hpp"

#include "indexer/connectorFailure.hpp"
#include "loggerHelper.h"

#include <wazuh_metrics/manager.hpp>

#include <algorithm>
#include <chrono>
#include <exception>
#include <functional>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace
{
    constexpr auto PIPELINE_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:sync"};

    const LogFn& logFn()
    {
        static const LogFn instance {PIPELINE_LOGTAG};
        return instance;
    }

    constexpr auto SHUTTING_DOWN_BODY {R"({"error":"Service unavailable","code":503})"};
    constexpr auto INDEXER_UNAVAILABLE_BODY {R"({"error":"Service unavailable","code":503})"};
} // namespace

namespace invsync::sync
{

    SyncPipeline::SyncPipeline(SyncPipelineConfig config,
                               std::vector<std::shared_ptr<indexer::IIndexerConnectorSync>> connectors,
                               std::string managerClusterName,
                               std::shared_ptr<vd::AgentInFlightRegistry> registry,
                               std::shared_ptr<wazuh::metrics::IManager> metrics)
        : m_config {config}
        , m_metrics {metrics ? std::move(metrics) : std::make_shared<wazuh::metrics::Manager>()}
        , m_processor {std::move(managerClusterName), m_metrics, config.sessionQueryBatchSize}
        , m_registry {std::move(registry)}
        , m_connectors {std::move(connectors)}
    {
        if (m_connectors.empty())
        {
            throw std::invalid_argument {"the sync pipeline needs at least one indexer connector"};
        }

        m_requestCounters = invsync::metrics::RequestCounters::make(*m_metrics);
        m_shedTotal =
            m_metrics->getOrCreateCounter(invsync::metrics::PIPELINE_SHED_TOTAL,
                                          "Enqueue refusals: the pipeline queue byte cap "
                                          "('wazuh_modules.inventory_sync_server_sync_queue_bytes') was reached",
                                          "count");
        m_bulkFlushes =
            m_metrics->getOrCreateCounter(invsync::metrics::BULK_FLUSHES,
                                          "Pipeline group-commit flushes that confirmed at least one session",
                                          "count");
        m_bulkBytesTotal = m_metrics->getOrCreateCounter(
            invsync::metrics::BULK_BYTES_TOTAL,
            "Request payload bytes of the sessions group commits confirmed (wire FlatBuffer "
            "bytes; the serialized indexer bytes are sync.bytes.ingested)",
            "bytes");
        m_bulkSessionsTotal = m_metrics->getOrCreateCounter(
            invsync::metrics::BULK_SESSIONS_TOTAL, "Sessions answered 200 by group-commit flushes", "count");
        // sync.indexer.bulk.requests / bulk.bytes.total / conflict.retries are pull metrics of the
        // facade now (read from the indexer client's own counters, I140); only the exhausted
        // conflicts are an outcome the pipeline decides.
        m_indexerConflictExhausted =
            m_metrics->getOrCreateCounter(invsync::metrics::INDEXER_CONFLICT_EXHAUSTED,
                                          "By-query operations whose version-conflict allowance ran out, "
                                          "answered 503 + Retry-After: a competing writer of the same "
                                          "agent's documents was still running",
                                          "count");
        const auto failureCounter = [this](const char* cause, const char* description)
        {
            return m_metrics->getOrCreateCounter(
                std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + cause, description, "count");
        };
        m_flushFailuresDocuments = failureCounter(
            "documents", "Sessions failed because the indexer rejected their documents or confirmed nothing");
        m_flushFailuresExhausted =
            failureCounter("exhausted", "Sessions failed by an exhausted retry budget (429, transport)");
        m_flushFailuresUnavailable =
            failureCounter("unavailable",
                           "Sessions failed because the indexer could not take the work now: no usable node, "
                           "throttled, queue full, transport, 5xx, closing");
        m_flushFailuresOther = failureCounter("other", "Sessions failed for any other reason");
        m_bulkSessionsFailed = m_metrics->getOrCreateCounter(
            invsync::metrics::BULK_SESSIONS_FAILED,
            "Sessions answered 500/503 by a group commit: each session answers for its own operations, "
            "so the healthy sessions of the same batch still get their 200",
            "count");
        m_durationBulk = m_metrics->getOrCreateHistogram(
            invsync::metrics::SESSION_DURATION_BULK, "Enqueue-to-response time of bulk sessions", "microseconds");
        m_durationImmediate = m_metrics->getOrCreateHistogram(invsync::metrics::SESSION_DURATION_IMMEDIATE,
                                                              "Enqueue-to-response time of immediate sessions",
                                                              "microseconds");

        m_shards.reserve(m_connectors.size());
        m_shardDepth.reserve(m_connectors.size());
        m_shardBytes.reserve(m_connectors.size());
        for (std::size_t i = 0; i < m_connectors.size(); ++i)
        {
            m_shards.push_back(std::make_unique<Shard>());
            m_shardDepth.push_back(m_metrics->getOrCreateGaugeInt(
                invsync::metrics::shardName(i, "depth"), "Items queued on this shard", "items"));
            m_shardBytes.push_back(m_metrics->getOrCreateGaugeInt(
                invsync::metrics::shardName(i, "bytes"), "Payload bytes queued on this shard", "bytes"));
        }

        // Threads last, once every shard exists: a workerLoop indexes into m_shards/m_connectors
        // from its first instruction.
        m_workers.reserve(m_connectors.size());
        for (std::size_t i = 0; i < m_connectors.size(); ++i)
        {
            m_workers.emplace_back(&SyncPipeline::workerLoop, this, i);
        }

        if (m_registry)
        {
            // A scan-lane release may be exactly what a parked shard waits for. The registry
            // outlives this pipeline (facade teardown order), and by the time it is destroyed no
            // lane is left to fire this.
            m_registry->addReleaseListener(
                [this]
                {
                    for (auto& shard : m_shards)
                    {
                        std::lock_guard<std::mutex> lock(shard->mutex);
                        shard->cv.notify_all();
                    }
                });
        }

        LOGFN_DEBUG1(logFn(), "Sync pipeline running with %zu worker(s).", m_connectors.size());
    }

    SyncPipeline::~SyncPipeline()
    {
        stop();
    }

    bool SyncPipeline::enqueue(Item item)
    {
        if (m_stopping.load(std::memory_order_acquire))
        {
            return false;
        }

        const auto bytes = item.request ? item.request->body.size() : 0;
        const auto queued = m_queuedBytes.fetch_add(bytes, std::memory_order_acq_rel) + bytes;
        if (m_config.maxQueueBytes != 0 && queued > m_config.maxQueueBytes)
        {
            m_queuedBytes.fetch_sub(bytes, std::memory_order_acq_rel);
            m_shedTotal->add(); // the endpoint answers 503 for this refusal
            return false;
        }

        const auto shardIndex = std::hash<std::string> {}(item.session.agentId) % m_shards.size();
        auto& shard = *m_shards[shardIndex];
        {
            std::lock_guard<std::mutex> lock(shard.mutex);
            if (m_stopping.load(std::memory_order_acquire))
            {
                m_queuedBytes.fetch_sub(bytes, std::memory_order_acq_rel);
                return false;
            }
            shard.queue.push_back(std::move(item));
            m_shardDepth[shardIndex]->add(1);
            m_shardBytes[shardIndex]->add(static_cast<int64_t>(bytes));
        }
        shard.cv.notify_one();
        return true;
    }

    void SyncPipeline::stop()
    {
        {
            std::lock_guard<std::mutex> lock(m_stopMutex);
            if (m_stopped)
            {
                return;
            }
            m_stopped = true;
        }

        m_stopping.store(true, std::memory_order_release);
        for (auto& shard : m_shards)
        {
            // Taking the lock before notifying closes the race against a worker that checked
            // m_stopping and is about to wait: it cannot be BETWEEN the check and the wait while
            // we hold its shard mutex.
            std::lock_guard<std::mutex> lock(shard->mutex);
            shard->cv.notify_all();
        }

        for (auto& worker : m_workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }

        // With every worker joined the queues are frozen; whatever they left is answered 503 so no
        // peer is left waiting out its own timeout. The transport guarantees a late send() after
        // its own stop() is a harmless no-op.
        std::size_t abandoned {0};
        for (auto& shard : m_shards)
        {
            for (auto& item : shard->queue)
            {
                respond(item, 503, SHUTTING_DOWN_BODY);
                ++abandoned;
            }
            shard->queue.clear();
        }
        m_queuedBytes.store(0, std::memory_order_release);
        for (std::size_t i = 0; i < m_shards.size(); ++i)
        {
            m_shardDepth[i]->set(0);
            m_shardBytes[i]->set(0);
        }

        if (abandoned > 0)
        {
            LOGFN_INFO(logFn(),
                       "Sync pipeline stopped; %zu queued request(s) were answered 503 for the agents to retry.",
                       abandoned);
        }
    }

    void SyncPipeline::respond(Item& item,
                               int status,
                               const std::string& body,
                               const std::vector<std::pair<std::string, std::string>>& headers)
    {
        if (item.responder)
        {
            m_requestCounters.count(status);
            if (item.kind == Item::Kind::Session && item.enqueuedAt != std::chrono::steady_clock::time_point {})
            {
                const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                                         std::chrono::steady_clock::now() - item.enqueuedAt)
                                         .count();
                const auto& histogram =
                    (classify(item.session) == SessionKind::BulkData) ? m_durationBulk : m_durationImmediate;
                histogram->observe(static_cast<uint64_t>(elapsed));
            }
            auto response = wazuh::uds_http::HttpResponse::json(status, body);
            response.headers.insert(response.headers.end(), headers.begin(), headers.end());
            item.responder->send(std::move(response));
        }
        if (m_registry)
        {
            // Lane-checked: for a never-acquired item (the stop() drain) this is a no-op and can
            // never free the scan lane's hold on the same agent.
            m_registry->release(item.session.agentId, vd::AgentInFlightRegistry::Lane::Pipeline);
        }
    }

    bool SyncPipeline::popDispatchable(Shard& shard, Item& item)
    {
        // Caller holds shard.mutex.
        if (!m_registry)
        {
            if (shard.queue.empty())
            {
                return false;
            }
            item = std::move(shard.queue.front());
            shard.queue.pop_front();
            return true;
        }

        // First item whose agent the registry lets the pipeline take. Skipping a busy agent's
        // item keeps per-agent FIFO (its items stay queued, in order) without head-of-line
        // blocking the shard's OTHER agents while a scan runs. Reentrant: with group commit,
        // several staged sessions of one agent hold it at once, released one by one on respond.
        for (auto it = shard.queue.begin(); it != shard.queue.end(); ++it)
        {
            if (m_registry->tryAcquire(
                    it->session.agentId, vd::AgentInFlightRegistry::Lane::Pipeline, /*reentrant=*/true))
            {
                item = std::move(*it);
                shard.queue.erase(it);
                return true;
            }
        }
        return false;
    }

    void SyncPipeline::respondFailure(Item& item, indexer::ConnectorError::Cause cause)
    {
        // Decided by the cause alone (I135): the cause already says whether the indexer was the
        // problem, so nothing re-asks isAvailable() after the fact.
        const auto failure = indexer::failureResponse(cause, m_config.conflictRetryAfterSeconds);
        if (cause == indexer::ConnectorError::Cause::ConflictsExhausted)
        {
            m_indexerConflictExhausted->add();
        }
        if (failure.retryAfter)
        {
            respond(item, failure.status, failure.body, {{"Retry-After", *failure.retryAfter}});
        }
        else
        {
            respond(item, failure.status, failure.body);
        }
    }

    void SyncPipeline::respondConnectorFailure(std::vector<Item>& items, indexer::ConnectorError::Cause cause)
    {
        for (auto& item : items)
        {
            respondFailure(item, cause);
        }
    }

    void SyncPipeline::countFlushFailure(indexer::ConnectorError::Cause cause)
    {
        const std::string_view suffix {indexer::failureMetric(cause)};
        if (suffix == "documents")
        {
            m_flushFailuresDocuments->add();
        }
        else if (suffix == "exhausted")
        {
            m_flushFailuresExhausted->add();
        }
        else if (suffix == "unavailable")
        {
            m_flushFailuresUnavailable->add();
        }
        else
        {
            m_flushFailuresOther->add();
        }
    }

    void SyncPipeline::flushAndRespond(std::vector<Item>& batch,
                                       std::size_t& batchBytes,
                                       indexer::IIndexerConnectorSync& connector)
    {
        if (batch.empty())
        {
            return;
        }

        // The whole durability contract in one call: flushSessions() sends the staged operations on
        // THIS thread and answers, per session in staging order, whether the indexer took ALL of
        // that session's operations (I136) -- REQ-SYNC-4 without registerNotify. A session answers
        // for its own operations only: one rejected document no longer fails its batch-mates.
        std::vector<indexer::SessionOutcome> outcomes;
        // LCOV_EXCL_START -- flushSessions() reports indexer failures in its outcomes; this guards a
        // connector that throws anyway, so its sessions are still answered.
        try
        {
            outcomes = connector.flushSessions(batch.size());
        }
        catch (const std::exception& e)
        {
            const auto* typed = dynamic_cast<const indexer::ConnectorError*>(&e);
            outcomes.assign(batch.size(),
                            indexer::SessionOutcome {
                                false, typed ? typed->cause() : indexer::ConnectorError::Cause::Other, e.what()});
        }
        // LCOV_EXCL_STOP
        if (outcomes.size() != batch.size())
        {
            // A connector bug, not an indexer outcome: never answer a session with another's result.
            LOGFN_ERROR(logFn(),
                        "A bulk flush answered %zu outcome(s) for %zu session(s); answering every session 500.",
                        outcomes.size(),
                        batch.size());
            outcomes.assign(batch.size(),
                            indexer::SessionOutcome {false, indexer::ConnectorError::Cause::Other, "outcome mismatch"});
        }

        std::size_t okSessions {0};
        std::size_t okBytes {0};
        std::size_t failedSessions {0};
        const indexer::SessionOutcome* firstFailure {nullptr};
        const Item* firstFailedItem {nullptr};
        for (std::size_t i = 0; i < batch.size(); ++i)
        {
            auto& item = batch[i];
            const auto& outcome = outcomes[i];
            if (outcome.ok)
            {
                ++okSessions;
                okBytes += item.request ? item.request->body.size() : 0;
                respond(item, 200, R"({"status":"ok"})");
                continue;
            }

            ++failedSessions;
            if (!firstFailure)
            {
                firstFailure = &outcome;
                firstFailedItem = &item;
            }
            countFlushFailure(outcome.cause);
            respondFailure(item, outcome.cause);
        }

        if (okSessions > 0)
        {
            m_bulkFlushes->add();
            m_bulkSessionsTotal->add(okSessions);
            m_bulkBytesTotal->add(okBytes);
        }
        if (failedSessions > 0)
        {
            m_bulkSessionsFailed->add(failedSessions);
            // One line per flush, not per session: a sick indexer fails whole batches at once.
            LOGFN_WARN(logFn(),
                       "A bulk flush failed %zu of %zu session(s) (first: agent %s, %s). The agents will retry.",
                       failedSessions,
                       batch.size(),
                       firstFailedItem->session.agentId.c_str(),
                       firstFailure->reason.empty() ? "no reason given" : firstFailure->reason.c_str());
        }

        batch.clear();
        batchBytes = 0;
    }

    void SyncPipeline::workerLoop(std::size_t index)
    {
        auto& shard = *m_shards[index];
        auto& connector = *m_connectors[index];

        std::vector<Item> batch;
        std::size_t batchBytes {0};

        while (true)
        {
            Item item;
            bool hasItem {false};
            {
                std::unique_lock<std::mutex> lock(shard.mutex);
                if (batch.empty())
                {
                    // Wait for stop, or for SOMETHING dispatchable: a non-empty queue whose every
                    // agent is scan-busy must keep sleeping (the registry's release listener wakes
                    // this cv), or the worker would spin.
                    shard.cv.wait(lock,
                                  [this, &shard]
                                  {
                                      if (m_stopping.load(std::memory_order_acquire))
                                      {
                                          return true;
                                      }
                                      if (!m_registry)
                                      {
                                          return !shard.queue.empty();
                                      }
                                      return std::any_of(shard.queue.begin(),
                                                         shard.queue.end(),
                                                         [this](const Item& queued)
                                                         {
                                                             return m_registry->couldAcquire(
                                                                 queued.session.agentId,
                                                                 vd::AgentInFlightRegistry::Lane::Pipeline,
                                                                 /*reentrant=*/true);
                                                         });
                                  });
                }
                hasItem = popDispatchable(shard, item);
            }

            if (!hasItem)
            {
                // Queue drained. Close the open batch -- THIS is the group commit's low-load path:
                // one session in, one flush out, same latency as flush-per-request.
                if (!batch.empty())
                {
                    if (m_stopping.load(std::memory_order_acquire))
                    {
                        // Shutdown must not wait on indexer I/O: the staged batch is abandoned and
                        // its sessions answered 503; the agents re-POST next cycle (RF-13).
                        for (auto& pending : batch)
                        {
                            respond(pending, 503, SHUTTING_DOWN_BODY);
                        }
                        batch.clear();
                        batchBytes = 0;
                    }
                    else
                    {
                        flushAndRespond(batch, batchBytes, connector);
                    }
                    continue; // re-check the queue before blocking
                }
                if (m_stopping.load(std::memory_order_acquire))
                {
                    break;
                }
                continue;
            }

            const auto itemBytes = item.request ? item.request->body.size() : 0;
            m_queuedBytes.fetch_sub(itemBytes, std::memory_order_acq_rel);
            m_shardDepth[index]->sub(1);
            m_shardBytes[index]->sub(static_cast<int64_t>(itemBytes));

            if (m_stopping.load(std::memory_order_acquire))
            {
                respond(item, 503, SHUTTING_DOWN_BODY);
                continue;
            }

            // Re-check at dispatch (the admission check may be minutes stale for a queued item):
            // refuse BEFORE staging, so nothing of this session sits in a buffer that cannot
            // flush. The open batch stays -- it was staged when the connector was available, and
            // its own flush will judge it.
            if (!connector.isAvailable())
            {
                respond(item, 503, INDEXER_UNAVAILABLE_BODY);
                continue;
            }

            if (item.kind == Item::Kind::DeleteAgent)
            {
                // The caller is waiting: the endpoint enqueued this item WITH its responder and
                // answered nothing, so respond() below carries the purge's outcome and releases the
                // agent from the registry.
                //
                // Same batch-cut rule as an Immediate session: the deletion executes its own I/O
                // now, and staged writes of an EARLIER session of this agent must reach the indexer
                // first or the delete-then-reinsert order would invert.
                flushAndRespond(batch, batchBytes, connector);

                try
                {
                    auto outcome = m_processor.executeDeleteAgent(item.session.agentId, connector);
                    respond(item, outcome.status, outcome.body);
                }
                catch (const std::exception& e)
                {
                    LOGFN_WARN(logFn(),
                               "Deleting the state documents of agent %s failed: %s. The caller may retry.",
                               item.session.agentId.c_str(),
                               e.what());
                    const auto* typed = dynamic_cast<const indexer::ConnectorError*>(&e);
                    respondFailure(item, typed ? typed->cause() : indexer::ConnectorError::Cause::Other);
                }
                continue;
            }

            if (classify(item.session) == SessionKind::Immediate)
            {
                // Batch cut: an immediate session executes its own I/O NOW, so the staged batch
                // must reach the indexer first or this session's effects (deletes, a checksum
                // read) would overtake bulk writes of an EARLIER session of the same agent.
                flushAndRespond(batch, batchBytes, connector);

                try
                {
                    auto outcome = m_processor.executeImmediate(item.session, connector);
                    respond(item, outcome.status, outcome.body);
                }
                catch (const std::exception& e)
                {
                    LOGFN_WARN(logFn(),
                               "A session from agent %s failed against the indexer: %s. The agent will retry.",
                               item.session.agentId.c_str(),
                               e.what());
                    const auto* typed = dynamic_cast<const indexer::ConnectorError*>(&e);
                    respondFailure(item, typed ? typed->cause() : indexer::ConnectorError::Cause::Other);
                }
                continue;
            }

            ProcessOutcome outcome;
            bool stagingFailed {false};
            try
            {
                outcome = m_processor.stageBulk(item.session, connector);
            }
            catch (const std::exception& e)
            {
                LOGFN_WARN(logFn(),
                           "Staging a session from agent %s failed: %s. The agent will retry.",
                           item.session.agentId.c_str(),
                           e.what());
                stagingFailed = true;
            }

            if (stagingFailed)
            {
                // Only an exception foreign to the connector lands here (a staging rejection marks
                // its session instead of throwing, I142), so the open batch's staging state is
                // unknown: answer everything 500 and discard what is staged rather than send it.
                // The agents re-POST; idempotence is what makes this recovery safe.
                std::vector<Item> failed;
                failed.reserve(batch.size() + 1);
                failed.push_back(std::move(item));
                for (auto& pending : batch)
                {
                    failed.push_back(std::move(pending));
                }
                batch.clear();
                batchBytes = 0;
                m_bulkSessionsFailed->add(failed.size());
                respondConnectorFailure(failed, indexer::ConnectorError::Cause::Other);
                try
                {
                    connector.discard();
                }
                catch (...) // LCOV_EXCL_LINE -- discard() drops local state only
                {
                    // Already answered; nothing staged survives a discard.
                }
                continue;
            }

            if (!outcome.staged)
            {
                respond(item, outcome.status, outcome.body); // 400 or a no-op 200
                continue;
            }

            // Closes this session's range, so the batch's flushSessions() can answer it for its own
            // operations (I136). Only after a staged outcome: a session that staged nothing is not
            // in the batch.
            connector.endSession();
            batch.push_back(std::move(item));
            batchBytes += itemBytes;

            if (batchBytes >= m_config.bulkFlushBytes)
            {
                flushAndRespond(batch, batchBytes, connector);
            }
        }
    }

} // namespace invsync::sync
