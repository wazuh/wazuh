/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP
#define _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP

#include "indexer/IIndexerConnectorSync.hpp"
#include "indexer/indexerClientSyncAdapter.hpp"
#include "indexer/indexerFactories.hpp"
#include "inventorySyncServerTestHooks.hpp"
#include "vd/IVdScanner.hpp"
#include "vd/vdScannerFactory.hpp"

// Not used in this header itself: several sibling *_test.cpp files include this header for its
// fakes and then reach for wazuh::uds_http types (HttpRequest/HttpResponse/...) unqualified,
// relying on it transitively -- removing it breaks their build, not this file's.
#include <uds_http_server/IUdsHttpServer.hpp>

#include <indexer_client/client.hpp>
#include <indexer_client/runtime.hpp>

#include <json.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace invsync::test
{

    /**
     * @brief Scripted `agent-state` (or `inventory`) writer: records what the endpoints and the pipeline hand it.
     *
     * post() answers `accepted` unless a test scripted a refusal (refuseWith()); cancel() records the tag and
     * answers a default CancelTicket (the pipeline never awaits it). group() answers a default-constructed Group,
     * which has no state behind it: every add() on it is refused InvalidState. A Group cannot be faked without the
     * client library's internals, so a test that needs real tickets (held, failed, 404) runs the real runtime on
     * the library's fake indexer instead (agentStateOrdering_test.cpp, syncPipeline_test.cpp's by-id cases).
     */
    class FakeWriter final : public indexer_client::IWriter
    {
    public:
        indexer_client::Submit submit(indexer_client::Op, indexer_client::Callback) override
        {
            indexer_client::Submit refused;
            refused.cause = indexer_client::Cause::InvalidState;
            refused.reason = "FakeWriter: submit() is not scripted";
            return refused;
        }

        indexer_client::Posted post(indexer_client::Op op) override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_calls.emplace_back("post:" + op.tag);
            m_posted.push_back(std::move(op));
            return m_postResult;
        }

        indexer_client::Group group() override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_calls.emplace_back("group");
            return indexer_client::Group {};
        }

        indexer_client::CancelTicket cancel(std::string_view tag) override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_calls.emplace_back("cancel:" + std::string {tag});
            m_cancelled.emplace_back(tag);
            return indexer_client::CancelTicket {};
        }

        /// From now on post() is refused with @p cause.
        void refuseWith(indexer_client::Cause cause, std::string reason = "scripted refusal")
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_postResult.accepted = false;
            m_postResult.cause = cause;
            m_postResult.reason = std::move(reason);
        }

        /// From now on post() is accepted again.
        void accept()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_postResult = indexer_client::Posted {true, indexer_client::Cause::None, {}};
        }

        /// Every op post() received, in call order (accepted or not).
        std::vector<indexer_client::Op> posted() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_posted;
        }

        /// Every tag cancel() received, in call order.
        std::vector<std::string> cancelled() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_cancelled;
        }

        /// Every call, in order: "post:<tag>", "group", "cancel:<tag>".
        std::vector<std::string> calls() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_calls;
        }

    private:
        mutable std::mutex m_mutex;
        indexer_client::Posted m_postResult {true, indexer_client::Cause::None, {}};
        std::vector<indexer_client::Op> m_posted;
        std::vector<std::string> m_cancelled;
        std::vector<std::string> m_calls;
    };

    /// Scripted query handle: records every delete-by-query and answers `{"deleted":N}` unless scripted.
    class FakeQuery final : public indexer_client::IQuery
    {
    public:
        struct Dbq
        {
            std::vector<std::string> indices;
            nlohmann::json query;
        };

        indexer_client::Outcome<nlohmann::json> search(std::string_view,
                                                       const nlohmann::json&,
                                                       const indexer_client::QueryOptions&,
                                                       indexer_client::Deadline) override
        {
            return unsupported<nlohmann::json>();
        }

        indexer_client::Outcome<indexer_client::Unit> searchAfter(std::string_view,
                                                                  nlohmann::json,
                                                                  std::function<bool(const nlohmann::json&)>,
                                                                  const indexer_client::QueryOptions&,
                                                                  indexer_client::Deadline) override
        {
            return unsupported<indexer_client::Unit>();
        }

        indexer_client::Outcome<indexer_client::Pit> pit(std::vector<std::string>,
                                                         indexer_client::PitOptions,
                                                         const indexer_client::QueryOptions&,
                                                         indexer_client::Deadline) override
        {
            return unsupported<indexer_client::Pit>();
        }

        indexer_client::Outcome<nlohmann::json> deleteByQuery(std::vector<std::string> indices,
                                                              const nlohmann::json& query,
                                                              indexer_client::DbqOptions,
                                                              const indexer_client::QueryOptions&,
                                                              indexer_client::Deadline) override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_dbqs.push_back({std::move(indices), query});
            if (m_failWith != indexer_client::Cause::None)
            {
                return indexer_client::Outcome<nlohmann::json>::failure(m_failWith, "scripted failure");
            }
            return indexer_client::Outcome<nlohmann::json>::success(nlohmann::json {{"deleted", m_deleted}});
        }

        indexer_client::Outcome<nlohmann::json> updateByQuery(std::vector<std::string>,
                                                              const nlohmann::json&,
                                                              const indexer_client::QueryOptions&,
                                                              indexer_client::Deadline) override
        {
            return unsupported<nlohmann::json>();
        }

        indexer_client::Outcome<bool>
        indexExists(std::string_view, const indexer_client::QueryOptions&, indexer_client::Deadline) override
        {
            return unsupported<bool>();
        }

        std::vector<Dbq> dbqs() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_dbqs;
        }

        void failWith(indexer_client::Cause cause)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_failWith = cause;
        }

        void deleted(std::uint64_t count)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_deleted = count;
        }

    private:
        template<typename T>
        static indexer_client::Outcome<T> unsupported()
        {
            return indexer_client::Outcome<T>::failure(indexer_client::Cause::InvalidState, "FakeQuery: not scripted");
        }

        mutable std::mutex m_mutex;
        std::vector<Dbq> m_dbqs;
        indexer_client::Cause m_failWith {indexer_client::Cause::None};
        std::uint64_t m_deleted {0};
    };

    /**
     * @brief Shared record of what the facade built and tore down: the Client, the sync connectors and the
     *        `agent-state` writer, query and sweeper handles the Client hands out.
     *
     * A single record rather than independent counters, because independent counters cannot express the
     * RELATIVE teardown order that stop() specifies.
     */
    struct ConnectorEvents
    {
        std::mutex m_mutex;                   ///< Guards m_destroyed and m_writes.
        std::vector<std::string> m_destroyed; ///< "sync"/"client", in destruction order.
        std::atomic<int> m_syncBuilds {0};    ///< Times the sync connector factory was invoked.
        std::atomic<int> m_clientBuilds {0};  ///< Times the (fake) indexer client factory was invoked.
        /// The cancellation tag and the chunk cap each sync connector was built with, in build order
        /// (the fake sync factory records them). Guarded by m_mutex.
        std::vector<std::string> m_syncTags;
        std::vector<std::size_t> m_syncCaps;
        /// Times the sync fake's endSession() ran (one per staged session of a batch).
        std::atomic<int> m_endSessions {0};
        /// Times the sync fake's discard() ran (the poisoned-batch and failed-staging paths).
        std::atomic<int> m_discards {0};
        /// When set, the sync fake's flushSessions(n) answers THESE outcomes for a batch of exactly
        /// their size (any other batch size falls through to the seam's all-or-nothing default).
        /// Guarded by m_mutex.
        std::optional<std::vector<invsync::indexer::SessionOutcome>> m_scriptedOutcomes;
        /// Same flag for the sync fake, for the pipeline's own availability gate (F2).
        std::atomic<bool> m_syncAvailable {true};
        /// What the fake Client's health() reports: one node, Available (true) or Down (false). Lets a test
        /// drive the endpoints' 503 gate and the facade's health log without a network.
        std::atomic<bool> m_clientUsable {true};
        /// The bucket specs each fake Client was built with, in build order. Guarded by m_mutex.
        std::vector<std::vector<indexer_client::BucketSpec>> m_clientBucketSpecs;
        /// What the fake Client hands out: the two buckets' writers (null for any other name) and the query.
        std::shared_ptr<FakeWriter> m_inventoryWriter {std::make_shared<FakeWriter>()};
        std::shared_ptr<FakeWriter> m_agentStateWriter {std::make_shared<FakeWriter>()};
        std::shared_ptr<FakeQuery> m_query {std::make_shared<FakeQuery>()};
        /// Times the fake Client's requestClose() ran.
        std::atomic<int> m_clientCloses {0};
        /// Operations seen by the sync fake, in call order: (op, id, index, data, version). `op` is
        /// the seam method name ("bulkIndex"/"bulkDelete"/"deleteByQuery"/"executeUpdateByQuery"/
        /// "executeSearchQuery"); fields the operation lacks stay empty. Guarded by
        /// m_mutex.
        std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string>> m_syncOps;
        std::atomic<int> m_syncFlushes {0}; ///< Times the sync fake's flush() ran.
        /// Canned body the sync fake returns from executeSearchQuery(). Guarded by m_mutex.
        nlohmann::json m_searchResponse = nlohmann::json::object();
        /// When non-empty, executeSearchQuery() pops from here instead (front first) -- lets a test
        /// drive the checksum pagination with a different page per call. Guarded by m_mutex.
        std::deque<nlohmann::json> m_searchResponses;
        /// Seam method name ("bulkIndex"/"bulkDelete"/"deleteByQuery"/"executeUpdateByQuery"/
        /// "executeSearchQuery"/"flush") the sync fake must throw from; empty disables.
        /// Guarded by m_mutex.
        std::string m_syncThrowOn;
        /// When non-empty, an injected failure of an operation that carries a document id (bulkIndex,
        /// bulkDelete) only fires for ids containing this text -- lets a test poison ONE session of a
        /// batch. Guarded by m_mutex.
        std::string m_syncThrowOnIdContaining;
        /// While true, the sync fake's flush() BLOCKS until openFlushGate(). Lets a test hold a
        /// worker inside its batch flush deterministically (group-commit accumulation).
        bool m_flushGateClosed {false};
        std::condition_variable m_flushGateCv;
        /// Times flush() was ENTERED (before the gate/injection). A test polls this to know a
        /// worker is parked at the closed gate before queueing more work behind it.
        std::atomic<int> m_flushEntered {0};
        /// What the VD scanner fake reports from feedReady() (D17 gates).
        std::atomic<bool> m_vdFeedReady {true};
        /// When true, the scanner fake's scan() reports a legitimate skip instead of running.
        std::atomic<bool> m_vdScanSkip {false};
        /// What the VD scanner fake reports from currentFeedOffset(). Defaults to 0 so tests that
        /// don't set a session's feed_offset (also defaulting to 0) see a match and aren't gated.
        std::atomic<std::uint64_t> m_vdCurrentOffset {0};
        /// What the VD scanner fake reports from scannerRunning(). Defaults to true: the offset
        /// gate applies, as it does on a node with vulnerability detection enabled.
        std::atomic<bool> m_vdScannerRunning {true};
        /// What the scanner fake's scanAgent() reports -- the ON-DEMAND scan, which reports its
        /// failures by value rather than by exception. Defaults to Ok.
        std::atomic<invsync::vd::AgentScanOutcome> m_vdAgentScanOutcome {invsync::vd::AgentScanOutcome::Ok};
        /// Run by the scanner fake's scanAgent() on the lane worker, after the gate -- where the
        /// real scanner fences the agent through the coordinator. Set before enqueueing.
        std::function<void(const std::string& agentId)> m_scanAgentHook;
        /// While true, scan() BLOCKS until openScanGate() -- for cross-lane ordering tests.
        bool m_scanGateClosed {false};
        std::condition_variable m_scanGateCv;
        std::atomic<int> m_scanEntered {0}; ///< Times scan() was entered (before gate/injection).
        /// The vdConfiguredEnabled the scanner factory was called with -- lets a test observe the
        /// config.vd_configured_enabled -> scannerFactory chain without a live facade.
        std::atomic<bool> m_vdConfiguredEnabled {false};

        void recordDestruction(const char* what)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_destroyed.emplace_back(what);
        }

        std::vector<std::string> destroyed()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_destroyed;
        }

        void recordSyncOp(std::string op, std::string id, std::string index, std::string data, std::string version)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_syncOps.emplace_back(std::move(op), std::move(id), std::move(index), std::move(data), std::move(version));
        }

        std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string>> syncOps()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_syncOps;
        }

        nlohmann::json searchResponse()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_searchResponses.empty())
            {
                auto response = std::move(m_searchResponses.front());
                m_searchResponses.pop_front();
                return response;
            }
            return m_searchResponse;
        }

        std::optional<std::vector<invsync::indexer::SessionOutcome>> scriptedOutcomes(std::size_t sessions)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_scriptedOutcomes && m_scriptedOutcomes->size() == sessions)
            {
                return m_scriptedOutcomes;
            }
            return std::nullopt;
        }

        void recordSyncBuild(const std::string& tag, std::size_t capBytes)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_syncTags.push_back(tag);
            m_syncCaps.push_back(capBytes);
        }

        void throwIfInjected(const char* op, std::string_view id = {})
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_syncThrowOn == op &&
                (m_syncThrowOnIdContaining.empty() || id.find(m_syncThrowOnIdContaining) != std::string_view::npos))
            {
                if (m_syncThrowCause)
                {
                    throw invsync::indexer::ConnectorError {std::string {"injected failure in "} + op,
                                                            *m_syncThrowCause};
                }
                throw std::runtime_error {std::string {"injected failure in "} + op};
            }
        }

        /// When set, throwIfInjected() throws the seam's typed ConnectorError with this cause
        /// instead of a plain runtime_error. Guarded by m_mutex.
        std::optional<invsync::indexer::ConnectorError::Cause> m_syncThrowCause;

        void closeFlushGate()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_flushGateClosed = true;
        }

        void openFlushGate()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_flushGateClosed = false;
            }
            m_flushGateCv.notify_all();
        }

        void waitAtFlushGate()
        {
            m_flushEntered.fetch_add(1);
            std::unique_lock<std::mutex> lock(m_mutex);
            m_flushGateCv.wait(lock, [this] { return !m_flushGateClosed; });
        }

        void closeScanGate()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_scanGateClosed = true;
        }

        void openScanGate()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_scanGateClosed = false;
            }
            m_scanGateCv.notify_all();
        }

        void waitAtScanGate()
        {
            m_scanEntered.fetch_add(1);
            std::unique_lock<std::mutex> lock(m_mutex);
            m_scanGateCv.wait(lock, [this] { return !m_scanGateClosed; });
        }
    };

    /**
     * @brief Sync connector fake: records every seam call into the shared event record.
     *
     * Operations never touch a network: writes append to
     * ConnectorEvents::m_syncOps, flush() bumps a counter, and executeSearchQuery() returns the
     * canned m_searchResponse -- which is how a test drives the checksum path deterministically.
     */
    class FakeIndexerConnectorSync final : public invsync::indexer::IIndexerConnectorSync
    {
    public:
        FakeIndexerConnectorSync(std::shared_ptr<ConnectorEvents> events, const char* name)
            : m_events {std::move(events)}
            , m_name {name}
        {
        }

        ~FakeIndexerConnectorSync() override
        {
            if (m_events)
            {
                m_events->recordDestruction(m_name);
            }
        }

        /// Reads the shared flag so a test can make the pipeline's availability gate fire.
        bool isAvailable() const override
        {
            return m_events == nullptr || m_events->m_syncAvailable.load();
        }

        void bulkIndex(std::string_view id, std::string_view index, std::string_view data) override
        {
            if (m_events)
            {
                m_events->throwIfInjected("bulkIndex", id);
                m_events->recordSyncOp("bulkIndex", std::string {id}, std::string {index}, std::string {data}, {});
            }
        }

        void
        bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version) override
        {
            if (m_events)
            {
                m_events->throwIfInjected("bulkIndex", id);
                m_events->recordSyncOp(
                    "bulkIndex", std::string {id}, std::string {index}, std::string {data}, std::string {version});
            }
        }

        void bulkDelete(std::string_view id, std::string_view index) override
        {
            if (m_events)
            {
                m_events->throwIfInjected("bulkDelete", id);
                m_events->recordSyncOp("bulkDelete", std::string {id}, std::string {index}, {}, {});
            }
        }

        void
        deleteByQuery(const std::string& index, const std::string& agentId, const std::string& clusterName) override
        {
            if (m_events)
            {
                m_events->throwIfInjected("deleteByQuery");
                // agentId rides in the id column; clusterName in the data column.
                m_events->recordSyncOp("deleteByQuery", agentId, index, clusterName, {});
            }
        }

        void executeUpdateByQuery(const std::vector<std::string>& indices, const nlohmann::json& updateQuery) override
        {
            if (m_events)
            {
                std::string joined;
                for (const auto& index : indices)
                {
                    joined += joined.empty() ? index : ("," + index);
                }
                m_events->throwIfInjected("executeUpdateByQuery");
                m_events->recordSyncOp("executeUpdateByQuery", {}, joined, updateQuery.dump(), {});
            }
        }

        nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery) override
        {
            if (!m_events)
            {
                return nlohmann::json::object();
            }
            m_events->throwIfInjected("executeSearchQuery");
            m_events->recordSyncOp("executeSearchQuery", {}, index, searchQuery.dump(), {});
            return m_events->searchResponse();
        }

        void flush() override
        {
            if (m_events)
            {
                m_events->waitAtFlushGate();
                m_events->throwIfInjected("flush");
                m_events->m_syncFlushes.fetch_add(1);
            }
        }

        /// Counted, so a test can pin that every staged session's range was closed.
        void endSession() override
        {
            if (m_events)
            {
                m_events->m_endSessions.fetch_add(1);
            }
        }

        /// With scripted outcomes of the batch's size: those, behind the same gate as flush() so a
        /// test can still park the worker; otherwise the seam's all-or-nothing default over flush().
        std::vector<invsync::indexer::SessionOutcome> flushSessions(std::size_t sessions) override
        {
            if (m_events)
            {
                if (auto scripted = m_events->scriptedOutcomes(sessions))
                {
                    m_events->waitAtFlushGate();
                    m_events->m_syncFlushes.fetch_add(1);
                    return *scripted;
                }
            }
            return invsync::indexer::IIndexerConnectorSync::flushSessions(sessions);
        }

        void discard() override
        {
            if (m_events)
            {
                m_events->m_discards.fetch_add(1);
            }
        }

    private:
        std::shared_ptr<ConnectorEvents> m_events;
        const char* m_name;
    };

    /**
     * @brief Stand-in for the module's indexer Client (I144, I148): the two bucket writers, the query handle and
     *        a health view the test drives.
     *
     * The facade's startup gate builds a Client through the IndexerClientFactory and takes the `agent-state`
     * writer and the query from it -- a null writer or null query fails the gate -- so this fake hands out the
     * ConnectorEvents' scripted ones. It reports one node, Available while `m_clientUsable` is true. A test that
     * needs the real thing (runtime, bucket, ordering, metrics) installs the production factory over a real
     * RuntimeRef instead.
     */
    class FakeIndexerClient final : public indexer_client::IClient
    {
    public:
        explicit FakeIndexerClient(std::shared_ptr<ConnectorEvents> events = std::make_shared<ConnectorEvents>())
            : m_events {std::move(events)}
        {
        }

        ~FakeIndexerClient() override
        {
            m_events->recordDestruction("client");
        }

        std::shared_ptr<indexer_client::IWriter> writer(std::string_view bucket) override
        {
            if (bucket == invsync::indexer::AGENT_STATE_BUCKET)
            {
                return m_events->m_agentStateWriter;
            }
            if (bucket == invsync::indexer::INVENTORY_BUCKET)
            {
                return m_events->m_inventoryWriter;
            }
            return nullptr;
        }

        std::shared_ptr<indexer_client::IQuery> query() override
        {
            return m_events->m_query;
        }

        indexer_client::HealthView health() const override
        {
            indexer_client::HealthView view;
            indexer_client::HealthView::Node node;
            node.url = "http://127.0.0.1:9200";
            node.state = m_events->m_clientUsable.load() ? indexer_client::HealthView::NodeState::Available
                                                         : indexer_client::HealthView::NodeState::Down;
            view.nodes.push_back(std::move(node));
            return view;
        }

        void requestClose() override
        {
            m_events->m_clientCloses.fetch_add(1);
        }

        indexer_client::Outcome<indexer_client::CloseReport> awaitClosed(indexer_client::Deadline) override
        {
            return indexer_client::Outcome<indexer_client::CloseReport>::success({});
        }

        indexer_client::ClientMetrics metrics() const override
        {
            return {};
        }

    private:
        std::shared_ptr<ConnectorEvents> m_events;
    };

    /// The production IndexerClientFactory as the facade wires it: a null runtime or a refused
    /// RuntimeRef::client() throws, which is what fails the sync stage of the startup gate (I131).
    /// Kept here so a test can wrap it (IndexerGating.StopReleasesClient) and so the reset restores it.
    inline invsync::indexer::IndexerClientFactory productionIndexerClientFactory()
    {
        return [](const void* runtime,
                  const std::vector<indexer_client::BucketSpec>& buckets) -> std::shared_ptr<indexer_client::IClient>
        {
            if (runtime == nullptr)
            {
                throw std::runtime_error("no indexer_client runtime was published to the module");
            }
            auto client = static_cast<const indexer_client::RuntimeRef*>(runtime)->client(
                invsync::indexer::INDEXER_CLIENT_CONSUMER, buckets);
            if (!client.ok())
            {
                throw std::runtime_error(std::string {"the indexer client was refused: "} +
                                         indexer_client::toString(client.cause) + ": " + client.reason);
            }
            return client.value;
        };
    }

    /// The production IndexerConnectorSyncFactory: one IndexerClientSyncAdapter per worker.
    inline invsync::indexer::IndexerConnectorSyncFactory productionIndexerConnectorSyncFactory()
    {
        return [](std::shared_ptr<indexer_client::IClient> client,
                  const invsync::indexer::AdapterOptions& options,
                  std::shared_ptr<const std::atomic<bool>> closing,
                  const std::string& tag) -> std::unique_ptr<invsync::indexer::IIndexerConnectorSync>
        {
            return std::make_unique<invsync::indexer::IndexerClientSyncAdapter>(
                std::move(client), options, std::move(closing), tag);
        };
    }

    /**
     * @brief VD scanner fake for the scan lane: the D22 gating without a CVE feed.
     *
     * scan() records itself as a "scan" op on the SAME timeline as the connector ops, which is
     * what lets a test assert the scan-BEFORE-index ordering with one vector. Failure is injected
     * through m_syncThrowOn ("scan"); skips through m_vdScanSkip; the feed gate through
     * m_vdFeedReady; and m_scanGate parks the lane worker mid-scan deterministically.
     */
    class FakeVdScanner final : public invsync::vd::IVdScanner
    {
    public:
        explicit FakeVdScanner(std::shared_ptr<ConnectorEvents> events)
            : m_events {std::move(events)}
        {
        }

        bool feedReady() const override
        {
            return m_events->m_vdFeedReady.load();
        }

        bool scannerRunning() const override
        {
            return m_events->m_vdScannerRunning.load();
        }

        std::uint64_t currentFeedOffset() const override
        {
            return m_events->m_vdCurrentOffset.load();
        }

        invsync::vd::ScanVerdict scan(const invsync::sync::ValidatedSession& session) override
        {
            m_events->waitAtScanGate();
            m_events->throwIfInjected("scan");
            m_events->recordSyncOp("scan", session.agentId, {}, {}, {});
            return m_events->m_vdScanSkip.load() ? invsync::vd::ScanVerdict::Skipped : invsync::vd::ScanVerdict::Ok;
        }

        invsync::vd::AgentScanOutcome scanAgent(const std::string& agentId) override
        {
            // Through the SAME gate and the same op log as scan(): a test that parks a session
            // mid-scan has to be able to park an on-demand scan the same way, and the ordering
            // tests read both from one timeline.
            m_events->waitAtScanGate();
            if (m_events->m_scanAgentHook)
            {
                m_events->m_scanAgentHook(agentId);
            }
            m_events->recordSyncOp("scanAgent", agentId, {}, {}, {});
            return m_events->m_vdAgentScanOutcome.load();
        }

    private:
        std::shared_ptr<ConnectorEvents> m_events;
    };

    /// Installs a FakeVdScanner (sharing @p events) as the module's scan lane seam.
    inline void installFakeVdScanner(const std::shared_ptr<ConnectorEvents>& events)
    {
        invsync::test_hooks::setVdScannerFactoryForTests(
            [events](bool vdConfiguredEnabled) -> std::shared_ptr<invsync::vd::IVdScanner>
            {
                events->m_vdConfiguredEnabled.store(vdConfiguredEnabled);
                return std::make_shared<FakeVdScanner>(events);
            });
    }

    /**
     * @brief Installs fakes for both slots that succeed instantly (the Client and the sync connectors), bypassing
     *        the real objects' runtime entirely.
     *
     * @return The shared event record: build counts per slot, the scripted writers and query, destruction order.
     */
    inline std::shared_ptr<ConnectorEvents> installAlwaysAvailableFakeIndexers()
    {
        auto events = std::make_shared<ConnectorEvents>();

        invsync::test_hooks::setIndexerClientFactoryForTests(
            [events](const void*,
                     const std::vector<indexer_client::BucketSpec>& buckets) -> std::shared_ptr<indexer_client::IClient>
            {
                events->m_clientBuilds.fetch_add(1);
                {
                    std::lock_guard<std::mutex> lock(events->m_mutex);
                    events->m_clientBucketSpecs.push_back(buckets);
                }
                return std::make_shared<FakeIndexerClient>(events);
            });
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(
            [events](std::shared_ptr<indexer_client::IClient>,
                     const invsync::indexer::AdapterOptions& options,
                     std::shared_ptr<const std::atomic<bool>>,
                     const std::string& tag) -> std::unique_ptr<invsync::indexer::IIndexerConnectorSync>
            {
                events->m_syncBuilds.fetch_add(1);
                events->recordSyncBuild(tag, options.capBytes);
                return std::make_unique<FakeIndexerConnectorSync>(events, "sync");
            });

        return events;
    }

    /// Everything healthy except the Client, which always throws @p reason.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersWithFailingClient(std::string reason)
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerClientFactoryForTests(
            [events, reason = std::move(reason)](
                const void*, const std::vector<indexer_client::BucketSpec>&) -> std::shared_ptr<indexer_client::IClient>
            {
                events->m_clientBuilds.fetch_add(1);
                throw std::runtime_error(reason);
            });
        return events;
    }

    /// Everything healthy except the sync connector, which always throws @p reason.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersWithFailingSync(std::string reason)
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(
            [events,
             reason = std::move(reason)](std::shared_ptr<indexer_client::IClient>,
                                         const invsync::indexer::AdapterOptions&,
                                         std::shared_ptr<const std::atomic<bool>>,
                                         const std::string&) -> std::unique_ptr<invsync::indexer::IIndexerConnectorSync>
            {
                events->m_syncBuilds.fetch_add(1);
                throw std::runtime_error(reason);
            });
        return events;
    }

    /// The sync connector throws for its first @p failures invocations, then succeeds. Lets a test pin that the
    /// slots which already succeeded are not rebuilt while another one keeps retrying.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersWithSyncFailingTimes(int failures)
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(
            [events, failures](std::shared_ptr<indexer_client::IClient>,
                               const invsync::indexer::AdapterOptions& options,
                               std::shared_ptr<const std::atomic<bool>>,
                               const std::string& tag) -> std::unique_ptr<invsync::indexer::IIndexerConnectorSync>
            {
                const auto attempt = events->m_syncBuilds.fetch_add(1);
                if (attempt < failures)
                {
                    throw std::runtime_error("sync connector not ready yet");
                }
                events->recordSyncBuild(tag, options.capBytes);
                return std::make_unique<FakeIndexerConnectorSync>(events, "sync");
            });
        return events;
    }

    /// The production Client factory and the production IndexerClientSyncAdapter per worker: the caller publishes a
    /// started RuntimeRef through `config.indexer_runtime`.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersOverRealClient()
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerClientFactoryForTests(productionIndexerClientFactory());
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(productionIndexerConnectorSyncFactory());
        return events;
    }

    /**
     * @brief Restores the real, production factories for every slot (indexer client, sync and the scanner).
     *
     * Call from TearDown(): an override made by one test must never leak into the next, and this is
     * the only reset point. Resetting only some of them would leave the others faked for the rest of
     * the process.
     */
    inline void resetIndexerConnectorFactoriesToProduction()
    {
        invsync::test_hooks::setIndexerClientFactoryForTests(productionIndexerClientFactory());
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(productionIndexerConnectorSyncFactory());
        invsync::test_hooks::setVdScannerFactoryForTests(
            [](bool vdConfiguredEnabled) { return invsync::vd::makeProductionVdScanner(vdConfiguredEnabled); });
    }

} // namespace invsync::test

#endif // _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP
