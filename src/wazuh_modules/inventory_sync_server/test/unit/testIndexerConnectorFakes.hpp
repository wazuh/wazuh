/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP
#define _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP

#include "indexer/IIndexerConnectorAsync.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "indexer/IIndexerSession.hpp"
#include "indexer/indexerConnectorAsyncAdapter.hpp"
#include "indexer/indexerConnectorSyncAdapter.hpp"
#include "indexer/indexerSessionAdapter.hpp"
#include "inventorySyncServerTestHooks.hpp"
#include "vd/IVdScanner.hpp"
#include "vd/vdScannerFactory.hpp"

#include <json.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace invsync::test
{

    /**
     * @brief Shared record of what the facade built and tore down, across all three indexer slots.
     *
     * A single record rather than three independent counters, because independent counters cannot
     * express the RELATIVE teardown order that stop() now specifies (async, then sync, then session).
     */
    struct ConnectorEvents
    {
        std::mutex m_mutex;                   ///< Guards m_destroyed and m_writes.
        std::vector<std::string> m_destroyed; ///< "async"/"sync"/"session", in destruction order.
        std::atomic<int> m_sessionBuilds {0}; ///< Times the session factory was invoked.
        std::atomic<int> m_syncBuilds {0};    ///< Times the sync connector factory was invoked.
        std::atomic<int> m_asyncBuilds {0};   ///< Times the async connector factory was invoked.
        /// What the async fake reports from isAvailable(). Lets a test drive the endpoints' 503 gate
        /// without an unreachable host, since the fake never touches a network.
        std::atomic<bool> m_asyncAvailable {true};
        /// Same flag for the sync fake, for the pipeline's own availability gate (F2).
        std::atomic<bool> m_syncAvailable {true};
        /// Writes seen by the async fake: (id, index, data).
        std::vector<std::tuple<std::string, std::string, std::string>> m_writes;
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
        /// While true, scan() BLOCKS until openScanGate() -- for cross-lane ordering tests.
        bool m_scanGateClosed {false};
        std::condition_variable m_scanGateCv;
        std::atomic<int> m_scanEntered {0}; ///< Times scan() was entered (before gate/injection).

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

        void recordWrite(std::string id, std::string index, std::string data)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_writes.emplace_back(std::move(id), std::move(index), std::move(data));
        }

        std::vector<std::tuple<std::string, std::string, std::string>> writes()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_writes;
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

        void throwIfInjected(const char* op)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_syncThrowOn == op)
            {
                throw std::runtime_error {std::string {"injected failure in "} + op};
            }
        }

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

    /// Records its own destruction into the shared event record, so teardown order can be pinned.
    template<typename TInterface>
    class FakeIndexerObject final : public TInterface
    {
    public:
        FakeIndexerObject(std::shared_ptr<ConnectorEvents> events, const char* name)
            : m_events {std::move(events)}
            , m_name {name}
        {
        }

        ~FakeIndexerObject() override
        {
            if (m_events)
            {
                m_events->recordDestruction(m_name);
            }
        }

    private:
        std::shared_ptr<ConnectorEvents> m_events;
        const char* m_name;
    };

    /// Session fake: nothing to forward, its construction succeeding is the whole contract.
    using FakeIndexerSession = FakeIndexerObject<invsync::indexer::IIndexerSession>;

    /**
     * @brief Sync connector fake: records every seam call into the shared event record.
     *
     * Its own class (not a shared template with the async fake) because past isAvailable() the two
     * seams share no method. Operations never touch a network: writes append to
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
                m_events->throwIfInjected("bulkIndex");
                m_events->recordSyncOp("bulkIndex", std::string {id}, std::string {index}, std::string {data}, {});
            }
        }

        void
        bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version) override
        {
            if (m_events)
            {
                m_events->throwIfInjected("bulkIndex");
                m_events->recordSyncOp(
                    "bulkIndex", std::string {id}, std::string {index}, std::string {data}, std::string {version});
            }
        }

        void bulkDelete(std::string_view id, std::string_view index) override
        {
            if (m_events)
            {
                m_events->throwIfInjected("bulkDelete");
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

    private:
        std::shared_ptr<ConnectorEvents> m_events;
        const char* m_name;
    };

    /**
     * @brief Async connector fake.
     *
     * Writes are recorded so the facade tests can assert on them; the per-endpoint suites use their
     * own local fakes instead, which record per instance.
     */
    class FakeIndexerConnectorAsync final : public invsync::indexer::IIndexerConnectorAsync
    {
    public:
        FakeIndexerConnectorAsync(std::shared_ptr<ConnectorEvents> events, const char* name)
            : m_events {std::move(events)}
            , m_name {name}
        {
        }

        ~FakeIndexerConnectorAsync() override
        {
            if (m_events)
            {
                m_events->recordDestruction(m_name);
            }
        }

        /// Reads the shared flag so a test can make the endpoints' 503 gate fire.
        bool isAvailable() const override
        {
            return m_events == nullptr || m_events->m_asyncAvailable.load();
        }

        void index(std::string_view id, std::string_view index, std::string_view data) override
        {
            if (m_events)
            {
                m_events->recordWrite(std::string {id}, std::string {index}, std::string {data});
            }
        }

        void indexDataStream(std::string_view index, std::string_view data) override
        {
            if (m_events)
            {
                m_events->recordWrite(std::string {}, std::string {index}, std::string {data});
            }
        }

    private:
        std::shared_ptr<ConnectorEvents> m_events;
        const char* m_name;
    };

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

    private:
        std::shared_ptr<ConnectorEvents> m_events;
    };

    /// Installs a FakeVdScanner (sharing @p events) as the module's scan lane seam.
    inline void installFakeVdScanner(const std::shared_ptr<ConnectorEvents>& events)
    {
        invsync::test_hooks::setVdScannerFactoryForTests([events]() -> std::shared_ptr<invsync::vd::IVdScanner>
                                                         { return std::make_shared<FakeVdScanner>(events); });
    }

    /**
     * @brief Installs fakes for all three slots that succeed instantly, bypassing the real objects'
     *        synchronous, network-bound construction entirely.
     *
     * @return The shared event record: build counts per slot plus destruction order.
     */
    inline std::shared_ptr<ConnectorEvents> installAlwaysAvailableFakeIndexers()
    {
        auto events = std::make_shared<ConnectorEvents>();

        invsync::test_hooks::setIndexerSessionFactoryForTests(
            [events](const nlohmann::json&, LoggingContext)
            {
                events->m_sessionBuilds.fetch_add(1);
                return std::make_unique<FakeIndexerSession>(events, "session");
            });
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(
            [events](const nlohmann::json&, const invsync::indexer::IIndexerSession&, LoggingContext)
            {
                events->m_syncBuilds.fetch_add(1);
                return std::make_unique<FakeIndexerConnectorSync>(events, "sync");
            });
        invsync::test_hooks::setIndexerConnectorAsyncFactoryForTests(
            [events](const nlohmann::json&, const invsync::indexer::IIndexerSession&, LoggingContext)
            {
                events->m_asyncBuilds.fetch_add(1);
                return std::make_unique<FakeIndexerConnectorAsync>(events, "async");
            });

        return events;
    }

    /// All three healthy except the session, which always throws @p reason.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersWithFailingSession(std::string reason)
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerSessionFactoryForTests(
            [events, reason = std::move(reason)](const nlohmann::json&,
                                                 LoggingContext) -> std::unique_ptr<invsync::indexer::IIndexerSession>
            {
                events->m_sessionBuilds.fetch_add(1);
                throw std::runtime_error(reason);
            });
        return events;
    }

    /// All three healthy except the sync connector, which always throws @p reason.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersWithFailingSync(std::string reason)
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(
            [events,
             reason = std::move(reason)](const nlohmann::json&,
                                         const invsync::indexer::IIndexerSession&,
                                         LoggingContext) -> std::unique_ptr<invsync::indexer::IIndexerConnectorSync>
            {
                events->m_syncBuilds.fetch_add(1);
                throw std::runtime_error(reason);
            });
        return events;
    }

    /// All three healthy except the async connector, which always throws @p reason.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersWithFailingAsync(std::string reason)
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerConnectorAsyncFactoryForTests(
            [events,
             reason = std::move(reason)](const nlohmann::json&,
                                         const invsync::indexer::IIndexerSession&,
                                         LoggingContext) -> std::unique_ptr<invsync::indexer::IIndexerConnectorAsync>
            {
                events->m_asyncBuilds.fetch_add(1);
                throw std::runtime_error(reason);
            });
        return events;
    }

    /// The async connector throws for its first @p failures invocations, then succeeds. Lets a test
    /// pin that the slots which already succeeded are not rebuilt while another one keeps retrying.
    inline std::shared_ptr<ConnectorEvents> installFakeIndexersWithAsyncFailingTimes(int failures)
    {
        auto events = installAlwaysAvailableFakeIndexers();
        invsync::test_hooks::setIndexerConnectorAsyncFactoryForTests(
            [events, failures](const nlohmann::json&,
                               const invsync::indexer::IIndexerSession&,
                               LoggingContext) -> std::unique_ptr<invsync::indexer::IIndexerConnectorAsync>
            {
                const auto attempt = events->m_asyncBuilds.fetch_add(1);
                if (attempt < failures)
                {
                    throw std::runtime_error("async connector not ready yet");
                }
                return std::make_unique<FakeIndexerConnectorAsync>(events, "async");
            });
        return events;
    }

    /**
     * @brief Restores the real, production factories for all three slots.
     *
     * Call from TearDown(): an override made by one test must never leak into the next, and this is
     * the only reset point. Resetting only some of them would leave the others faked for the rest of
     * the process.
     */
    inline void resetIndexerConnectorFactoriesToProduction()
    {
        invsync::test_hooks::setIndexerSessionFactoryForTests(
            [](const nlohmann::json& config, LoggingContext logging)
            { return std::make_unique<invsync::indexer::IndexerSessionAdapter>(config, std::move(logging)); });
        invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(
            [](const nlohmann::json& config, const invsync::indexer::IIndexerSession& session, LoggingContext logging)
            {
                const auto& adapter = dynamic_cast<const invsync::indexer::IndexerSessionAdapter&>(session);
                return std::make_unique<invsync::indexer::IndexerConnectorSyncAdapter>(
                    config, adapter.session(), std::move(logging));
            });
        invsync::test_hooks::setIndexerConnectorAsyncFactoryForTests(
            [](const nlohmann::json& config, const invsync::indexer::IIndexerSession& session, LoggingContext logging)
            {
                const auto& adapter = dynamic_cast<const invsync::indexer::IndexerSessionAdapter&>(session);
                return std::make_unique<invsync::indexer::IndexerConnectorAsyncAdapter>(
                    config, adapter.session(), std::move(logging));
            });
        invsync::test_hooks::setVdScannerFactoryForTests([]() { return invsync::vd::makeProductionVdScanner(); });
    }

} // namespace invsync::test

#endif // _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP
