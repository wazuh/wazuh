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

#include "vd/vdScanLane.hpp"

#include "loggerHelper.h"

#include <algorithm>
#include <exception>
#include <stdexcept>
#include <utility>

namespace
{
    constexpr auto LANE_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:vd"};

    const LogFn& logFn()
    {
        static const LogFn instance {LANE_LOGTAG};
        return instance;
    }

    constexpr auto SHUTTING_DOWN_BODY {R"({"error":"Service unavailable","code":503})"};
    constexpr auto SCAN_FAILED_BODY {R"({"error":"vulnerability scan failed","code":500})"};
    constexpr auto FEED_NOT_READY_BODY {R"({"error":"vulnerability feed not ready","code":503})"};

    bool isVDSync(const invsync::sync::ValidatedSession& session)
    {
        return session.option == invsync::schema::fb::Option_VDSync;
    }

    bool isVDFirst(const invsync::sync::ValidatedSession& session)
    {
        return session.option == invsync::schema::fb::Option_VDFirst;
    }
} // namespace

namespace invsync::vd
{

    VdScanLane::VdScanLane(VdScanLaneConfig config,
                           std::shared_ptr<IVdScanner> scanner,
                           std::vector<std::shared_ptr<indexer::IIndexerConnectorSync>> connectors,
                           std::shared_ptr<AgentInFlightRegistry> registry,
                           std::string managerClusterName)
        : m_config {config}
        , m_scanner {std::move(scanner)}
        , m_connectors {std::move(connectors)}
        , m_registry {std::move(registry)}
        , m_processor {std::move(managerClusterName)}
    {
        if (!m_scanner || m_connectors.empty() || !m_registry)
        {
            throw std::invalid_argument {"the VD scan lane needs a scanner, a registry and at least one connector"};
        }
        if (m_config.queueSlots == 0)
        {
            m_config.queueSlots = 2 * m_connectors.size();
        }

        // An agent released by the PIPELINE may be exactly what a parked lane item waits for.
        m_registry->addReleaseListener([this] { m_cv.notify_all(); });

        m_workers.reserve(m_connectors.size());
        for (std::size_t i = 0; i < m_connectors.size(); ++i)
        {
            m_workers.emplace_back(&VdScanLane::workerLoop, this, i);
        }

        LOGFN_DEBUG1(logFn(),
                     "VD scan lane running with %zu worker(s) and %zu queue slot(s).",
                     m_connectors.size(),
                     m_config.queueSlots);
    }

    VdScanLane::~VdScanLane()
    {
        stop();
    }

    VdScanLane::Admission VdScanLane::tryEnqueue(Item item)
    {
        if (m_stopping.load(std::memory_order_acquire))
        {
            return Admission::Stopping;
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopping.load(std::memory_order_acquire))
            {
                return Admission::Stopping;
            }
            if (m_queue.size() >= m_config.queueSlots)
            {
                // STATS-PLACEHOLDER: vd_capacity_503
                return Admission::Full;
            }
            if (isVDSync(item.session))
            {
                ++m_vdSyncPending;
            }
            m_queue.push_back(std::move(item));
            // STATS-PLACEHOLDER: vd_lane_depth
        }
        m_cv.notify_one();
        return Admission::Accepted;
    }

    void VdScanLane::stop()
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
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_cv.notify_all();
        }

        // A worker inside a scan finishes it (no cancellation point in VD); everything else exits
        // promptly on the stop flag.
        for (auto& worker : m_workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }

        std::size_t abandoned {0};
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& item : m_queue)
            {
                respond(item, 503, SHUTTING_DOWN_BODY);
                ++abandoned;
            }
            m_queue.clear();
            m_vdSyncPending = 0;
        }
        m_drainCv.notify_all();

        if (abandoned > 0)
        {
            LOGFN_INFO(logFn(),
                       "VD scan lane stopped; %zu queued session(s) were answered 503 for the agents to retry.",
                       abandoned);
        }
    }

    bool VdScanLane::hasVDSyncInFlight() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_vdSyncPending > 0;
    }

    std::vector<std::string> VdScanLane::agentsWithVDFirstInFlight() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto agents = m_inFlightVDFirstAgents;
        for (const auto& item : m_queue)
        {
            if (isVDFirst(item.session))
            {
                agents.push_back(item.session.agentId);
            }
        }
        return agents;
    }

    bool VdScanLane::hasAgentQueued(const std::string& agentId) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return std::any_of(
            m_queue.begin(), m_queue.end(), [&agentId](const Item& item) { return item.session.agentId == agentId; });
    }

    bool VdScanLane::drainVDSync(std::chrono::seconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_drainCv.wait_for(lock, timeout, [this] { return m_vdSyncPending == 0; });
    }

    void VdScanLane::respond(Item& item, int status, const std::string& body)
    {
        if (item.responder)
        {
            // STATS-PLACEHOLDER: requests_total{code}, vd_lane_time_total
            item.responder->send(http::HttpResponse::json(status, body));
        }
    }

    void VdScanLane::respondConnectorFailure(Item& item, indexer::IIndexerConnectorSync& connector)
    {
        bool available {false};
        try
        {
            available = connector.isAvailable();
        }
        catch (...) // LCOV_EXCL_LINE -- isAvailable() does not throw in the real connector
        {
        }
        respond(item,
                available ? 500 : 503,
                available ? R"({"error":"Internal error","code":500})"
                          : R"({"error":"Service unavailable","code":503})");
    }

    void VdScanLane::workerLoop(std::size_t index)
    {
        auto& connector = *m_connectors[index];

        while (true)
        {
            Item item;
            bool hasItem {false};
            bool vdFirst {false};
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock,
                          [this]
                          {
                              if (m_stopping.load(std::memory_order_acquire))
                              {
                                  return true;
                              }
                              // Dispatchable = some queued item whose agent is free in the shared
                              // registry. A busy agent's item stays queued (FIFO per agent) while
                              // other agents' items may pass it.
                              return std::any_of(m_queue.begin(),
                                                 m_queue.end(),
                                                 [this](const Item& queued)
                                                 { return m_registry->isFree(queued.session.agentId); });
                          });

                if (m_stopping.load(std::memory_order_acquire))
                {
                    break;
                }

                for (auto it = m_queue.begin(); it != m_queue.end(); ++it)
                {
                    // isFree() then tryAcquire under the LANE mutex: two lane workers cannot grab
                    // the same item, and a same-agent second item stays parked because tryAcquire
                    // is non-reentrant for the scan lane.
                    if (m_registry->tryAcquire(it->session.agentId,
                                               AgentInFlightRegistry::Lane::Scan,
                                               /*reentrant=*/false))
                    {
                        item = std::move(*it);
                        m_queue.erase(it);
                        hasItem = true;
                        break;
                    }
                }
                if (!hasItem)
                {
                    continue; // every queued agent is busy; wait for a release notification
                }
                vdFirst = isVDFirst(item.session);
                if (vdFirst)
                {
                    m_inFlightVDFirstAgents.push_back(item.session.agentId);
                }
            }

            const auto finish = [&](int status, const std::string& body)
            {
                respond(item, status, body);
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (vdFirst)
                    {
                        m_inFlightVDFirstAgents.erase(std::remove(m_inFlightVDFirstAgents.begin(),
                                                                  m_inFlightVDFirstAgents.end(),
                                                                  item.session.agentId),
                                                      m_inFlightVDFirstAgents.end());
                    }
                    if (isVDSync(item.session) && m_vdSyncPending > 0)
                    {
                        --m_vdSyncPending;
                    }
                }
                m_registry->release(item.session.agentId, AgentInFlightRegistry::Lane::Scan);
                m_drainCv.notify_all();
            };

            if (m_stopping.load(std::memory_order_acquire))
            {
                finish(503, SHUTTING_DOWN_BODY);
                continue;
            }

            // Indexer availability re-check BEFORE the scan: a scan whose inventory could never
            // land would waste minutes to answer a 503 the connector already knows.
            if (!connector.isAvailable())
            {
                finish(503, R"({"error":"Service unavailable","code":503})");
                continue;
            }

            // D17 re-check at dispatch: the feed can become unready between admission and here
            // (a new feed download started). Rejected without processing, with the Retry-After.
            if (!m_scanner->feedReady())
            {
                auto response = http::HttpResponse::json(503, FEED_NOT_READY_BODY);
                response.headers.emplace_back("Retry-After", std::to_string(m_config.retryAfterSeconds));
                if (item.responder)
                {
                    item.responder->send(std::move(response));
                    item.responder.reset(); // finish() must not answer twice
                }
                // STATS-PLACEHOLDER: retry_after_total
                finish(0, "");
                continue;
            }

            // THE gating of D22: scan first; only an OK (or a legitimate skip) may index.
            ScanVerdict verdict {};
            try
            {
                // STATS-PLACEHOLDER: vd_scan_duration
                verdict = m_scanner->scan(item.session);
            }
            catch (const std::exception& e)
            {
                LOGFN_WARN(logFn(),
                           "The vulnerability scan for agent %s failed: %s. Answering 500 with NOTHING indexed; the "
                           "agent will retry scan and ingest together.",
                           item.session.agentId.c_str(),
                           e.what());
                // STATS-PLACEHOLDER: vd_scans_failed
                finish(500, SCAN_FAILED_BODY);
                continue;
            }

            if (verdict == ScanVerdict::Skipped)
            {
                LOGFN_DEBUG1(logFn(),
                             "Vulnerability scan for agent %s skipped legitimately; indexing its inventory anyway.",
                             item.session.agentId.c_str());
                // STATS-PLACEHOLDER: vd_scans_skipped
            }
            // STATS-PLACEHOLDER: vd_scans_ok

            // Scan OK (or skip): NOW the inventory may be indexed. No group commit here -- one VD
            // session at a time per worker, staged and flushed within the request.
            try
            {
                auto outcome = m_processor.stageBulk(item.session, connector);
                if (outcome.staged)
                {
                    connector.flush();
                    outcome.staged = false;
                }
                finish(outcome.status, outcome.body);
            }
            catch (const std::exception& e)
            {
                LOGFN_WARN(logFn(),
                           "Indexing the inventory of agent %s after its scan failed: %s. The agent will retry.",
                           item.session.agentId.c_str(),
                           e.what());
                try
                {
                    connector.flush(); // drain any partial staging; the re-POST overwrites it
                }
                catch (...)
                {
                }
                respondConnectorFailure(item, connector);
                item.responder.reset();
                finish(0, "");
            }
        }
    }

} // namespace invsync::vd
