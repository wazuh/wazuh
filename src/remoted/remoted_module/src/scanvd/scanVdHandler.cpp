/*
 * Wazuh remoted module - VD Scan handler
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "scanVdHandler.hpp"
#include "common/vdClient.hpp"
#include "json.hpp"
#include "loggerHelper.h"

#include <uds_http_server/logThrottle.hpp>

#include <httplib.h>
#include <string>
#include <utility>

namespace remoted::scanvd
{
    namespace
    {
        constexpr auto SCANVD_HANDLER_LOGTAG {"wazuh-manager-remoted:scanvd-handler"};

        const LogFn& logFn()
        {
            static const LogFn instance {SCANVD_HANDLER_LOGTAG};
            return instance;
        }
    } // namespace

    class ScanVdHandlerImpl::Impl
    {
    public:
        Impl(std::shared_ptr<remoted::common::VdClient> vdClient, ScanVdMetrics& metrics, std::string socketPath)
            : m_vdClient(std::move(vdClient))
            , m_metrics(metrics)
            , m_vdModulesdSocketPath(std::move(socketPath))
        {
        }

        void
        handleVdScan(uint32_t agentId, uint64_t requestedOffset, remoted::endpoints::scanvd::ScanVdCallback callback)
        {
            using remoted::endpoints::scanvd::ScanVdOutcome;
            using remoted::endpoints::scanvd::ScanVdResponse;

            LOGFN_DEBUG1(logFn(), "VD scan request for agent %u with offset %llu", agentId, requestedOffset);
            incRequests(m_metrics);

            if (agentId == 0)
            {
                LOGFN_WARN(logFn(), "VD scan request rejected: invalid agent ID (0)");
                incInvalidAgent(m_metrics);
                callback(ScanVdResponse {ScanVdOutcome::InvalidAgent, 0, {}});
                return;
            }

            const uint64_t currentOffset = m_vdClient->getOffset();
            if (requestedOffset != currentOffset)
            {
                LOGFN_DEBUG1(logFn(),
                             "VD scan offset mismatch for agent %u: requested=%llu, current=%llu",
                             agentId,
                             requestedOffset,
                             currentOffset);
                incVersionMismatch(m_metrics);
                callback(ScanVdResponse {ScanVdOutcome::VersionMismatch, currentOffset, {}});
                return;
            }

            // ONE inline POST, no queue and no retry on this side: VD's dispatch lane is the
            // only queue that guarantees execution, so its admission answer IS the answer. The
            // agent's pending state survives a 503 and its next notify re-requests -- retrying
            // here would only duplicate that loop with a worse deadline. Blocking is fine: this
            // runs on the transport's request pool (group B), which exists for handlers that do
            // synchronous downstream round trips.
            const auto vdAnswer = postScan(agentId);

            if (vdAnswer.first == 200)
            {
                LOGFN_DEBUG1(logFn(), "VD queued the scan for agent %u at offset %llu", agentId, currentOffset);
                incAccepted(m_metrics);
                callback(ScanVdResponse {ScanVdOutcome::Accepted, currentOffset, {}});
                return;
            }

            if (vdAnswer.second == "scan_queue_full")
            {
                incQueueFull(m_metrics);
            }
            else if (vdAnswer.second == "indexer_unavailable")
            {
                // VD's own reported, VD-logged cause -- exactly like scan_queue_full, and NOT a
                // relay failure. Folding it into the vd_error window below would let a
                // fleet-wide indexer outage bury a genuine vd_unreachable (the window's only
                // cause detail is its LAST error) and send the operator to the wrong subsystem.
                incIndexerUnavailable(m_metrics);
            }
            else
            {
                incVdError(m_metrics);
                // Capacity 503s are VD's to report (it logs them throttled); everything else on
                // this leg -- unreachable socket, unexpected status -- is OUR failure to relay
                // and would otherwise be invisible on this side of the wire.
                if (const auto decision = m_vdErrorThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Answered %llu scan request(s) with 503 in the last %d s: VD did not queue them "
                               "(last: %s). The agents retry on their next notify.",
                               static_cast<unsigned long long>(decision.total),
                               wazuh::uds_http::LogThrottle::kDefaultWindowSeconds,
                               vdAnswer.second.c_str());
                }
            }
            callback(ScanVdResponse {ScanVdOutcome::VdRejected, currentOffset, vdAnswer.second});
        }

    private:
        /// @return {status, errorCode}: {200, ""} when VD queued the scan; otherwise the error
        /// code out of VD's body ("scan_queue_full", "feed_not_ready", ...), "vd_unreachable"
        /// when the round trip itself failed, or "vd_error" for anything unrecognisable.
        std::pair<int, std::string> postScan(uint32_t agentId)
        {
            try
            {
                // See vdClient.cpp: httplib::Client's single-string constructor only parses
                // "http(s)://host[:port]" URLs, so a raw socket path needs set_address_family
                // (AF_UNIX) to actually be treated as a Unix domain socket.
                httplib::Client client(m_vdModulesdSocketPath);
                client.set_address_family(AF_UNIX);
                client.set_read_timeout(VD_SCAN_READ_TIMEOUT_SECONDS, 0);
                client.set_write_timeout(VD_SCAN_WRITE_TIMEOUT_SECONDS, 0);

                nlohmann::json requestBody;
                requestBody["agent_id"] = std::to_string(agentId);

                const auto res = client.Post("/vulnerability-detector/scan", requestBody.dump(), "application/json");
                if (!res)
                {
                    return {0, "vd_unreachable"};
                }
                if (res->status == 200)
                {
                    return {200, {}};
                }

                try
                {
                    const auto errorJson = nlohmann::json::parse(res->body);
                    if (errorJson.contains("error") && errorJson["error"].is_string())
                    {
                        return {res->status, errorJson["error"].get<std::string>()};
                    }
                }
                catch (...) // NOLINT(bugprone-empty-catch)
                {
                    // Unparseable body: fall through to the generic code.
                }
                return {res->status, "vd_error"};
            }
            catch (const std::exception&)
            {
                return {0, "vd_unreachable"};
            }
        }

        std::shared_ptr<remoted::common::VdClient> m_vdClient;
        ScanVdMetrics& m_metrics;
        std::string m_vdModulesdSocketPath;
        /// One window for relay failures only -- VD logs its own capacity rejections.
        wazuh::uds_http::LogThrottle m_vdErrorThrottle;
    };

    ScanVdHandlerImpl::ScanVdHandlerImpl(std::shared_ptr<remoted::common::VdClient> vdClient,
                                         ScanVdMetrics& metrics,
                                         std::string vdModulesdSocketPath)
        : m_impl(std::make_unique<Impl>(std::move(vdClient), metrics, std::move(vdModulesdSocketPath)))
    {
    }

    ScanVdHandlerImpl::~ScanVdHandlerImpl() = default;

    void ScanVdHandlerImpl::handleVdScan(uint32_t agentId,
                                         uint64_t requestedOffset,
                                         remoted::endpoints::scanvd::ScanVdCallback callback)
    {
        m_impl->handleVdScan(agentId, requestedOffset, std::move(callback));
    }

} // namespace remoted::scanvd
