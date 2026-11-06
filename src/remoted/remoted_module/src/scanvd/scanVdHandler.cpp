/*
 * Wazuh remoted module - VD Scan handler
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "scanVdHandler.hpp"
#include "common/vdClient.hpp"
#include "downstream/blockingCall.hpp"
#include "json.hpp"
#include "loggerHelper.h"

#include <uds_http_server/logThrottle.hpp>

#include <chrono>
#include <stdexcept>
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
        Impl(std::shared_ptr<remoted::common::VdClient> vdClient,
             std::shared_ptr<remoted::downstream::IDownstreamClient> httpClient,
             ScanVdMetrics& metrics,
             std::string socketPath,
             long readTimeoutSeconds,
             long writeTimeoutSeconds)
            : m_vdClient(std::move(vdClient))
            , m_httpClient(std::move(httpClient))
            , m_metrics(metrics)
            , m_vdModulesdSocketPath(std::move(socketPath))
            , m_readTimeoutSeconds(readTimeoutSeconds)
            , m_writeTimeoutSeconds(writeTimeoutSeconds)
        {
        }

        long long budgetMs() const noexcept
        {
            return ScanVdHandlerImpl::budgetMsFor(m_readTimeoutSeconds, m_writeTimeoutSeconds);
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

            if (vdAnswer.status == 200)
            {
                LOGFN_DEBUG1(logFn(), "VD queued the scan for agent %u at offset %llu", agentId, currentOffset);
                incAccepted(m_metrics);
                callback(ScanVdResponse {ScanVdOutcome::Accepted, currentOffset, {}});
                return;
            }

            if (vdAnswer.code == "scan_queue_full")
            {
                incQueueFull(m_metrics);
            }
            else if (vdAnswer.code == "indexer_unavailable")
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
                    // A relay failure names its class ("vd_unreachable (connect_failed)"): the agent only
                    // ever sees the code, but the operator needs to tell "VD is not running" from "VD did
                    // not answer in time".
                    const std::string cause =
                        vdAnswer.detail.empty() ? vdAnswer.code : vdAnswer.code + " (" + vdAnswer.detail + ")";
                    LOGFN_WARN(logFn(),
                               "Answered %llu scan request(s) with 503 in the last %d s: VD did not queue them "
                               "(last: %s). The agents retry on their next notify.",
                               static_cast<unsigned long long>(decision.total),
                               wazuh::uds_http::LogThrottle::kDefaultWindowSeconds,
                               cause.c_str());
                }
            }
            callback(ScanVdResponse {ScanVdOutcome::VdRejected, currentOffset, vdAnswer.code});
        }

    private:
        struct ScanAnswer
        {
            int status;
            /// Empty on 200; otherwise what the agent sees.
            std::string code;
            /// Why the round trip failed, for the log only (the client's error class); empty when VD answered.
            std::string detail;
        };

        /// @return {200, ""} when VD queued the scan; otherwise the error code out of VD's body
        /// ("scan_queue_full", "feed_not_ready", ...), "vd_unreachable" when the round trip itself
        /// failed, or "vd_error" for anything unrecognisable.
        ScanAnswer postScan(uint32_t agentId)
        {
            using remoted::common::VdClient;

            nlohmann::json requestBody;
            requestBody["agent_id"] = std::to_string(agentId);
            // The client only views the body; this keeps it alive until the send completes, even if the
            // wait below gives up first.
            const auto body = std::make_shared<const std::string>(requestBody.dump());

            const int writeTimeoutMs = static_cast<int>(m_writeTimeoutSeconds * 1000);
            const int responseTimeoutMs = static_cast<int>(m_readTimeoutSeconds * 1000);

            remoted::downstream::DownstreamRequest request;
            request.socketPath = m_vdModulesdSocketPath;
            request.method = remoted::http::Method::Post;
            request.path = "/vulnerability-detector/scan";
            request.contentType = "application/json";
            request.body = *body;
            request.writeTimeoutMs = writeTimeoutMs;
            request.responseTimeoutMs = responseTimeoutMs;

            const auto result = remoted::downstream::sendBlocking(
                *m_httpClient,
                std::move(request),
                body,
                std::chrono::milliseconds {static_cast<long long>(VdClient::CONNECT_TIMEOUT_MS) + writeTimeoutMs +
                                           responseTimeoutMs + VdClient::BACKSTOP_MARGIN_MS});

            if (result.error != remoted::downstream::DownstreamError::None)
            {
                return {0, "vd_unreachable", remoted::downstream::toString(result.error)};
            }
            if (result.response.status == 200)
            {
                return {200, {}, {}};
            }

            try
            {
                const auto errorJson = nlohmann::json::parse(result.response.body);
                if (errorJson.contains("error") && errorJson["error"].is_string())
                {
                    return {result.response.status, errorJson["error"].get<std::string>(), {}};
                }
            }
            catch (...) // NOLINT(bugprone-empty-catch)
            {
                // Unparseable body: fall through to the generic code.
            }
            return {result.response.status, "vd_error", {}};
        }

        std::shared_ptr<remoted::common::VdClient> m_vdClient;
        std::shared_ptr<remoted::downstream::IDownstreamClient> m_httpClient;
        ScanVdMetrics& m_metrics;
        std::string m_vdModulesdSocketPath;
        long m_readTimeoutSeconds;
        long m_writeTimeoutSeconds;
        /// One window for relay failures only -- VD logs its own capacity rejections.
        wazuh::uds_http::LogThrottle m_vdErrorThrottle;
    };

    namespace
    {
        std::shared_ptr<remoted::downstream::IDownstreamClient>
        requireClient(std::shared_ptr<remoted::downstream::IDownstreamClient> httpClient)
        {
            if (!httpClient)
            {
                throw std::invalid_argument("ScanVdHandlerImpl needs an HTTP client for VD's socket");
            }
            return httpClient;
        }
    } // namespace

    ScanVdHandlerImpl::ScanVdHandlerImpl(std::shared_ptr<remoted::common::VdClient> vdClient,
                                         std::shared_ptr<remoted::downstream::IDownstreamClient> httpClient,
                                         ScanVdMetrics& metrics,
                                         std::string vdModulesdSocketPath,
                                         long readTimeoutSeconds,
                                         long writeTimeoutSeconds)
        // <=0 -> the compiled-in default: a config that never ran through
        // remoted_module_control_config() must not turn every request into an immediate timeout.
        : m_impl(std::make_unique<Impl>(std::move(vdClient),
                                        requireClient(std::move(httpClient)),
                                        metrics,
                                        std::move(vdModulesdSocketPath),
                                        readTimeoutSeconds > 0 ? readTimeoutSeconds : VD_SCAN_READ_TIMEOUT_SECONDS,
                                        writeTimeoutSeconds > 0 ? writeTimeoutSeconds : VD_SCAN_WRITE_TIMEOUT_SECONDS))
    {
    }

    ScanVdHandlerImpl::~ScanVdHandlerImpl() = default;

    long long ScanVdHandlerImpl::getBudgetMs() const noexcept
    {
        return m_impl->budgetMs();
    }

    void ScanVdHandlerImpl::handleVdScan(uint32_t agentId,
                                         uint64_t requestedOffset,
                                         remoted::endpoints::scanvd::ScanVdCallback callback)
    {
        m_impl->handleVdScan(agentId, requestedOffset, std::move(callback));
    }

} // namespace remoted::scanvd
