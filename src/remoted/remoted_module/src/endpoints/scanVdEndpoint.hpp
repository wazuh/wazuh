/*
 * Wazuh remoted module - VD Scan endpoint
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SCANVD_ENDPOINT_HPP
#define SCANVD_ENDPOINT_HPP

#include "authGateway.hpp"
#include <cstdint>
#include <functional>
#include <string>

namespace remoted::endpoints::scanvd
{
    enum class ScanVdOutcome
    {
        Accepted,        ///< VD queued the scan -- it WILL run. -> 200.
        VersionMismatch, ///< requestedOffset != current VD feed offset. -> 409, carries currentOffset.
        VdRejected,      ///< VD did not queue it (lane full, not ready, shutting down, unreachable);
                         ///< unrelated to feed version -- the agent retries on its next notify.
                         ///< -> 503, carries errorCode with the actual cause.
        InvalidAgent     ///< Defensive: agentId 0 reached the handler directly (bypassing the
                         ///< endpoint's own parseAgentId check). -> 400.
    };

    struct ScanVdResponse
    {
        ScanVdOutcome outcome;
        uint64_t currentOffset; ///< Meaningful only when outcome == VersionMismatch.
        std::string errorCode;  ///< Meaningful only when outcome == VdRejected: VD's own error code
                                ///< passed through (scan_queue_full, feed_not_ready, shutting_down,
                                ///< ...) or vd_unreachable when the POST itself failed.
    };

    using ScanVdCallback = std::function<void(const ScanVdResponse&)>;

    class ScanVdHandler
    {
    public:
        virtual ~ScanVdHandler() = default;
        virtual void handleVdScan(uint32_t agentId, uint64_t requestedOffset, ScanVdCallback callback) = 0;
    };

    remoted::endpoints::AuthenticatedHandler makeHandler(ScanVdHandler& handler);

} // namespace remoted::endpoints::scanvd

#endif // SCANVD_ENDPOINT_HPP
