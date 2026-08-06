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

namespace remoted::endpoints::scanvd
{
    enum class ScanVdOutcome
    {
        Accepted,        ///< Queued (or refreshed an already-tracked request). -> 200.
        VersionMismatch, ///< requestedOffset != current VD feed offset. -> 409, carries currentOffset.
        QueueFull,       ///< Scan tracking table is at capacity; unrelated to feed version. -> 503.
        InvalidAgent     ///< Defensive: agentId 0 reached the handler directly (bypassing the
                         ///< endpoint's own parseAgentId check). -> 400.
    };

    struct ScanVdResponse
    {
        ScanVdOutcome outcome;
        uint64_t currentOffset; ///< Meaningful only when outcome == VersionMismatch.
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
