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

#ifndef SCANVD_HANDLER_HPP
#define SCANVD_HANDLER_HPP

#include "endpoints/scanVdEndpoint.hpp"
#include "scanvd/scanVdMetrics.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace remoted::common
{
    class VdClient;
}

namespace remoted::scanvd
{
    class ScanVdHandlerImpl final : public remoted::endpoints::scanvd::ScanVdHandler
    {
    public:
        /**
         * @param vdModulesdSocketPath VD module UDS endpoint used to trigger scans, as a raw
         * filesystem path (e.g. "/queue/sockets/modulesd-vdscan") -- NOT a "unix://" URI; see
         * vdClient.cpp for why. This is VD's dedicated scan socket, separate from the one
         * VdClient uses for /offset -- see vulnerabilityScanner.cpp's SCAN_SOCKET_PATH, kept in
         * sync manually since remoted and VD are independent binaries. Defaults to the real
         * socket; overridable so tests can point this at a fake server instead.
         * @param maxTrackedAgents Cap on how many agents can be simultaneously tracked (queued,
         * backing off, or executing) before new requests are rejected with QueueFull. Defaults to
         * the real production limit; overridable so tests can reach that limit without needing
         * 10000 distinct agents.
         */
        ScanVdHandlerImpl(std::shared_ptr<remoted::common::VdClient> vdClient,
                          ScanVdMetrics& metrics,
                          std::string vdModulesdSocketPath = "/queue/sockets/modulesd-vdscan",
                          size_t maxTrackedAgents = 10000);
        ~ScanVdHandlerImpl() override;

        void handleVdScan(uint32_t agentId,
                          uint64_t requestedOffset,
                          remoted::endpoints::scanvd::ScanVdCallback callback) override;

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::scanvd

#endif // SCANVD_HANDLER_HPP
