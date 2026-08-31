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
    /**
     * @brief Synchronous admission passthrough for POST /scan/vd.
     *
     * remoted holds no scan state of its own: after the offset gate, the request becomes ONE
     * inline POST to VD's scan route, which answers at ADMISSION into its bounded dispatch
     * queue -- so the 200 relayed to the agent genuinely means "the scan will run". Anything
     * VD refuses (lane full, feed mid-update, module stopping) or a failed round trip becomes
     * an honest 503, and the agent's own pending state drives the retry on its next notify.
     * The previous design (a tracking table plus a worker pool retrying with backoff behind an
     * already-sent 200) could exhaust its retries and silently drop scans the agent believed
     * were handled.
     */
    class ScanVdHandlerImpl final : public remoted::endpoints::scanvd::ScanVdHandler
    {
    public:
        // VD answers the scan POST at ADMISSION into its bounded dispatch queue -- inline route
        // work, never the scan itself -- so this is a local-socket round trip measured in
        // milliseconds. 5 s is pure headroom for a loaded box; anything slower is indistinguishable
        // from VD being down, and the honest answer to the agent is the same 503 either way.
        static constexpr long VD_SCAN_READ_TIMEOUT_SECONDS = 5;
        static constexpr long VD_SCAN_WRITE_TIMEOUT_SECONDS = 5;
        /// Total downstream budget for one scan, for the facade's startup check.
        static constexpr long long VD_SCAN_BUDGET_MS =
            (VD_SCAN_READ_TIMEOUT_SECONDS + VD_SCAN_WRITE_TIMEOUT_SECONDS) * 1000;

        /**
         * @param vdModulesdSocketPath VD module UDS endpoint used to trigger scans, as a raw
         * filesystem path (e.g. "/queue/sockets/vd-http.sock") -- NOT a "unix://" URI; see
         * vdClient.cpp for why. The same socket VdClient uses for /offset, passed separately
         * because remoted and VD are independent binaries. Defaults to the real socket;
         * overridable so tests can point this at a fake server instead.
         */
        ScanVdHandlerImpl(std::shared_ptr<remoted::common::VdClient> vdClient,
                          ScanVdMetrics& metrics,
                          std::string vdModulesdSocketPath = "/queue/sockets/vd-http.sock");
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
