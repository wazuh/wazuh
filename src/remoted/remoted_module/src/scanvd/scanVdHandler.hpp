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
         * filesystem path (e.g. "/queue/sockets/modulesd") -- NOT a "unix://" URI; see
         * vdClient.cpp for why. Defaults to the real modulesd socket; overridable so tests can
         * point this at a fake server instead.
         */
        ScanVdHandlerImpl(std::shared_ptr<remoted::common::VdClient> vdClient,
                          ScanVdMetrics& metrics,
                          std::string vdModulesdSocketPath = "/queue/sockets/modulesd");
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
