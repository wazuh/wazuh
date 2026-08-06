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
#include "loggerHelper.h"
#include <string>

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
        explicit Impl(std::shared_ptr<remoted::common::VdClient> vdClient)
            : m_vdClient(std::move(vdClient))
        {
        }
        ~Impl() = default;

        void
        handleVdScan(uint32_t agentId, uint64_t requestedOffset, remoted::endpoints::scanvd::ScanVdCallback callback)
        {
            LOGFN_DEBUG1(logFn(), "VD scan request for agent %u with offset %llu", agentId, requestedOffset);

            // Get current VD offset
            const uint64_t currentOffset = m_vdClient->getOffset();

            // Validate offset matches
            if (requestedOffset != currentOffset)
            {
                LOGFN_DEBUG1(logFn(),
                             "VD scan offset mismatch for agent %u: requested=%llu, current=%llu",
                             agentId,
                             requestedOffset,
                             currentOffset);

                remoted::endpoints::scanvd::ScanVdResponse response;
                response.success = false;
                response.currentOffset = currentOffset;
                callback(response);
                return;
            }

            // TODO: Enqueue scan task to analysisd
            // For now, just return success
            LOGFN_DEBUG1(logFn(), "VD scan task queued for agent %u with offset %llu", agentId, requestedOffset);

            remoted::endpoints::scanvd::ScanVdResponse response;
            response.success = true;
            response.currentOffset = currentOffset;
            callback(response);
        }

    private:
        std::shared_ptr<remoted::common::VdClient> m_vdClient;
    };

    ScanVdHandlerImpl::ScanVdHandlerImpl(std::shared_ptr<remoted::common::VdClient> vdClient)
        : m_impl(std::make_unique<Impl>(std::move(vdClient)))
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
