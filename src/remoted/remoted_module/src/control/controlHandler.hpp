/*
 * Wazuh remoted module - Control handler
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_HANDLER_HPP
#define _REMOTED_CONTROL_HANDLER_HPP

#include "agentRegistry.hpp"
#include "controlConfig.hpp"
#include "controlTypes.hpp"
#include "hashCache.hpp"
#include "metrics.hpp"
#include "taskClient.hpp"
#include "wazuhDBClient.hpp"
#include <memory>

namespace remoted::common
{
    class VdClient;
}

namespace remoted::control
{
    class ControlHandler
    {
    public:
        ControlHandler(std::shared_ptr<AgentRegistry> registry,
                       std::shared_ptr<WazuhDBClient> wdbClient,
                       std::shared_ptr<TaskClient> taskClient,
                       std::shared_ptr<HashCache> hashCache,
                       std::shared_ptr<remoted::common::VdClient> vdClient,
                       ControlMetrics& metrics,
                       const Config& config);
        ~ControlHandler();

        void handleStartup(AgentId id, const StartupData& data, ResponseCallback callback);
        void handleNotify(AgentId id, const NotifyData& data, ResponseCallback callback);
        void handleShutdown(AgentId id, const ShutdownData& data, ResponseCallback callback);

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_HANDLER_HPP
