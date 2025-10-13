/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync_message_transport.hpp"

#if CLIENT
  #include "mqueue_transport.hpp"
#else
  #include "router_transport.hpp"
#endif

namespace SyncTransportFactory {

#if CLIENT
std::unique_ptr<ISyncMessageTransport> createDefaultTransport(
    const std::string& moduleName,
    const MQ_Functions& mqFuncs,
    LoggerFunc logger,
    std::function<void(const std::vector<char>&)>)
{
    return std::make_unique<MQueueTransport>(moduleName, mqFuncs, std::move(logger));
}
#else
std::unique_ptr<ISyncMessageTransport> createDefaultTransport(
    const std::string& agentId,
    const std::string& agentName,
    const std::string& agentIp,
    const std::string& moduleName,
    LoggerFunc logger,
    std::function<void(const std::vector<char>&)> responseCallback)
{
    return std::make_unique<RouterTransport>(agentId, agentName, agentIp, moduleName, std::move(logger), std::move(responseCallback));
}
#endif

} // namespace SyncTransportFactory
