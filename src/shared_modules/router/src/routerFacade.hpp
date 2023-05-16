/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_FACADE_HPP
#define _ROUTER_FACADE_HPP

#include "publisher.hpp"
#include "remoteProvider.hpp"
#include "remoteStateHelper.hpp"
#include "remoteSubscriber.hpp"
#include "singleton.hpp"
#include <functional>
#include <map>
#include <memory>
#include <shared_mutex>
#include <string>

class RouterFacade final : public Singleton<RouterFacade>
{
public:
    // From subscriber.
    void addSubscriber(const std::string& name,
                       const std::string& subscriberId,
                       const std::function<void(const std::vector<char>&)>& callback);
    void addSubscriberRemote(const std::string& name,
                             const std::string& subscriberId,
                             const std::function<void(const std::vector<char>&)>& callback);
    void removeSubscriberLocal(const std::string& name, const std::string& subscriberId);
    void removeSubscriberRemote(const std::string& name, const std::string& subscriberId);

    // From providers.
    void initProviderRemote(const std::string& name);
    void removeProviderRemote(const std::string& name);

    void initProviderLocal(const std::string& name);
    void removeProviderLocal(const std::string& name);

    void push(const std::string& name, const std::vector<char>& data);

    // From modulesd-router
    void initialize();
    void destroy();

private:
    std::map<std::string, std::unique_ptr<Publisher>> m_providers {};
    std::shared_mutex m_providersMutex {};
    std::shared_ptr<SocketServer<Socket<OSPrimitives>, EpollWrapper>> m_providerRegistrationServer {};
    std::map<std::string, std::shared_ptr<RemoteSubscriber>> m_remoteSubscribers {};
    std::map<std::string, std::shared_ptr<RemoteProvider>> m_remoteProviders {};
    std::mutex m_remoteSubscribersMutex {};
    std::mutex m_remoteProvidersMutex {};
};

#endif /* _ROUTER_FACADE_HPP */
