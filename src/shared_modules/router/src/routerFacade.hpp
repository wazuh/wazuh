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

/**
 * @brief RouterFacade
 *
 */
class RouterFacade final : public Singleton<RouterFacade>
{
public:
    // From subscriber.

    /**
     * @brief
     *
     * @param name
     * @param subscriberId
     * @param callback
     */
    void addSubscriber(const std::string& name,
                       const std::string& subscriberId,
                       const std::function<void(const std::vector<char>&)>& callback);

    /**
     * @brief
     *
     * @param name
     * @param subscriberId
     * @param callback
     */
    void addSubscriberRemote(const std::string& name,
                             const std::string& subscriberId,
                             const std::function<void(const std::vector<char>&)>& callback);

    /**
     * @brief
     *
     * @param name
     * @param subscriberId
     * @return * void
     */
    void removeSubscriberLocal(const std::string& name, const std::string& subscriberId);

    /**
     * @brief
     *
     * @param name
     * @param subscriberId
     */
    void removeSubscriberRemote(const std::string& name, const std::string& subscriberId);

    // From providers.

    /**
     * @brief
     *
     * @param name
     */
    void initProviderRemote(const std::string& name);

    /**
     * @brief
     *
     * @param name
     */
    void removeProviderRemote(const std::string& name);

    /**
     * @brief
     *
     * @param name
     */
    void initProviderLocal(const std::string& name);

    /**
     * @brief
     *
     * @param name
     */
    void removeProviderLocal(const std::string& name);

    /**
     * @brief
     *
     * @param name
     * @param data
     */
    void push(const std::string& name, const std::vector<char>& data);

    // From modulesd-router

    /**
     * @brief initialize
     *
     */
    void initialize();

    /**
     * @brief destroy
     *
     */
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
