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
#include "remoteSubscriber.hpp"
#include "remoteSubscriptionManager.hpp"
#include "singleton.hpp"
#include <functional>
#include <map>
#include <memory>
#include <shared_mutex>
#include <string>

/**
 * @brief RouterFacade class.
 *
 */
class RouterFacade final : public Singleton<RouterFacade>
{
public:
    // From subscriber.
    // LCOV_EXCL_START
    /**
     * @brief Adds a subscriber to a given provider.
     *
     * @param name Provider name.
     * @param subscriberId Subscriber ID.
     * @param callback Subscriber update callback.
     */
    void addSubscriber(const std::string& name,
                       const std::string& subscriberId,
                       const std::function<void(const std::vector<char>&)>& callback);

    /**
     * @brief Adds a subscriber to a given remote provider.
     *
     * @param name Provider name.
     * @param subscriberId Subscriber ID.
     * @param callback Subscriber update callback.
     * @param onConnect Callback to be called when the subscriber is connected.
     */
    void addSubscriberRemote(
        const std::string& name,
        const std::string& subscriberId,
        const std::function<void(const std::vector<char>&)>& callback,
        const std::function<void()>& onConnect = []() {});

    /**
     * @brief Removes a local subscriber.
     *
     * @param name Provider name.
     * @param subscriberId Subscriber ID.
     */
    void removeSubscriberLocal(const std::string& name, const std::string& subscriberId);

    /**
     * @brief Removes a remote subscriber.
     *
     * @param name Subscriber name.
     * @param subscriberId Subscriber ID.
     */
    void removeSubscriberRemote(const std::string& name, const std::string& subscriberId);

    // From providers.

    /**
     * @brief Initializes remote provider.
     *
     * @param name Provider name.
     * @param onConnect Callback to be called when the provider is connected.
     */
    void initProviderRemote(
        const std::string& name, const std::function<void()>& onConnect = []() {});

    /**
     * @brief Removes remote provider.
     *
     * @param name Provider name.
     */
    void removeProviderRemote(const std::string& name);

    /**
     * @brief Initializes local provider.
     *
     * @param name Provider name.
     */
    void initProviderLocal(const std::string& name);

    /**
     * @brief Removes local provider.
     *
     * @param name Provider name.
     */
    void removeProviderLocal(const std::string& name);

    /**
     * @brief Push data into a provider.
     *
     * @param name Provider name.
     * @param data Data to be pushed.
     */
    void push(const std::string& name, const std::vector<char>& data);

    // From modulesd-router

    /**
     * @brief Initializes a server that listen to new providers.
     *
     */
    void initialize();

    /**
     * @brief Stop server and clean providers/subscribers info.
     *
     */
    void destroy();
    // LCOV_EXCL_STOP
private:
    std::unordered_map<std::string, std::unique_ptr<Publisher>> m_providers {};
    std::shared_mutex m_providersMutex {};
    std::unique_ptr<SocketServer<Socket<OSPrimitives>, EpollWrapper>> m_providerRegistrationServer {};
    std::unordered_map<std::string, std::shared_ptr<RemoteSubscriber>> m_remoteSubscribers {};
    std::unordered_map<std::string, std::shared_ptr<RemoteProvider>> m_remoteProviders {};
    std::mutex m_remoteSubscribersMutex {};
    std::mutex m_remoteProvidersMutex {};
    std::mutex m_initializationMutex {};
};

#endif /* _ROUTER_FACADE_HPP */
