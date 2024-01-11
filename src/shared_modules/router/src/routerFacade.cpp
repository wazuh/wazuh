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

#include "routerFacade.hpp"
#include "observer.hpp"
#include "socketServer.hpp"
#include "subscriber.hpp"
#include <external/nlohmann/json.hpp>

constexpr auto DEFAULT_SOCKET_PATH = "queue/router/";

void RouterFacade::initialize()
{
    if (m_providerRegistrationServer)
    {
        throw std::runtime_error("Already initialized");
    }
    // This is a server that will listen for new provider.
    m_providerRegistrationServer =
        std::make_unique<SocketServer<Socket<OSPrimitives>, EpollWrapper>>(REMOTE_SUBSCRIPTION_ENDPOINT);
    m_providerRegistrationServer->listen(
        [providerRegistrationServer = m_providerRegistrationServer.get()](
            const int fd, const char* body, const uint32_t bodySize, const char*, const uint32_t)
        {
            auto message = nlohmann::json::parse(body, body + bodySize);
            nlohmann::json result;
            // Register provider
            try
            {
                const std::string messageType = message.at("MessageType");
                if (messageType.compare("InitProvider") == 0)
                {
                    RouterFacade::instance().initProviderLocal(
                        message.at("EndpointName").get_ref<const std::string&>());
                }
                else if (messageType.compare("RemoveSubscriber") == 0)
                {
                    RouterFacade::instance().removeSubscriberLocal(
                        message.at("EndpointName").get_ref<const std::string&>(),
                        message.at("SubscriberId").get_ref<const std::string&>());
                }
                else
                {
                    throw std::runtime_error("Invalid message type");
                }
                result["Result"] = "OK";
            }
            catch (const std::exception& e)
            {
                result["Result"] = e.what();
            }

            const auto resultStr {result.dump()};
            providerRegistrationServer->send(fd, resultStr.data(), resultStr.size());
        });
}

void RouterFacade::destroy()
{
    if (!m_providerRegistrationServer)
    {
        throw std::runtime_error("Not initialized");
    }
    m_remoteSubscribers.clear();
    m_remoteProviders.clear();
    m_providerRegistrationServer.reset();
    m_providers.clear();
}

void RouterFacade::initProviderLocal(const std::string& endpointName)
{
    std::unique_lock<std::shared_mutex> lock {m_providersMutex};
    // Create if not exist.
    if (m_providers.find(endpointName) == m_providers.end())
    {
        m_providers.emplace(endpointName, std::make_unique<Publisher>(endpointName, DEFAULT_SOCKET_PATH));
    }
}

void RouterFacade::removeProviderLocal(const std::string& endpointName)
{
    std::unique_lock<std::shared_mutex> lock {m_providersMutex};

    // If already exist throw exception
    if (m_providers.find(endpointName) == m_providers.end())
    {
        throw std::runtime_error("Provider not exist: ");
    }
    m_providers.erase(endpointName);
}

void RouterFacade::initProviderRemote(const std::string& name, const std::function<void()>& onConnect)
{
    std::lock_guard<std::mutex> lock {m_remoteProvidersMutex};
    // If exist throw exception
    if (m_remoteProviders.find(name) != m_remoteProviders.end())
    {
        throw std::runtime_error("initProviderRemote: Provider already exist");
    }

    // Send a message to the provider from the client side to add a remote provider
    m_remoteProviders[name] = std::make_shared<RemoteProvider>(name, DEFAULT_SOCKET_PATH, onConnect);
}

void RouterFacade::removeProviderRemote(const std::string& name)
{
    std::lock_guard<std::mutex> lock {m_remoteProvidersMutex};
    // If exist throw exception
    if (m_remoteProviders.find(name) == m_remoteProviders.end())
    {
        throw std::runtime_error("removeProviderRemote: provider not exist");
    }

    m_remoteProviders.erase(name);
}

void RouterFacade::addSubscriber(const std::string& name,
                                 const std::string& subscriberId,
                                 const std::function<void(const std::vector<char>&)>& callback)
{
    std::lock_guard<std::shared_mutex> lock {m_providersMutex};
    // If not exist, create it.
    if (m_providers.find(name) == m_providers.end())
    {
        m_providers.emplace(name, std::make_unique<Publisher>(name, DEFAULT_SOCKET_PATH));
    }

    m_providers[name]->addSubscriber(std::make_shared<Subscriber<const std::vector<char>&>>(callback, subscriberId));
}

void RouterFacade::addSubscriberRemote(const std::string& name,
                                       const std::string& subscriberId,
                                       const std::function<void(const std::vector<char>&)>& callback,
                                       const std::function<void()>& onConnect)
{
    std::lock_guard<std::mutex> lock {m_remoteSubscribersMutex};
    // If exist throw exception
    if (m_remoteSubscribers.find(name) != m_remoteSubscribers.end())
    {
        throw std::runtime_error("addSubscriberRemote: Subscriber already exist");
    }

    // Send a message to the provider from the client side to add a remote subscriber
    m_remoteSubscribers[name] =
        std::make_shared<RemoteSubscriber>(name, subscriberId, callback, DEFAULT_SOCKET_PATH, onConnect);
}

void RouterFacade::removeSubscriberRemote(const std::string& name, const std::string& subscriberId)
{
    std::lock_guard<std::mutex> lock {m_remoteSubscribersMutex};
    // If not exist throw exception
    if (m_remoteSubscribers.find(name) != m_remoteSubscribers.end())
    {
        m_remoteSubscribers.erase(name);
    }
}

void RouterFacade::removeSubscriberLocal(const std::string& name, const std::string& subscriberId)
{
    std::shared_lock<std::shared_mutex> lock {m_providersMutex};
    // If not exist throw exception
    if (m_providers.find(name) != m_providers.end())
    {
        m_providers[name]->removeSubscriber(subscriberId);
    }
}

void RouterFacade::push(const std::string& name, const std::vector<char>& data)
{
    std::unique_lock<std::mutex> lockRemoteProviders {m_remoteProvidersMutex};
    const auto itRemoteProvider {m_remoteProviders.find(name)};

    if (itRemoteProvider != m_remoteProviders.end())
    {
        itRemoteProvider->second->push(data);
    }
    else
    {
        std::shared_lock<std::shared_mutex> lockLocalProviders {m_providersMutex};
        const auto itLocalProvider {m_providers.find(name)};

        if (itLocalProvider != m_providers.end())
        {
            itLocalProvider->second->push(data);
        }
        else
        {
            throw std::runtime_error("Push: Provider not exist");
        }
    }
}
