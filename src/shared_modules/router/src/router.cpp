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

#include "router.h"
#include "logging_helper.h"
#include "routerFacade.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include "threadSafeQueue.h"

static std::function<void(const modules_log_level_t, const std::string&)> GS_LOG_FUNCTION;

static void logMessage(const modules_log_level_t level, const std::string& msg)
{
    if (!msg.empty() && GS_LOG_FUNCTION)
    {
        GS_LOG_FUNCTION(level, msg);
    }
}

auto constexpr ROUTER_INIT_WAIT_TIME {500};
std::shared_mutex PROVIDERS_MUTEX;

class providerHandler
{
private:
    std::atomic<bool> m_shouldStop {false};
    RouterProvider m_provider;
    std::thread m_workingThread;
    Utils::SafeQueue<std::vector<char>> m_queue;

    void threadBody()
    {
        {
            while (!m_shouldStop.load() && !m_provider.isReady())
            {
                try
                {
                    m_provider.start();
                    break;
                }
                catch (const std::exception& e)
                {
                    logMessage(modules_log_level_t::LOG_DEBUG, std::string("Error starting provider: ") + e.what());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(ROUTER_INIT_WAIT_TIME));
            }

            while (!m_shouldStop.load() && m_provider.isReady())
            {
                std::vector<char> tempData;
                if (m_queue.pop(tempData))
                {
                    m_provider.send(tempData);
                }
            }
        }
    }

public:
    providerHandler(std::string providerName)
        : m_provider(providerName, false)
    {
    }

    ~providerHandler()
    {
        stop();
    }

    void start()
    {
        m_workingThread = std::thread {&providerHandler::threadBody, this};
    }

    void stop()
    {
        m_shouldStop.store(true);
        m_queue.cancel();
        if (m_workingThread.joinable())
        {
            m_workingThread.join();
        }
        m_provider.stop();
    }

    bool isReady()
    {
        return m_provider.isReady();
    }

    void send(const std::vector<char>& data)
    {
        m_provider.send(data);
    }

    void push(const std::vector<char>& data)
    {
        m_queue.push(data);
    }
};

std::map<std::string, std::shared_ptr<providerHandler>> PROVIDERS;

void RouterModule::initialize(const std::function<void(const modules_log_level_t, const std::string&)>& logFunction)
{
    if (!GS_LOG_FUNCTION)
    {
        GS_LOG_FUNCTION = logFunction;
    }
}

void RouterModule::start()
{
    // Init socket to receive messages from remoted and send them to the right module subscribed.
    // Init socket to receive remote subscribers.
    RouterFacade::instance().initialize();
}

void RouterModule::stop()
{
    // clean subscribers.
    // Destroy socket.
    RouterFacade::instance().destroy();
}

void RouterProvider::send(const std::vector<char>& data)
{
    // Send data to the right provider.
    RouterFacade::instance().push(m_topicName, data);
}

void RouterProvider::start()
{
    if (m_isReady.load())
    {
        return;
    }
    // Add provider to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().initProviderLocal(m_topicName);
    }
    else
    {
        RouterFacade::instance().initProviderRemote(m_topicName);
    }
    m_isReady.store(true);
}

void RouterProvider::stop()
{
    // Add subscriber to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().removeProviderLocal(m_topicName);
    }
    else
    {
        RouterFacade::instance().removeProviderRemote(m_topicName);
    }
    m_isReady.store(false);
}

bool RouterProvider::isReady()
{
    return m_isReady.load();
}

void RouterSubscriber::subscribe(const std::function<void(const std::vector<char>&)>& callback)
{
    // Add subscriber to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().addSubscriber(m_topicName, m_subscriberId, callback);
    }
    else
    {
        RouterFacade::instance().addSubscriberRemote(m_topicName, m_subscriberId, callback);
    }
}

void RouterSubscriber::unsubscribe()
{
    // Remove subscriber to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().removeSubscriberLocal(m_topicName, m_subscriberId);
    }
    else
    {
        RouterFacade::instance().removeSubscriberRemote(m_topicName, m_subscriberId);
    }
}

#ifdef __cplusplus
extern "C"
{
#endif

    int router_initialize(log_callback_t callbackLog)
    {
        int retVal = 0;
        try
        {
            RouterModule::initialize([callbackLog](const modules_log_level_t level, const std::string& msg)
                                     { callbackLog(level, msg.c_str(), ":router"); });
            logMessage(modules_log_level_t::LOG_DEBUG, "Router initialized successfully.");
        }
        catch (...)
        {
            retVal = -1;
        }
        return retVal;
    }

    int router_start()
    {
        int retVal = 0;
        try
        {
            RouterModule::instance().start();
            logMessage(modules_log_level_t::LOG_DEBUG, "Router started successfully.");
        }
        catch (...)
        {
            retVal = -1;
        }
        return retVal;
    }

    int router_stop()
    {
        int retVal = 0;
        try
        {
            RouterModule::instance().stop();
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error stopping router: " << e.what() << std::endl;
            retVal = -1;
        }
        return retVal;
    }

    int router_provider_send(const char* provider_name, const char* message, unsigned int message_size)
    {
        int retVal = -1;
        try
        {
            if (!message || message_size == 0)
            {
                throw std::runtime_error("Error sending message to provider. Message is empty");
            }
            else
            {
                std::unique_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
                if (PROVIDERS.find(provider_name) == PROVIDERS.end())
                {
                    // TO DO - Add parameter to control if the provider is local or remote.
                    PROVIDERS[provider_name] = std::make_shared<providerHandler>(provider_name);
                    PROVIDERS.at(provider_name)->start();
                }

                std::vector<char> data(message, message + message_size);

                if (PROVIDERS.at(provider_name)->isReady())
                {
                    PROVIDERS.at(provider_name)->send(data);
                }
                else
                {
                    PROVIDERS.at(provider_name)->push(std::move(data));
                }

                retVal = 0;
            }
        }
        catch (const std::exception& e)
        {
            logMessage(modules_log_level_t::LOG_ERROR, std::string("Error sending message to provider: ") + e.what());
        }
        return retVal;
    }

    void router_provider_destroy(const char* provider_name)
    {
        std::unique_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
        auto it = PROVIDERS.find(provider_name);
        if (it != PROVIDERS.end())
        {
            it->second->stop();
            PROVIDERS.erase(it);
        }
    }

#ifdef __cplusplus
}
#endif
