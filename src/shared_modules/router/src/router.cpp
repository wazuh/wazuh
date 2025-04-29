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
#include "external/cpp-httplib/httplib.h"
#include "flatbuffers/idl.h"
#include "logging_helper.h"
#include "routerFacade.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include <filesystem>

std::map<ROUTER_PROVIDER_HANDLE, std::shared_ptr<RouterProvider>> PROVIDERS;
std::shared_mutex PROVIDERS_MUTEX;

static std::function<void(const modules_log_level_t, const std::string&)> GS_LOG_FUNCTION;

static void logMessage(const modules_log_level_t level, const std::string& msg)
{
    if (!msg.empty() && GS_LOG_FUNCTION)
    {
        GS_LOG_FUNCTION(level, msg);
    }
}

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
    // Add provider to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().initProviderLocal(m_topicName);
    }
    else
    {
        RouterFacade::instance().initProviderRemote(m_topicName);
    }
}

void RouterProvider::start(const std::function<void()>& onConnect)
{
    // Add provider to the list.
    if (m_isLocal)
    {
        this->start();
        onConnect();
    }
    else
    {
        RouterFacade::instance().initProviderRemote(m_topicName, onConnect);
    }
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

void RouterSubscriber::subscribe(const std::function<void(const std::vector<char>&)>& callback,
                                 const std::function<void()>& onConnect)
{
    // Add subscriber to the list.
    if (m_isLocal)
    {
        this->subscribe(callback);
        onConnect();
    }
    else
    {
        RouterFacade::instance().addSubscriberRemote(m_topicName, m_subscriberId, callback, onConnect);
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

    ROUTER_PROVIDER_HANDLE router_provider_create(const char* name, bool isLocal)
    {
        ROUTER_PROVIDER_HANDLE retVal = nullptr;
        try
        {
            std::string topicName(name);
            if (topicName.empty())
            {
                logMessage(modules_log_level_t::LOG_ERROR, "Error creating provider. Topic name is empty");
            }
            else
            {
                std::shared_ptr<RouterProvider> provider = std::make_shared<RouterProvider>(name, isLocal);
                provider->start();
                std::unique_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
                PROVIDERS[provider.get()] = provider;
                retVal = provider.get();
            }
        }
        catch (...)
        {
            logMessage(modules_log_level_t::LOG_ERROR, "Error creating provider");
        }

        return retVal;
    }

    int router_provider_send(ROUTER_PROVIDER_HANDLE handle, const char* message, unsigned int message_size)
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
                std::vector<char> data(message, message + message_size);
                std::shared_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
                PROVIDERS.at(handle)->send(data);
                retVal = 0;
            }
        }
        catch (const std::exception& e)
        {
            logMessage(modules_log_level_t::LOG_ERROR, std::string("Error sending message to provider: ") + e.what());
        }
        return retVal;
    }

    int router_provider_send_fb(ROUTER_PROVIDER_HANDLE handle, const char* message, const char* schema)
    {
        int retVal = -1;
        try
        {
            if (!message)
            {
                throw std::runtime_error("Error sending message to provider. Message is empty");
            }
            else
            {
                flatbuffers::Parser parser;
                if (!parser.Parse(schema))
                {
                    throw std::runtime_error("Error parsing schema, " + std::string(parser.error_));
                }

                if (!parser.Parse(message))
                {
                    throw std::runtime_error("Error parsing message, " + std::string(parser.error_));
                }

                std::vector<char> data(parser.builder_.GetBufferPointer(),
                                       parser.builder_.GetBufferPointer() + parser.builder_.GetSize());
                std::shared_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
                PROVIDERS.at(handle)->send(data);
                retVal = 0;
            }
        }
        catch (const std::exception& e)
        {
            logMessage(modules_log_level_t::LOG_ERROR, std::string("Error sending message to provider: ") + e.what());
        }
        return retVal;
    }

    void router_provider_destroy(ROUTER_PROVIDER_HANDLE handle)
    {
        std::unique_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
        auto it = PROVIDERS.find(handle);
        if (it != PROVIDERS.end())
        {
            PROVIDERS.erase(it);
        }
    }

    /**
     * @brief Struct to hold the server instance and its thread.
     */
    struct ServerInstance final
    {
        std::unique_ptr<httplib::Server> server; ///< Server instance
        std::thread serverThread;                ///< Thread to run the server
        bool running {false};                    ///< Flag to indicate if the server is running
    };

    std::map<std::string, std::shared_ptr<ServerInstance>> G_HTTPINSTANCES;

    void router_register_api_endpoint(char* socketPath, const char* method, const char* endpoint, void* callback)
    {
        if (!socketPath || !endpoint || !callback || !method)
        {
            logMessage(modules_log_level_t::LOG_ERROR, "Error registering API endpoint. Invalid parameters");
            return;
        }

        std::string socketPathStr(socketPath);
        if (G_HTTPINSTANCES.find(socketPathStr) == G_HTTPINSTANCES.end())
        {
            G_HTTPINSTANCES[socketPathStr] = std::make_shared<ServerInstance>();
            G_HTTPINSTANCES[socketPathStr]->server = std::make_unique<httplib::Server>();
        }

        auto instance = G_HTTPINSTANCES[socketPathStr];
        auto methodStr = std::string(method);
        auto endpointStr = std::string(endpoint);

        if (methodStr.compare("GET") == 0)
        {
            logMessage(modules_log_level_t::LOG_INFO, "Registering GET endpoint: " + endpointStr);
            instance->server->Get(
                endpoint,
                [callback, endpointStr](const httplib::Request& req, httplib::Response& res)
                {
                    bool first = true;
                    auto start = std::chrono::high_resolution_clock::now();
                    std::string json = "{";

                    for (const auto& [key, value] : req.path_params)
                    {
                        if (!first)
                        {
                            json += ",";
                        }
                        first = false;
                        json.append("\"").append(key).append("\":\"").append(value).append("\"");
                    }
                    json += "}";

                    char* output = nullptr;
                    auto cb = reinterpret_cast<int (*)(const char*, const char*, const char*, char**)>(callback);
                    logMessage(modules_log_level_t::LOG_DEBUG_VERBOSE,
                               "GET: " + endpointStr + " request parameters: " + json);
                    cb(endpointStr.c_str(), "GET", json.c_str(), &output);
                    logMessage(modules_log_level_t::LOG_DEBUG_VERBOSE, "GET response: " + std::string(output));

                    if (output == nullptr)
                    {
                        res.status = 400;
                    }
                    else
                    {
                        res.status = 200;
                        res.set_content(output, "text/json");
                        free(output);
                    }
                    auto end = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                    logMessage(modules_log_level_t::LOG_DEBUG,
                               "GET: " + endpointStr + " request processed in " + std::to_string(duration.count()) +
                                   " us");
                });
        }
        else if (methodStr.compare("POST") == 0)
        {
            logMessage(modules_log_level_t::LOG_INFO, "Registering POST endpoint: " + endpointStr);
            instance->server->Post(
                endpoint,
                [callback, endpointStr](const httplib::Request& req, httplib::Response& res)
                {
                    auto start = std::chrono::high_resolution_clock::now();
                    char* output = nullptr;
                    auto cb = reinterpret_cast<int (*)(const char*, const char*, const char*, char**)>(callback);
                    logMessage(modules_log_level_t::LOG_DEBUG_VERBOSE,
                               "POST: " + endpointStr + " request parameters: " + req.body);
                    cb(endpointStr.c_str(), "POST", req.body.c_str(), &output);
                    logMessage(modules_log_level_t::LOG_DEBUG_VERBOSE, "POST response: " + std::string(output));

                    if (output == nullptr)
                    {
                        res.status = 400;
                    }
                    else
                    {
                        res.status = 200;
                        res.set_content(output, "text/json");
                        free(output);
                    }
                    auto end = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                    logMessage(modules_log_level_t::LOG_DEBUG,
                               "POST: " + endpointStr + " request processed in " + std::to_string(duration.count()) +
                                   " us");
                });
        }
        else
        {
            logMessage(modules_log_level_t::LOG_ERROR, "Error registering API endpoint. Invalid method");
            return;
        }
    }

    void router_start_api(const char* socketPath)
    {
        if (!socketPath)
        {
            logMessage(modules_log_level_t::LOG_ERROR, "Error starting API. Invalid socket path");
            return;
        }

        std::string socketPathStr(socketPath);
        if (G_HTTPINSTANCES.find(socketPath) == G_HTTPINSTANCES.end())
        {
            logMessage(modules_log_level_t::LOG_ERROR, "Error starting API. Socket path not found");
            return;
        }

        auto instance = G_HTTPINSTANCES[socketPath];

        instance->serverThread = std::thread(
            [instance, socketPathStr]()
            {
                const static std::string SOCKETPATH {"queue/sockets/"};
                std::filesystem::remove(SOCKETPATH + socketPathStr);
                std::filesystem::path path {SOCKETPATH + socketPathStr};
                std::filesystem::create_directories(path.parent_path());
                instance->server->set_address_family(AF_UNIX);
                instance->running = instance->server->listen(path.c_str(), true);

                if (instance->running == false)
                {
                    logMessage(modules_log_level_t::LOG_ERROR, "Error starting API. Failed to listen on socket");
                    return;
                }
            });
        // Spin lock until server is ready
        while (!instance->server->is_running() && instance->running)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        logMessage(modules_log_level_t::LOG_INFO, "API started successfully");
    }

    void router_stop_api(const char* socketPath)
    {
        if (!socketPath)
        {
            logMessage(modules_log_level_t::LOG_ERROR, "Error stopping API. Invalid socket path");
            return;
        }

        auto it = G_HTTPINSTANCES.find(socketPath);
        if (it != G_HTTPINSTANCES.end())
        {
            it->second->server->stop();
            if (it->second->serverThread.joinable())
            {
                logMessage(modules_log_level_t::LOG_INFO, "Stopping server thread");
                it->second->serverThread.join();
            }
            G_HTTPINSTANCES.erase(it);
        }
    }

#ifdef __cplusplus
}
#endif
