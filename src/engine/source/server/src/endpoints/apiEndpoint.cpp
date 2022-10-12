/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "apiEndpoint.hpp"

#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <tuple>

#include <api/api.hpp>
#include <json/json.hpp>
#include <logging/logging.hpp>
#include <uvw/timer.hpp>

#include "server/protocolHandler.hpp"

using uvw::CloseEvent;
using uvw::DataEvent;
using uvw::EndEvent;
using uvw::ErrorEvent;
using uvw::ListenEvent;
using uvw::Loop;
using uvw::PipeHandle;
using uvw::TimerEvent;
using uvw::TimerHandle;


namespace
{
constexpr uint32_t CONNECTION_TIMEOUT_MSEC = 5000; // Stream

auto addSecureHeader(std::string_view data)
{
    auto buffer = std::unique_ptr<char[]> {new char[data.size() + sizeof(uint32_t)]};
    auto size {static_cast<uint32_t>(data.size())};
    std::memcpy(buffer.get(), &size, sizeof(uint32_t));
    std::memcpy(buffer.get() + sizeof(uint32_t), data.data(), data.size());
    return std::tuple<std::unique_ptr<char[]>, uint32_t> {std::move(buffer),
                                                          size + sizeof(uint32_t)};
}

} // namespace

namespace engineserver::endpoints
{

void APIEndpoint::connectionHandler(PipeHandle& handle)
{
    auto client = handle.loop().resource<PipeHandle>();
    auto timer = client->loop().resource<TimerHandle>();

    auto protocolHandler = std::make_shared<ProtocolHandler>();

    timer->on<TimerEvent>(
        [client](const auto&, auto& handler)
        {
            WAZUH_LOG_INFO("API TimerEvent: Timeout for connection.");
            client->close();
            handler.close();
        });

    client->on<ErrorEvent>(
        [](const ErrorEvent& event, PipeHandle& client)
        {
            WAZUH_LOG_ERROR("API ErrorEvent: endpoint[{}] error: code=[{}]; "
                            "name=[{}]; message=[{}]",
                            client.peer(),
                            event.code(),
                            event.name(),
                            event.what());
        });

    client->on<DataEvent>(
        [&, timer, protocolHandler](const DataEvent& event, PipeHandle& client)
        {
            timer->again();
            const auto result {protocolHandler->process(event.data.get(), event.length)};

            if (result)
            {
                for (const auto& message : result.value())
                {
                    api::WazuhResponse wresponse {};
                    try
                    {
                        auto jrequest = json::Json {message.c_str()};
                        auto wrequest = api::WazuhRequest {jrequest};
                        if (wrequest.isValid())
                        {
                            wresponse =
                                m_registry->getCallback(wrequest.getCommand().value())(
                                    wrequest.getParameters().value());
                        }
                        else
                        {
                            wresponse = api::WazuhResponse(
                                json::Json {R"({})"}, -1, wrequest.error().value());
                            // Create ERROR API response
                        }
                    }
                    catch (const std::runtime_error& e)
                    {
                        wresponse = api::WazuhResponse::invalidRequest();
                    }
                    catch (const std::exception& e)
                    {
                        wresponse = api::WazuhResponse::unknownError();
                        WAZUH_LOG_ERROR("API DataEvent: endpoint[{}] error: {}",
                                        client.peer(),
                                        e.what());
                    }

                    auto [buffer, size] {addSecureHeader(wresponse.toString())};
                    client.write(std::move(buffer), size);
                }
            }
            else
            {
                WAZUH_LOG_WARN("API DataEvent: endpoint[{}] error: Data could "
                               "not be processed.",
                               m_path);
                auto invalidSize = api::WazuhResponse::invalidSize();
                auto [buffer, size] {addSecureHeader(invalidSize.toString())};
                client.write(std::move(buffer), size);
                timer->close();
                client.close();
            }
        });

    client->on<EndEvent>(
        [timer](const EndEvent&, PipeHandle& client)
        {
            WAZUH_LOG_INFO("API EndEvent: Terminating connection.");
            timer->close();
            client.close();
        });

    client->on<CloseEvent>([](const CloseEvent& event, PipeHandle& client)
                           { WAZUH_LOG_INFO("API CloseEvent: Connection closed."); });

    handle.accept(*client);
    WAZUH_LOG_INFO("API ListenEvent: Client accepted.");

    timer->start(TimerHandle::Time {CONNECTION_TIMEOUT_MSEC},
                 TimerHandle::Time {CONNECTION_TIMEOUT_MSEC});

    client->read();
}

APIEndpoint::APIEndpoint(const std::string &config,  std::shared_ptr<api::Registry> registry)
    : BaseEndpoint {config}
    , m_loop {Loop::getDefault()}
    , m_handle {m_loop->resource<PipeHandle>()}
    , m_registry {registry}
{

    m_handle->on<ErrorEvent>(
        [](const ErrorEvent& event, PipeHandle& handle)
        {
            WAZUH_LOG_ERROR("API ErrorEvent: endpoint[{}] error: code=[{}]; "
                            "name=[{}]; message=[{}]",
                            handle.sock(),
                            event.code(),
                            event.name(),
                            event.what());
        });

    m_handle->on<ListenEvent>(
        [this](const ListenEvent& event, PipeHandle& handle)
        {
            WAZUH_LOG_INFO("API ListenEvent: stablishing new connection.");
            connectionHandler(handle);
        });

    m_handle->on<CloseEvent>([](const CloseEvent& event, PipeHandle& handle)
                             { WAZUH_LOG_INFO("API CloseEvent."); });

    WAZUH_LOG_INFO("API endpoint configured: [{}]", config);
}

void APIEndpoint::configure()
{
    unlink(m_path.c_str());
    m_handle->bind(m_path);
    m_handle->listen();
}

void APIEndpoint::run()
{
    // Check if the endpoint is already running
    if (m_handle->active())
    {
        WAZUH_LOG_INFO("API endpoint already running.");
        return;
    } // else
    m_loop->run<Loop::Mode::DEFAULT>();
}

void APIEndpoint::close()
{
    if (m_loop->alive())
    {
        m_loop->stop(); /// Stops the loop
        m_loop->walk([](uvw::BaseHandle& handle)
                     { handle.close(); }); /// Triggers every handle's close callback
        m_loop->run(); /// Runs the loop again, so every handle is able to receive
                       /// its close callback
        m_loop->clear();
        m_loop->close();
        WAZUH_LOG_INFO("Closed loop.");
    }
    else
    {
        WAZUH_LOG_INFO("Loop is already closed.");
    }
}

APIEndpoint::~APIEndpoint()
{
    close();
};

std::shared_ptr<api::Registry> APIEndpoint::getRegistry() const
{
    return m_registry;
}

} // namespace engineserver::endpoints
