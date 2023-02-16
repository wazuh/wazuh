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

#include "server/wazuhStreamProtocol.hpp"

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
constexpr uint32_t CONNECTION_TIMEOUT_MSEC {5000}; // Stream

auto addSecureHeader(std::string_view data)
{
    auto buffer = std::unique_ptr<char[]> {new char[data.size() + sizeof(uint32_t)]};
    auto size = static_cast<uint32_t>(data.size());
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

    auto protocolHandler = std::make_shared<WazuhStreamProtocol>();

    timer->on<TimerEvent>(
        [client](const auto&, auto& handler)
        {
            WAZUH_LOG_INFO("Engine API endpoint: Connection timeout with client ({}).",
                           client->peer());
            client->close();
            handler.close();
        });

    client->on<ErrorEvent>(
        [](const ErrorEvent& event, PipeHandle& client)
        {
            WAZUH_LOG_ERROR("Engine API endpoint: Connection error with client ({}): "
                            "code=[{}]; name=[{}]; message=[{}].",
                            client.peer(),
                            event.code(),
                            event.name(),
                            event.what());
        });

    client->on<DataEvent>(
        [&, timer, protocolHandler](const DataEvent& event, PipeHandle& client)
        {
            timer->again();
            const auto result = protocolHandler->process(event.data.get(), event.length);

            if (result)
            {
                for (const auto& message : result.value())
                {
                    base::utils::wazuhProtocol::WazuhResponse wresponse {};
                    try
                    {
                        json::Json jrequest {message.c_str()};
                        base::utils::wazuhProtocol::WazuhRequest wrequest {jrequest};
                        if (wrequest.isValid())
                        {
                            wresponse = m_registry->getCallback(wrequest.getCommand().value())(wrequest);
                        }
                        else
                        {
                            wresponse =
                                base::utils::wazuhProtocol::WazuhResponse::invalidRequest(wrequest.error().value());
                        }
                    }
                    catch (const std::runtime_error& e)
                    {
                        wresponse = base::utils::wazuhProtocol::WazuhResponse::invalidJsonRequest();
                    }
                    catch (const std::exception& e)
                    {
                        wresponse = base::utils::wazuhProtocol::WazuhResponse::unknownError();
                        WAZUH_LOG_ERROR("Engine API endpoint: Error with client ({}): {}", client.peer(), e.what());
                    }

                    auto [buffer, size] = addSecureHeader(wresponse.toString());
                    client.write(std::move(buffer), size);
                }
            }
            else
            {
                WAZUH_LOG_WARN(
                    "Engine API endpoint: Some data could not be processed from client "
                    "({}).",
                    client.peer());
                // TODO: are we sure that it is always due to an invalid size?
                auto invalidSize = base::utils::wazuhProtocol::WazuhResponse::invalidSize();
                auto [buffer, size] {addSecureHeader(invalidSize.toString())};
                client.write(std::move(buffer), size);
                timer->close();
                client.close();
            }
        });

    client->on<EndEvent>(
        [timer](const EndEvent&, PipeHandle& client)
        {
            WAZUH_LOG_INFO("Engine API endpoint: Closing connection of client ({}).",
                           client.peer());
            timer->close();
            client.close();
        });

    client->on<CloseEvent>(
        [](const CloseEvent& event, PipeHandle& client)
        {
            WAZUH_LOG_INFO("Engine API endpoint: Connection closed of client ({}).",
                           client.peer());
        });

    handle.accept(*client);
    WAZUH_LOG_INFO("Engine API endpoint: Client accepted: {}", client->peer());

    timer->start(TimerHandle::Time {CONNECTION_TIMEOUT_MSEC},
                 TimerHandle::Time {CONNECTION_TIMEOUT_MSEC});

    client->read();
}

APIEndpoint::APIEndpoint(const std::string& config,
                         std::shared_ptr<api::Registry> registry)
    : BaseEndpoint {config}
    , m_loop {Loop::getDefault()}
    , m_handle {m_loop->resource<PipeHandle>()}
    , m_registry {registry}
{
    m_handle->on<ErrorEvent>(
        [](const ErrorEvent& event, PipeHandle& handle)
        {
            WAZUH_LOG_ERROR("Engine API endpoint: Error on endpoint ({}): code=[{}]; "
                            "name=[{}]; message=[{}].",
                            handle.sock(),
                            event.code(),
                            event.name(),
                            event.what());
        });

    m_handle->on<ListenEvent>(
        [this](const ListenEvent& event, PipeHandle& handle)
        {
            // TODO check if the parameter is correct
            WAZUH_LOG_INFO("Engine API endpoint: Stablishing a new connection with peer "
                           "({}).",
                           handle.peer());
            connectionHandler(handle);
        });

    m_handle->on<CloseEvent>(
        [](const CloseEvent& event, PipeHandle& handle)
        {
            // TODO check if the parameter is correct
            WAZUH_LOG_INFO("Engine API endpoint: Closing connection with peer ({}).",
                           handle.peer());
        });

    WAZUH_LOG_INFO("Engine API endpoint: Endpoint configured: [{}]", config);
}

void APIEndpoint::configure()
{
    unlink(m_path.c_str());
    m_handle->bind(m_path);
    m_handle->listen();
}

void APIEndpoint::run()
{
    m_loop->run<Loop::Mode::DEFAULT>();
}

void APIEndpoint::close()
{
    if (m_loop->alive())
    {
        // The loop is stoped
        m_loop->stop();
        // Every handle's closing callback is triggered
        m_loop->walk([](uvw::BaseHandle& handle) { handle.close(); });
        // The loop is run again, so every handle is able to receive its close callback
        m_loop->run();
        m_loop->clear();
        m_loop->close();
        WAZUH_LOG_INFO("Engine API endpoint: All the endpoints were closed.");
    }
    else
    {
        WAZUH_LOG_INFO("Engine API endpoint: Loop is already closed.");
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
