/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "httpsClientFacade.hpp"

HttpsClientFacade::HttpsClientFacade(const hc_config_t& config, const hc_callbacks_t& callbacks)
    : m_config(ModuleConfig::fromC(config))
    , m_callbacks(callbacks)
{
}

HttpsClientFacade::~HttpsClientFacade()
{
    stop();
}

bool HttpsClientFacade::start()
{
    {
        std::lock_guard<std::mutex> lock(m_lifecycleMutex);
        if (m_started)
        {
            LOGFN_WARN(m_logFn, "https_client already started, ignoring start request.");
            return true;
        }
        if (!validateConfig())
        {
            return false;
        }
        m_started = true;
    }
    LOGFN_INFO(m_logFn,
               "Starting https_client (server=%s:%u, agent=%s).",
               m_config.serverHost.c_str(),
               m_config.serverPort,
               m_config.agentId.c_str());
    publishState(HC_STATE_STARTING);
    return true;
}

void HttpsClientFacade::stop()
{
    {
        std::lock_guard<std::mutex> lock(m_lifecycleMutex);
        if (!m_started)
        {
            return;
        }
        m_started = false;
    }
    LOGFN_INFO(m_logFn, "Stopping https_client.");
    publishState(HC_STATE_STOPPED);
}

bool HttpsClientFacade::submitEvent(const uint8_t* frame, size_t length)
{
    if (!m_started || frame == nullptr || length == 0)
    {
        return false;
    }
    // Routed to the stateless stream once it lands; nothing accepts data yet.
    return false;
}

bool HttpsClientFacade::submitSyncSession(const char* sessionId, const uint8_t* buffer, size_t length)
{
    if (!m_started || sessionId == nullptr || buffer == nullptr || length == 0)
    {
        return false;
    }
    // Routed to the stateful stream once it lands; nothing accepts data yet.
    return false;
}

bool HttpsClientFacade::submitTaskResponse(const char* taskId, const char* resultJson)
{
    if (!m_started || taskId == nullptr || resultJson == nullptr)
    {
        return false;
    }
    // Routed to the control stream once it lands; nothing accepts data yet.
    return false;
}

void HttpsClientFacade::notifyNow()
{
    if (m_started)
    {
        LOGFN_DEBUG1(m_logFn, "notify_now requested (control stream not wired yet).");
    }
}

hc_conn_state_t HttpsClientFacade::state() const
{
    return static_cast<hc_conn_state_t>(m_state.load());
}

bool HttpsClientFacade::validateConfig() const
{
    return m_config.validate(m_fsProbe, m_logFn);
}

void HttpsClientFacade::publishState(hc_conn_state_t newState)
{
    const int previous = m_state.exchange(newState);
    if (previous != newState && m_callbacks.on_state_change != nullptr)
    {
        m_callbacks.on_state_change(newState, m_callbacks.user_data);
    }
}
