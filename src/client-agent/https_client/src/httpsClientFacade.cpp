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

#include "curlHandle.hpp"

HttpsClientFacade::HttpsClientFacade(const hc_config_t& config, const hc_callbacks_t& callbacks)
    : m_config(ModuleConfig::fromC(config))
    , m_keyProvider(m_config.agentKeyHex)
    , m_signer(m_config.agentId, m_keyProvider)
    , m_performer(m_config, defaultCurlHandleFactory())
    , m_dispatcher(callbacks)
    , m_control(m_config, m_performer, m_signer, m_clock, m_random, m_dispatcher, m_cluster,
                m_authGate)
{
}

HttpsClientFacade::~HttpsClientFacade()
{
    stop();
}

bool HttpsClientFacade::start()
{
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);

    if (m_started)
    {
        LOGFN_WARN(m_logFn, "https_client already started, ignoring start request.");
        return true;
    }

    if (!m_config.validate(m_fsProbe, m_logFn))
    {
        return false; // Fail closed: nothing starts.
    }

    LOGFN_INFO(m_logFn,
               "Starting https_client (server=%s:%u, agent=%s).",
               m_config.serverHost.c_str(),
               m_config.serverPort,
               m_config.agentId.c_str());
    m_started = true;
    m_dispatcher.start();
    m_dispatcher.onStateChange(HC_STATE_STARTING);
    m_controlThread = std::thread(&HttpsClientFacade::controlLoop, this);
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

    // Interrupt in-flight requests and break the loops; wake gated streams.
    m_controlWaiter.requestStop();
    m_gate.abort();

    if (m_controlThread.joinable())
    {
        m_controlThread.join();
    }

    drain(); // Best-effort final shutdown message, from this thread.

    m_dispatcher.onStateChange(HC_STATE_STOPPED);
    m_dispatcher.stop(); // Drains queued callbacks, then joins.
}

void HttpsClientFacade::controlLoop()
{
    while (true)
    {
        const bool registered = m_control.step(m_controlWaiter);

        if (registered)
        {
            m_gate.open();
        }

        if (!m_controlWaiter.waitFor(controlInterval()))
        {
            break;
        }
    }
}

void HttpsClientFacade::drain()
{
    if (m_authGate.paused() || m_control.connState() != HC_STATE_REGISTERED)
    {
        return; // Paused (dead key) or never registered: nothing to flush.
    }

    m_control.drainStep(m_drainWaiter); // Final shutdown message.
}

std::chrono::milliseconds HttpsClientFacade::controlInterval() const
{
    const uint32_t seconds =
        m_control.useSlowCadence() ? m_config.rejectedRetryIntervalS : m_config.notifyIntervalS;
    return std::chrono::seconds {seconds};
}

void HttpsClientFacade::notifyNow()
{
    if (m_started)
    {
        m_controlWaiter.notify(); // Break the Notify cadence for one out-of-cycle send.
    }
}

bool HttpsClientFacade::setAgentKey(const char* keyHex)
{
    // Callback-safe (no lifecycle lock): the natural flow is to call this from
    // inside on_reenroll_required. It swaps the CMAC key, clears the auth pause
    // and (via the gate's wake) drives the control loop to re-register.
    if (keyHex == nullptr || !m_keyProvider.setKey(keyHex))
    {
        return false; // Invalid material: the previous key stays in place.
    }

    m_authGate.release();
    return true;
}

hc_conn_state_t HttpsClientFacade::state() const
{
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);
    return m_started ? m_control.connState() : HC_STATE_STOPPED;
}
