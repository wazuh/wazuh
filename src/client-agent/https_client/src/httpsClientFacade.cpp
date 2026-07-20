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
    , m_spoolFactory(m_config.spoolDir)
    , m_performer(m_config, defaultCurlHandleFactory())
    , m_dispatcher(callbacks)
    , m_stateless(m_config, m_performer, m_signer, m_clock, m_random, m_dispatcher)
    , m_stateful(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_dispatcher)
    , m_control(m_config, m_performer, m_signer, m_clock, m_random, m_dispatcher)
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
    m_statelessThread = std::thread(&HttpsClientFacade::statelessLoop, this);
    m_statefulThread = std::thread(&HttpsClientFacade::statefulLoop, this);
    startSyncIntake();
    return true;
}

void HttpsClientFacade::startSyncIntake()
{
    if (m_config.syncSocketPath.empty())
    {
        return; // Large-session intake disabled; sessions arrive via the ABI only.
    }

    const std::string spoolDir = m_config.spoolDir.empty() ? std::string {"/tmp"} :
                                 m_config.spoolDir;
    m_syncIntake = std::make_unique<SyncIntake>(
                       m_config.syncSocketPath, spoolDir,
                       [this](const std::string & sessionId, const std::string & path, uint64_t size)
    {
        // The intake streamed the session to `path`; hand it to the stateful
        // stream, which adopts and deletes it after sending.
        m_stateful.submitFile(sessionId, path, size);
        m_statefulWaiter.notify();
    });

    if (m_syncIntake->start())
    {
        LOGFN_INFO(m_logFn, "https_client sync intake listening on %s.",
                   m_config.syncSocketPath.c_str());
    }
    else
    {
        LOGFN_ERROR(m_logFn, "https_client sync intake failed to bind %s.",
                    m_config.syncSocketPath.c_str());
        m_syncIntake.reset();
    }
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

    // Stop the intake first so no new sessions arrive during the drain.
    if (m_syncIntake)
    {
        m_syncIntake->stop();
        m_syncIntake.reset();
    }

    // Interrupt in-flight requests and break the loops; wake gated streams.
    m_controlWaiter.requestStop();
    m_statelessWaiter.requestStop();
    m_statefulWaiter.requestStop();
    m_gate.abort();

    if (m_controlThread.joinable())
    {
        m_controlThread.join();
    }

    if (m_statelessThread.joinable())
    {
        m_statelessThread.join();
    }

    if (m_statefulThread.joinable())
    {
        m_statefulThread.join();
    }

    drain(); // Best-effort final flush + shutdown Notify, from this thread.

    m_dispatcher.onStateChange(HC_STATE_STOPPED);
    m_dispatcher.stop(); // Drains queued callbacks, then joins.
}

void HttpsClientFacade::controlLoop()
{
    while (true)
    {
        const bool registered = m_control.step(m_controlWaiter, false);

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

void HttpsClientFacade::statelessLoop()
{
    if (!m_gate.wait())
    {
        return; // Aborted before registration.
    }

    while (true)
    {
        m_stateless.tick(m_statelessWaiter, false);

        if (!m_statelessWaiter.waitFor(std::chrono::milliseconds {m_config.batchIntervalMs}))
        {
            break;
        }
    }
}

void HttpsClientFacade::statefulLoop()
{
    if (!m_gate.wait())
    {
        return;
    }

    while (true)
    {
        while (m_stateful.step(m_statefulWaiter))
        {
            if (m_statefulWaiter.stopRequested())
            {
                return;
            }
        }

        if (!m_statefulWaiter.waitFor(std::chrono::milliseconds {m_config.batchIntervalMs}))
        {
            break;
        }
    }
}

void HttpsClientFacade::drain()
{
    if (m_control.connState() != HC_STATE_REGISTERED)
    {
        return; // Never registered: nothing to flush toward the manager.
    }

    m_stateless.tick(m_drainWaiter, true); // One final forced flush.
    m_control.step(m_drainWaiter, true);   // Final Notify with shutdown status.
}

std::chrono::milliseconds HttpsClientFacade::controlInterval() const
{
    const uint32_t seconds =
        m_control.useSlowCadence() ? m_config.rejectedRetryIntervalS : m_config.notifyIntervalS;
    return std::chrono::seconds {seconds};
}

bool HttpsClientFacade::submitEvent(const uint8_t* frame, size_t length)
{
    if (!m_started || frame == nullptr || length == 0)
    {
        return false;
    }

    return m_stateless.submit(frame, length);
}

bool HttpsClientFacade::submitSyncSession(const char* sessionId, const uint8_t* buffer, size_t length)
{
    if (!m_started || sessionId == nullptr || buffer == nullptr || length == 0)
    {
        return false;
    }

    const bool queued = m_stateful.submit(sessionId, buffer, length);
    m_statefulWaiter.notify(); // Wake the sender promptly.
    return queued;
}

bool HttpsClientFacade::submitSyncSessionFile(const char* sessionId, const char* filePath,
                                              uint64_t size)
{
    if (!m_started || sessionId == nullptr || filePath == nullptr)
    {
        return false;
    }

    const bool queued = m_stateful.submitFile(sessionId, filePath, size);
    m_statefulWaiter.notify(); // Wake the sender promptly.
    return queued;
}

bool HttpsClientFacade::submitTaskResponse(const char* taskId, const char* resultJson)
{
    if (!m_started || taskId == nullptr || resultJson == nullptr)
    {
        return false;
    }

    m_control.queueTaskResponse(taskId, resultJson);
    return true;
}

void HttpsClientFacade::notifyNow()
{
    if (m_started)
    {
        m_controlWaiter.notify(); // Break the Notify cadence for one out-of-cycle send.
    }
}

hc_conn_state_t HttpsClientFacade::state() const
{
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);
    return m_started ? m_control.connState() : HC_STATE_STOPPED;
}
