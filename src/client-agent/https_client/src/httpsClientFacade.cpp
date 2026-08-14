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

#include <functional>
#include <string>

namespace
{
    /// Wraps a `void(char*, size_t, void*)`-shaped C metadata callback as the
    /// `std::function<std::string()>` pull-source both ControlStream (Notify's
    /// host block) and StatelessStream (the H line's host block) take. Returns
    /// "" when fn is null, so an unset callback degrades to "no extra metadata"
    /// rather than a crash.
    std::function<std::string()> makeMetadataCollector(void (*fn)(char*, size_t, void*),
                                                       void* userData)
    {
        return [fn, userData]() -> std::string
        {
            if (fn == nullptr)
            {
                return {};
            }

            char buffer[4096] = {};
            fn(buffer, sizeof(buffer), userData);
            buffer[sizeof(buffer) - 1] = '\0';
            return std::string(buffer);
        };
    }

    std::function<std::string()> makeHostCollector(const hc_callbacks_t& callbacks)
    {
        return makeMetadataCollector(callbacks.on_collect_host, callbacks.user_data);
    }

    /// Pull-source for the /stateless H line's host block -- a separate C
    /// callback from on_collect_host (Notify's), so the two endpoints' host
    /// blocks can carry different fields and evolve independently without
    /// either risking the other's already-shipped contract.
    std::function<std::string()> makeStatelessHostCollector(const hc_callbacks_t& callbacks)
    {
        return makeMetadataCollector(callbacks.on_collect_stateless_host, callbacks.user_data);
    }
} // namespace

HttpsClientFacade::HttpsClientFacade(const hc_config_t& config, const hc_callbacks_t& callbacks)
    : m_config(ModuleConfig::fromC(config))
    , m_keyProvider(m_config.agentKeyHex)
    , m_signer(m_config.agentId, m_keyProvider)
    , m_spoolFactory(m_config.spoolDir)
    , m_performer(m_config, defaultCurlHandleFactory())
    , m_dispatcher(callbacks)
    , m_configHash(m_config.configChecksum)
    , m_taskStore(callbacks.check_and_record_task, callbacks.user_data)
    , m_vdOffsetStore(callbacks.vd_offset_observe, callbacks.vd_offset_clear_pending, callbacks.user_data)
    , m_collectors(callbacks)
    , m_stateless(m_config, m_performer, m_signer, m_clock, m_random, m_dispatcher, m_authGate,
                  m_compressionGate, makeStatelessHostCollector(callbacks))
    , m_stateful(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_dispatcher,
                 m_authGate, m_compressionGate, m_fileCompressor)
    , m_control(m_config, m_performer, m_signer, m_clock, m_random, m_dispatcher, m_spoolFactory,
                m_configHash, m_cluster, m_authGate, m_compressionGate, m_taskStore, m_vdOffsetStore,
                makeHostCollector(callbacks))
    , m_reporter(m_config, m_performer, m_signer, m_clock, m_random, m_authGate, m_compressionGate,
                 m_cluster, m_collectors)
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
        LOGFN_WARN(m_logFn, "Already started, ignoring start request.");
        return true;
    }

    if (m_stopped)
    {
        // Single-shot: per-run state (waiter, gate, state machine) is not reset,
        // so a restart would launch a control thread that exits immediately.
        // Fail closed instead of returning a misleading success.
        LOGFN_WARN(m_logFn, "Stopped; create a new instance to start again.");
        return false;
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

    if (m_reporter.anyEnabled())
    {
        m_reporterThread = std::thread(&HttpsClientFacade::reporterLoop, this);
    }

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
        // stream, which adopts and deletes it after sending — or right away if
        // it cannot take it.
        if (!m_stateful.submitFile(sessionId, path, size))
        {
            // Say so on both channels: the producer is another process and only
            // sees the intake's answer, while the outcome of every other session
            // reaches this agent through on_sync_response.
            LOGFN_WARN(m_logFn, "Refused sync session %s: the /stateful queue is full.",
                       sessionId.c_str());
            // 503: the manager-not-ready code the sync protocol already knows how to
            // handle (retry next cycle) - this is local backpressure, never a real HTTP
            // response, but the semantics match.
            m_dispatcher.onSyncResponse(sessionId, 503, "");
            return false;
        }

        m_statefulWaiter.notify();
        return true;
    });

    if (m_syncIntake->start())
    {
        LOGFN_INFO(m_logFn, "Sync intake listening on %s.",
                   m_config.syncSocketPath.c_str());
    }
    else
    {
        LOGFN_ERROR(m_logFn, "Sync intake failed to bind %s.",
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
        m_stopped = true; // Single-shot: reject any later start().
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
    m_reporterWaiter.requestStop();
    m_gate.abort();

    if (m_controlThread.joinable())
    {
        m_controlThread.join();
    }

    // Joins any in-flight remote_upgrade download/dispatch thread ControlStream may have
    // spawned (dispatchUpgradeTask()). Must happen here, before member teardown begins --
    // m_controlWaiter (destroyed before m_control, per this class's declaration order) is
    // captured by reference in that thread's lambda, so it must finish first.
    m_control.joinUpgradeWork();

    if (m_statelessThread.joinable())
    {
        m_statelessThread.join();
    }

    if (m_statefulThread.joinable())
    {
        m_statefulThread.join();
    }

    if (m_reporterThread.joinable())
    {
        m_reporterThread.join(); // Joined before drain: the drain skips the reporter.
    }

    drain(); // Best-effort final flush + final shutdown message, from this thread.

    m_dispatcher.onStateChange(HC_STATE_STOPPED);
    m_dispatcher.stop(); // Drains queued callbacks, then joins.
}

void HttpsClientFacade::controlLoop()
{
    // The hashes and any pending tasks only ever arrive on Notify, so a Startup that
    // just got accepted (first connect, reconnect, or a settings-refresh in place)
    // shouldn't sit idle for a full notify cycle before the first one is sent.
    constexpr std::chrono::seconds FAST_FOLLOWUP_INTERVAL {1};

    while (true)
    {
        const bool registered = m_control.step(m_controlWaiter);

        if (registered)
        {
            m_gate.open();
        }

        const auto interval = m_control.consumeFastFollowup() ? FAST_FOLLOWUP_INTERVAL : controlInterval();

        if (!m_controlWaiter.waitFor(interval))
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
        const auto delay = m_stateless.tick(m_statelessWaiter, false);

        if (!m_statelessWaiter.waitFor(delay))
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

void HttpsClientFacade::reporterLoop()
{
    if (!m_gate.wait())
    {
        return; // Aborted before registration.
    }

    while (true)
    {
        const auto delay = m_reporter.tick(m_reporterWaiter, m_control.isRegistered());

        if (!m_reporterWaiter.waitFor(delay))
        {
            break;
        }
    }
}

void HttpsClientFacade::drain()
{
    // The manager was observed never receiving the /control shutdown message, with no
    // failure log either -- pointing at this guard silently skipping the send. Neither
    // branch had a log
    // statement at any verbosity before this, so raising debug logging could
    // not distinguish "guard tripped" from "never reached this code at all".
    // These two lines make that observable; see controlStream.cpp's
    // sendShutdown() for the send-attempt/outcome logs on the other side of
    // the guard.
    if (m_authGate.paused() || m_control.connState() != HC_STATE_REGISTERED)
    {
        LOGFN_DEBUG2(m_logFn,
                     "Skipping drain/shutdown notification (auth paused=%d, connState=%d): "
                     "paused or never registered, nothing to flush.",
                     static_cast<int>(m_authGate.paused()),
                     static_cast<int>(m_control.connState()));
        return; // Paused (dead key) or never registered: nothing to flush.
    }

    LOGFN_DEBUG2(m_logFn, "Draining (stateless flush + /control shutdown) before stopping.");
    m_stateless.drain(m_drainWaiter);   // Flush the backlog in bounded batches.
    m_control.drainStep(m_drainWaiter); // Final shutdown message.
}

std::chrono::milliseconds HttpsClientFacade::controlInterval() const
{
    const uint32_t seconds =
        m_control.useSlowCadence() ? m_config.rejectedRetryIntervalS : m_config.notifyIntervalS;
    return std::chrono::seconds {seconds};
}

bool HttpsClientFacade::submitEvent(const uint8_t* frame, size_t length)
{
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);

    if (!m_started || frame == nullptr || length == 0)
    {
        return false;
    }

    const auto result = m_stateless.submit(frame, length);

    if (result.shouldWakeSender)
    {
        m_statelessWaiter.notify();
    }

    return result.accepted;
}

bool HttpsClientFacade::submitSyncSession(const char* sessionId, const uint8_t* buffer, size_t length)
{
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);

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
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);

    if (!m_started || sessionId == nullptr || filePath == nullptr)
    {
        return false;
    }

    const bool queued = m_stateful.submitFile(sessionId, filePath, size);
    m_statefulWaiter.notify(); // Wake the sender promptly.
    return queued;
}

void HttpsClientFacade::notifyNow()
{
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);

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

void HttpsClientFacade::setConfigHash(const char* configHash)
{
    // Deliberately no lifecycle lock: callable from inside callbacks (the
    // dispatcher thread) without deadlocking; only its own mutex is taken.
    m_configHash.set(configHash);
}

hc_conn_state_t HttpsClientFacade::state() const
{
    std::lock_guard<std::mutex> lock(m_lifecycleMutex);
    return m_started ? m_control.connState() : HC_STATE_STOPPED;
}
