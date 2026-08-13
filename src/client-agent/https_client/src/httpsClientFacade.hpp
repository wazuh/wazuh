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

#ifndef _HTTPS_CLIENT_FACADE_HPP
#define _HTTPS_CLIENT_FACADE_HPP

#include "authGate.hpp"
#include "callbackDispatcher.hpp"
#include "clusterIdentity.hpp"
#include "cmacSigner.hpp"
#include "collectorSource.hpp"
#include "compressionGate.hpp"
#include "configHashState.hpp"
#include "controlStream.hpp"
#include "reporterStream.hpp"
#include "curlPerformer.hpp"
#include "fileCompressor.hpp"
#include "https_client.h"
#include "keyProvider.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "registrationGate.hpp"
#include "spoolFile.hpp"
#include "statefulStream.hpp"
#include "statelessStream.hpp"
#include "stopToken.hpp"
#include "syncIntake.hpp"
#include "sysSeams.hpp"
#include "taskIdStoreAdapter.hpp"
#include "vdOffsetStoreAdapter.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

/**
 * @brief Composition root of the agent HTTPS client behind the C ABI.
 *
 * Builds every seam (curl performer, signer, spool factory, dispatcher) and
 * owns the module's threads: the control loop, the stateless sender, the
 * stateful sender and the dispatcher. The data streams idle behind a
 * registration gate until Startup is accepted. Shutdown is cooperative:
 * interrupt in-flight requests, join the loops, drain (final flush + final
 * shutdown message), then stop the dispatcher — no callback outlives stop().
 * The lifecycle skeleton mirrors the manager-side RemotedModuleFacade.
 */
class HttpsClientFacade final
{
    public:
        HttpsClientFacade(const hc_config_t& config, const hc_callbacks_t& callbacks);
        ~HttpsClientFacade();

        HttpsClientFacade(const HttpsClientFacade&) = delete;
        HttpsClientFacade& operator=(const HttpsClientFacade&) = delete;

        bool start();
        void stop();

        bool submitEvent(const uint8_t* frame, size_t length);
        bool submitSyncSession(const char* sessionId, const uint8_t* buffer, size_t length);
        bool submitSyncSessionFile(const char* sessionId, const char* filePath, uint64_t size);
        void notifyNow();
        void setConfigHash(const char* configHash);
        bool setAgentKey(const char* keyHex);
        hc_conn_state_t state() const;

    private:
        void controlLoop();
        void statelessLoop();
        void statefulLoop();
        void reporterLoop();
        void startSyncIntake();
        void drain();
        std::chrono::milliseconds controlInterval() const;

        ModuleConfig m_config;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};

        // Seams (built once; stable references handed to the streams).
        SystemClock m_clock;
        Mt19937Random m_random;
        FsProbe m_fsProbe;
        ConfigKeyProvider m_keyProvider;
        CmacSigner m_signer;
        TempSpoolFactory m_spoolFactory;
        ZstdFileCompressor m_fileCompressor; // /stateful only; compresses spooled sessions once, up front.
        CurlPerformer m_performer;
        CallbackDispatcher m_dispatcher;
        ConfigHashState m_configHash;
        ClusterIdentity m_cluster;
        TaskIdStoreAdapter m_taskStore;
        VdOffsetStoreAdapter m_vdOffsetStore;
        // Wakes the control loop so it publishes AUTH_ERROR / recovers promptly.
        // The wake lambda runs later, so referencing m_controlWaiter (declared
        // below) is safe.
        AuthGate m_authGate {m_dispatcher, [this] { m_controlWaiter.notify(); }};
        // Shared across every stream's RetrySender: one 415 disables
        // compression agent-wide for the rest of this run.
        CompressionGate m_compressionGate;

        CallbackCollectorSource m_collectors;
        StatelessStream m_stateless;
        StatefulStream m_stateful;
        ControlStream m_control;
        ReporterStream m_reporter;

        // One waiter per stream thread; the stop flag doubles as the abort flag.
        Waiter m_controlWaiter;
        Waiter m_statelessWaiter;
        Waiter m_statefulWaiter;
        Waiter m_drainWaiter; ///< Fresh (never stopped) so the final drain can run.
        RegistrationGate m_gate;

        Waiter m_reporterWaiter;

        std::thread m_controlThread;
        std::thread m_statelessThread;
        std::thread m_statefulThread;
        std::thread m_reporterThread;

        // Optional stateful sync intake (large sessions off a local STREAM
        // socket). Constructed only when a socket path is configured; its sink
        // feeds the stateful stream's file-based submit.
        std::unique_ptr<SyncIntake> m_syncIntake;

        mutable std::mutex m_lifecycleMutex;
        bool m_started {false};
        bool m_stopped {false}; ///< Latched on stop(); the client is single-shot.
};

#endif // _HTTPS_CLIENT_FACADE_HPP
