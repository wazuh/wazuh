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
#include "configHashState.hpp"
#include "controlStream.hpp"
#include "curlPerformer.hpp"
#include "https_client.h"
#include "keyProvider.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "registrationGate.hpp"
#include "spoolFile.hpp"
#include "statelessStream.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>

/**
 * @brief Composition root of the agent HTTPS client behind the C ABI.
 *
 * Builds every seam (curl performer, signer, dispatcher) and owns the
 * module's threads: the control loop, the stateless sender and the
 * dispatcher. The data streams idle behind a registration gate until Startup
 * is accepted. Shutdown is cooperative: interrupt in-flight requests, join
 * the loops, drain (final flush + final shutdown message), then stop the
 * dispatcher — no callback outlives stop(). The lifecycle skeleton mirrors
 * the manager-side RemotedModuleFacade.
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
        void notifyNow();
        void setConfigHash(const char* configHash);
        bool setAgentKey(const char* keyHex);
        hc_conn_state_t state() const;

    private:
        void controlLoop();
        void statelessLoop();
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
        CurlPerformer m_performer;
        CallbackDispatcher m_dispatcher;
        ConfigHashState m_configHash;
        ClusterIdentity m_cluster;
        // Wakes the control loop so it publishes AUTH_ERROR / recovers promptly.
        // The wake lambda runs later, so referencing m_controlWaiter (declared
        // below) is safe.
        AuthGate m_authGate {m_dispatcher, [this] { m_controlWaiter.notify(); }};

        StatelessStream m_stateless;
        ControlStream m_control;

        // One waiter per stream thread; the stop flag doubles as the abort flag.
        Waiter m_controlWaiter;
        Waiter m_statelessWaiter;
        Waiter m_drainWaiter; ///< Fresh (never stopped) so the final drain can run.
        RegistrationGate m_gate;

        std::thread m_controlThread;
        std::thread m_statelessThread;

        mutable std::mutex m_lifecycleMutex;
        bool m_started {false};
        bool m_stopped {false}; ///< Latched on stop(); the client is single-shot.
};

#endif // _HTTPS_CLIENT_FACADE_HPP
