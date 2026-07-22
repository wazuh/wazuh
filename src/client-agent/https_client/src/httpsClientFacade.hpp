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
#include "cmacSigner.hpp"
#include "curlPerformer.hpp"
#include "https_client.h"
#include "keyProvider.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

#include <mutex>

/**
 * @brief Composition root of the agent HTTPS client behind the C ABI.
 *
 * Builds every seam (curl performer, signer, dispatcher) and owns the module
 * lifecycle. The stream loops (/control, /stateless, /stateful) mount on this
 * skeleton in their own workstreams; the foundation carries configuration
 * validation (fail-closed TLS), the signing credential and its runtime swap
 * (hc_set_agent_key after a re-enrollment), and the callback dispatcher. The
 * lifecycle skeleton mirrors the manager-side RemotedModuleFacade.
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

        bool setAgentKey(const char* keyHex);
        hc_conn_state_t state() const;

    private:
        ModuleConfig m_config;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};

        // Seams (built once; stable references handed to the streams).
        SystemClock m_clock;
        Mt19937Random m_random;
        FsProbe m_fsProbe;
        ConfigKeyProvider m_keyProvider;
        CmacSigner m_signer;
        CurlPerformer m_performer;
        CallbackDispatcher m_dispatcher;
        // Pauses all outbound traffic on a 401 and surfaces re-enrollment once
        // per incident; hc_set_agent_key -> release() resumes. The wake hook
        // is a no-op until the control loop (#37830) mounts and hooks it.
        AuthGate m_authGate {m_dispatcher, [] {}};

        mutable std::mutex m_lifecycleMutex;
        bool m_started {false};
};

#endif // _HTTPS_CLIENT_FACADE_HPP
