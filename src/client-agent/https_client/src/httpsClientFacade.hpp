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

#include "https_client.h"
#include "loggerHelper.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>

constexpr auto HTTPS_CLIENT_LOGTAG {"wazuh-agentd:https-client"}; ///< Tag used for module logging.

/**
 * @brief Internal engine of the agent HTTPS client.
 *
 * Composition root behind the C ABI (include/https_client.h). It owns the
 * module's threads and implements the cooperative-shutdown lifecycle
 * (atomic flag + join), mirroring the manager-side RemotedModuleFacade.
 * Unlike remoted, the hc_* ABI is handle-based, so this facade is a plain
 * class owned by the opaque hc_handle rather than a Singleton.
 *
 * The endpoint streams (stateless, stateful, control) and the callback
 * dispatcher plug in behind this lifecycle skeleton.
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
    bool submitTaskResponse(const char* taskId, const char* resultJson);
    void notifyNow();
    hc_conn_state_t state() const;

private:
    bool validateConfig() const;
    void publishState(hc_conn_state_t newState);

    hc_config_t m_config {};        ///< Deep copy (fixed-size buffers make plain copy safe).
    hc_callbacks_t m_callbacks {};  ///< Injected environment; owned by value.
    const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
    std::mutex m_lifecycleMutex;             ///< Serializes start()/stop().
    std::atomic<bool> m_started {false};     ///< Lifecycle flag; data-plane gate.
    std::atomic<int> m_state {HC_STATE_STOPPED}; ///< Published hc_conn_state_t.
};

#endif // _HTTPS_CLIENT_FACADE_HPP
