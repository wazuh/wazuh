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

#ifndef _HC_MODULE_CONFIG_HPP
#define _HC_MODULE_CONFIG_HPP

#include "https_client.h"
#include "loggerHelper.h"
#include "sysSeams.hpp"

#include <cstdint>
#include <string>

/**
 * @brief Typed, deep-copied configuration with the module defaults applied.
 *
 * Built once from the C POD at creation; the caller's struct is never
 * retained. validate() implements the fail-closed TLS policy: when the
 * verification mode requires a CA and none is configured or readable, the
 * client refuses to start and no request ever leaves the agent.
 */
struct ModuleConfig
{
        std::string serverHost;
        uint16_t serverPort {443};
        std::string agentId;
        std::string agentKeyHex;
        hc_verify_mode_t verifyMode {HC_VERIFY_FULL};
        std::string caPath;
        std::string clientCert;
        std::string clientKey;
        std::string ciphers;

        uint32_t notifyIntervalS {20};
        uint32_t rejectedRetryIntervalS {60};

        std::string version;

        uint32_t requestTimeoutMs {10000};
        uint32_t backoffBaseMs {1000};
        uint32_t backoffCapMs {60000};
        uint32_t drainTimeoutMs {5000};

        std::string spoolDir;

        // Always "https" in production (fromC never changes it); the component
        // test overrides it to "http" to drive the real curl path against a
        // plaintext fake manager.
        std::string scheme {"https"};

        static ModuleConfig fromC(const hc_config_t& config);

        bool validate(const IFsProbe& fsProbe, const LogFn& logFn) const;

        std::string baseUrl() const;

    private:
        bool validateTls(const IFsProbe& fsProbe, const LogFn& logFn) const;
        bool validateClientCert(const IFsProbe& fsProbe, const LogFn& logFn) const;
};

#endif // _HC_MODULE_CONFIG_HPP
