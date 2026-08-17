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

        uint64_t batchSizeBytes {1024 * 1024};
        uint32_t batchIntervalMs {10000};
        uint32_t bufferCapMultiplier {4};

        // Legacy client-buffer ladder defaults (etc/internal_options.conf).
        uint32_t bufferWarnLevel {90};
        uint32_t bufferNormalLevel {70};
        uint32_t bufferFloodToleranceS {15};

        uint32_t notifyIntervalS {10};
        uint32_t rejectedRetryIntervalS {60};

        /// Safety bound for a remote_upgrade WPK download: stops a
        /// hostile or faulty manager exhausting disk. WPKs are tens of MB,
        /// much larger than merged.mg, hence the bigger default than config's.
        uint64_t wpkMaxDownloadBytes {200ULL * 1024 * 1024};

        std::string version;
        std::string configChecksum;

        uint32_t requestTimeoutMs {10000};
        uint32_t statefulTimeoutMs {120000};
        uint32_t backoffBaseMs {1000};
        uint32_t backoffCapMs {60000};
        uint32_t drainTimeoutMs {5000};

        std::string spoolDir;

        // #37843 periodic reporters. Struct defaults only; fromC() always overrides
        // both from the agent config, where <config_report> ships on and
        // <stats_report> stays off (see ClientConf() in client-agent/src/config.c).
        bool statsEnabled {false};
        uint32_t statsIntervalS {60};
        bool configReportEnabled {false};
        uint32_t configReportIntervalS {3600};
        std::string syncSocketPath; ///< Stateful sync-intake STREAM socket; empty = disabled.

        // zstd-compress in-memory request bodies before signing/sending.
        // internal_options.conf (agent.https_compression_enabled), off by default.
        bool httpsCompressionEnabled {false};

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
