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

#include "moduleConfig.hpp"

#include <cstring>

namespace
{
    // Fixed-size C buffers are not guaranteed NUL-terminated when the caller
    // filled them completely; bound every read.
    std::string boundedString(const char* field, size_t capacity)
    {
        return std::string(field, strnlen(field, capacity));
    }

    template<typename T>
    T orDefault(T value, T defaultValue)
    {
        return value != 0 ? value : defaultValue;
    }
} // namespace

ModuleConfig ModuleConfig::fromC(const hc_config_t& config)
{
    ModuleConfig typed;
    typed.serverHost = boundedString(config.server_host, sizeof(config.server_host));
    typed.serverPort = orDefault<uint16_t>(config.server_port, 443);
    typed.agentId = boundedString(config.agent_id, sizeof(config.agent_id));
    typed.agentKeyHex = boundedString(config.agent_key, sizeof(config.agent_key));
    typed.verifyMode = static_cast<hc_verify_mode_t>(config.verify_mode);
    typed.caPath = boundedString(config.ca_path, sizeof(config.ca_path));
    typed.clientCert = boundedString(config.client_cert, sizeof(config.client_cert));
    typed.clientKey = boundedString(config.client_key, sizeof(config.client_key));
    typed.ciphers = boundedString(config.ciphers, sizeof(config.ciphers));
    typed.requestTimeoutMs = orDefault<uint32_t>(config.request_timeout_ms, 10000);
    typed.backoffBaseMs = orDefault<uint32_t>(config.backoff_base_ms, 1000);
    typed.backoffCapMs = orDefault<uint32_t>(config.backoff_cap_ms, 60000);
    typed.spoolDir = boundedString(config.spool_dir, sizeof(config.spool_dir));
    return typed;
}

bool ModuleConfig::validate(const IFsProbe& fsProbe, const LogFn& logFn) const
{
    if (serverHost.empty() || agentId.empty())
    {
        LOGFN_ERROR(logFn, "https_client config rejected: server_host and agent_id are mandatory.");
        return false;
    }

    return validateTls(fsProbe, logFn) && validateClientCert(fsProbe, logFn);
}

bool ModuleConfig::validateTls(const IFsProbe& fsProbe, const LogFn& logFn) const
{
    if (verifyMode != HC_VERIFY_FULL && verifyMode != HC_VERIFY_CERT && verifyMode != HC_VERIFY_NONE)
    {
        LOGFN_ERROR(logFn, "https_client config rejected: unknown verify_mode %d.", verifyMode);
        return false;
    }

    if (verifyMode == HC_VERIFY_NONE)
    {
        LOGFN_WARN(logFn, "https_client TLS verification is DISABLED (verify_mode=none).");
        return true;
    }

    // Fail closed (H1): a verifying mode without a readable CA never sends.
    if (caPath.empty() || !fsProbe.isReadableFile(caPath))
    {
        LOGFN_ERROR(logFn,
                    "https_client config rejected: verify_mode requires a readable CA file "
                    "(certificate_authorities='%s').",
                    caPath.c_str());
        return false;
    }

    return true;
}

bool ModuleConfig::validateClientCert(const IFsProbe& fsProbe, const LogFn& logFn) const
{
    if (clientCert.empty() && clientKey.empty())
    {
        return true;
    }

    if (clientCert.empty() || clientKey.empty())
    {
        LOGFN_ERROR(logFn, "https_client config rejected: client certificate and key must be set together.");
        return false;
    }

    if (!fsProbe.isReadableFile(clientCert) || !fsProbe.isReadableFile(clientKey))
    {
        LOGFN_ERROR(logFn, "https_client config rejected: client certificate or key is not readable.");
        return false;
    }

    return true;
}

std::string ModuleConfig::baseUrl() const
{
    return scheme + "://" + serverHost + ":" + std::to_string(serverPort);
}
