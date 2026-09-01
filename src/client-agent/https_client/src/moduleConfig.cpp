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
    typed.serverScopeId = config.server_scope_id;
    typed.serverEndpoint = boundedString(config.server_endpoint, sizeof(config.server_endpoint));
    typed.agentId = boundedString(config.agent_id, sizeof(config.agent_id));
    typed.agentKeyHex = boundedString(config.agent_key, sizeof(config.agent_key));
    typed.verifyMode = static_cast<hc_verify_mode_t>(config.verify_mode);
    typed.caPath = boundedString(config.ca_path, sizeof(config.ca_path));
    typed.clientCert = boundedString(config.client_cert, sizeof(config.client_cert));
    typed.clientKey = boundedString(config.client_key, sizeof(config.client_key));
    typed.ciphers = boundedString(config.ciphers, sizeof(config.ciphers));
    typed.batchSizeBytes = orDefault<uint64_t>(config.batch_size_bytes, 1024 * 1024);
    typed.batchIntervalMs = orDefault<uint32_t>(config.batch_interval_ms, 10000);
    typed.bufferCapMultiplier = orDefault<uint32_t>(config.buffer_cap_multiplier, 4);
    typed.bufferWarnLevel = orDefault<uint32_t>(config.buffer_warn_level, 90);
    typed.bufferNormalLevel = orDefault<uint32_t>(config.buffer_normal_level, 70);
    typed.bufferFloodToleranceS = orDefault<uint32_t>(config.buffer_flood_tolerance_s, 15);
    typed.notifyIntervalS = orDefault<uint32_t>(config.notify_interval_s, 10);
    typed.rejectedRetryIntervalS = orDefault<uint32_t>(config.rejected_retry_interval_s, 60);
    typed.wpkMaxDownloadBytes = orDefault<uint64_t>(config.wpk_max_download_bytes, 200ULL * 1024 * 1024);
    typed.statsEnabled = config.stats_enabled;
    typed.statsIntervalS = orDefault<uint32_t>(config.stats_interval_s, 60);
    typed.configReportEnabled = config.config_report_enabled;
    typed.configReportIntervalS = orDefault<uint32_t>(config.config_report_interval_s, 3600);
    typed.version = boundedString(config.version, sizeof(config.version));
    typed.configChecksum = boundedString(config.config_checksum, sizeof(config.config_checksum));
    typed.requestTimeoutMs = orDefault<uint32_t>(config.request_timeout_ms, 10000);
    typed.statefulTimeoutMs = orDefault<uint32_t>(config.stateful_timeout_ms, 90000);
    typed.backoffBaseMs = orDefault<uint32_t>(config.backoff_base_ms, 1000);
    typed.backoffCapMs = orDefault<uint32_t>(config.backoff_cap_ms, 60000);
    typed.drainTimeoutMs = orDefault<uint32_t>(config.drain_timeout_ms, 5000);
    typed.controlMaxAttempts = orDefault<uint32_t>(config.control_max_attempts, 4);
    typed.statelessMaxAttempts = orDefault<uint32_t>(config.stateless_max_attempts, 5);
    typed.statefulMaxAttempts = orDefault<uint32_t>(config.stateful_max_attempts, 5);
    typed.downloadMaxAttempts = orDefault<uint32_t>(config.download_max_attempts, 2);
    typed.producerPauseThreshold = orDefault<uint32_t>(config.producer_pause_threshold, 2);
    typed.spoolDir = boundedString(config.spool_dir, sizeof(config.spool_dir));
    typed.syncSocketPath = boundedString(config.sync_socket_path, sizeof(config.sync_socket_path));
    typed.httpsCompressionEnabled = config.https_compression_enabled;
    return typed;
}

bool ModuleConfig::validate(const IFsProbe& fsProbe, const LogFn& logFn) const
{
    if (serverHost.empty() || agentId.empty())
    {
        LOGFN_ERROR(logFn, "Config rejected: server_host and agent_id are mandatory.");
        return false;
    }

    return validateTiming(logFn) && validateTransport(fsProbe, logFn);
}

bool ModuleConfig::validateTiming(const LogFn& logFn) const
{
    // Paired internal options: getDefine_Int_default() range-checks each one on its own, but
    // nothing relates the two, so an inverted pair is reachable from two individually valid
    // values. Rejected rather than silently reordered -- an inverted min/max is always an
    // operator error, and starting with a quietly corrected value hides it.
    if (backoffBaseMs > backoffCapMs)
    {
        LOGFN_ERROR(logFn,
                    "Config rejected: agent.https_backoff_base (%u) is above "
                    "agent.https_backoff_cap (%u).",
                    backoffBaseMs,
                    backoffCapMs);
        return false;
    }

    return true;
}

bool ModuleConfig::validateTransport(const IFsProbe& fsProbe, const LogFn& logFn) const
{
    return validateTls(fsProbe, logFn) && validateClientCert(fsProbe, logFn);
}

bool ModuleConfig::validateTls(const IFsProbe& fsProbe, const LogFn& logFn) const
{
    if (verifyMode != HC_VERIFY_FULL && verifyMode != HC_VERIFY_CERT && verifyMode != HC_VERIFY_NONE
            && verifyMode != HC_VERIFY_SYSTEM)
    {
        LOGFN_ERROR(logFn, "Config rejected: unknown verify_mode %d.", verifyMode);
        return false;
    }

    if (verifyMode == HC_VERIFY_NONE)
    {
        // The agent's own configured default (client-config.h's agent_verify_mode_t),
        // not an operator opt-out to flag -- informational, not a WARNING.
        LOGFN_INFO(logFn, "TLS verification is DISABLED (verify_mode=none).");
        return true;
    }

    if (verifyMode == HC_VERIFY_SYSTEM)
    {
        // A configured CA would simply be unused under 'system' (the OS store is the trust
        // anchor instead); failing closed here surfaces that mismatch instead of silently
        // ignoring an operator's certificate_authorities.
        if (!caPath.empty())
        {
            LOGFN_CRITICAL(logFn,
                           "https_client config rejected: verify_mode=system must not set "
                           "certificate_authorities (got '%s').",
                           caPath.c_str());
            return false;
        }

#if !defined(WIN32) && !defined(__APPLE__)

        // Windows/macOS ask their native certificate store (CurlPerformer), which this
        // process cannot introspect at validation time; Linux's trust anchor is a probed
        // file, so fail closed now rather than at the first handshake if none is found.
        if (fsProbe.findSystemCaBundle().empty())
        {
            LOGFN_CRITICAL(logFn,
                           "https_client config rejected: verify_mode=system found no OS CA "
                           "bundle in any known location.");
            return false;
        }

#endif

        return true;
    }

    // Fail closed (H1): a verifying mode without a readable CA never sends. This can never
    // self-resolve without an operator fixing the config (mirrors main.c's hard exit on a
    // missing/invalid <manager><address>) -- CRITICAL terminates the daemon via the bridge's log
    // callback instead of leaving it running with a permanently dead transport.
    if (caPath.empty() || !fsProbe.isReadableFile(caPath))
    {
        LOGFN_CRITICAL(logFn,
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
        LOGFN_ERROR(logFn, "Config rejected: client certificate and key must be set together.");
        return false;
    }

    if (!fsProbe.isReadableFile(clientCert) || !fsProbe.isReadableFile(clientKey))
    {
        LOGFN_ERROR(logFn, "Config rejected: client certificate or key is not readable.");
        return false;
    }

    return true;
}

std::string ModuleConfig::baseUrl() const
{
    // A bare IPv6 literal (which contains ':') must be bracketed in a URL
    // authority, or its trailing group is misparsed as the port:
    // https://[2001:db8::1]:443, not https://2001:db8::1:443. Hostnames and
    // IPv4 never contain ':'; an already-bracketed value is left as is.
    const bool ipv6 = serverHost.find(':') != std::string::npos && serverHost.front() != '[';

    // A link-local IPv6 address needs its zone id to be dialable, and inside a URL the
    // zone separator '%' must itself be percent-encoded, hence "%25" (#38624). Only
    // meaningful for an IPv6 literal: an IPv4 or hostname never carries a scope.
    std::string host = serverHost;

    if (ipv6)
    {
        host = "[" + serverHost;

        if (serverScopeId != 0)
        {
            host += "%25" + std::to_string(serverScopeId);
        }

        host += "]";
    }

    // serverEndpoint is NOT joined in here: #38491 (the manager's global
    // prefix) routes on the prefixed request-target, so callers fold it into
    // HttpRequestSpec::target (via prefixedTarget(), requestTarget.hpp) --
    // this function only ever sees the already-prefixed target appended to
    // it afterward, same as before #38492. Routing only: the bearer token
    // does not bind the target.
    return scheme + "://" + host + ":" + std::to_string(serverPort);
}
