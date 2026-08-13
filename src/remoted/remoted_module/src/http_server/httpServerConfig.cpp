/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "httpServerConfig.hpp"

#include "proc.hpp"

#include <string>

namespace
{
    constexpr auto DEFAULT_BIND_ADDRESS {"127.0.0.1"};
    constexpr std::uint16_t DEFAULT_HTTPS_PORT {1517};
    // Multiplier applied to cpp_get_nproc() for the handler pool: unlike the I/O reactor threads,
    // work here can block (CMAC verification, client.keys file I/O), so it is oversubscribed.
    constexpr unsigned int WORKER_THREADS_NPROC_MULTIPLIER {2};
    // Transport hard cap. Kept above the auth middleware's body limit (AuthConfig::maxBodySize,
    // 10 MiB) so an oversized batch reaches the middleware and gets a clean 413 there, while this
    // still bounds memory as a backstop.
    constexpr std::size_t DEFAULT_MAX_BODY_SIZE {20U * 1024U * 1024U};
    constexpr std::size_t DEFAULT_READ_TIMEOUT_SEC {10};
    constexpr std::size_t DEFAULT_WRITE_TIMEOUT_SEC {10};
    constexpr std::size_t DEFAULT_REQUEST_TIMEOUT_SEC {30};
    constexpr std::size_t DEFAULT_MAX_URL_SIZE {2048};
    constexpr std::size_t DEFAULT_MAX_HEADER_NAME_SIZE {256};
    constexpr std::size_t DEFAULT_MAX_HEADER_VALUE_SIZE {8192};
    constexpr std::size_t DEFAULT_MAX_HEADER_COUNT {64};
    constexpr std::size_t DEFAULT_MAX_PIPELINED_REQUESTS {4};
    constexpr std::size_t DEFAULT_CONCURRENT_ACCEPTS {2};
    constexpr std::size_t DEFAULT_BUFFER_SIZE {8192};
    // Bytes per chunk for a streamed response body. Agreed default; tunable through
    // remoted.http_stream_chunk_size because the CPU cost per byte moves noticeably with it.
    constexpr std::size_t DEFAULT_STREAM_CHUNK_SIZE {64U * 1024U};

    // Global cap on in-flight (unprocessed) request payload bytes. Bounds the worker-pool
    // queue + handlers + deferred responses so a burst can't grow memory without limit;
    // over it, new requests get 503.
    constexpr std::size_t DEFAULT_MAX_INFLIGHT_BYTES {256U * 1024U * 1024U};

    // Max simultaneous TCP connections. With DEFAULT_MAX_BODY_SIZE it bounds the read-phase
    // peak (bodies being received before they reach the budget) to conns * http_max_body_size.
    constexpr std::size_t DEFAULT_MAX_PARALLEL_CONNECTIONS {512};

    // Relative to remoted's cwd, which is the chroot root ("/") by the time these paths are
    // opened (Privsep_Chroot() chdir()s there before the HTTPS module starts), so these resolve
    // identically to an equivalent leading-"/" path -- written without one here to avoid reading
    // as a real host-absolute path.
    constexpr auto DEFAULT_CERTIFICATE_PATH {"etc/certs/remoted.pem"};
    constexpr auto DEFAULT_PRIVATE_KEY_PATH {"etc/certs/remoted-key.pem"};
    constexpr auto DEFAULT_CA_PATH {"etc/certs/root-ca.pem"};
    constexpr auto DEFAULT_CIPHERS {"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"};

    // A positive caller value wins; otherwise the built-in default. remoted is expected to
    // always pass an already-validated value read from the `remoted.http_*` internal options.
    std::size_t resolveUnsigned(const int configValue, const std::size_t defaultValue)
    {
        return configValue > 0 ? static_cast<std::size_t>(configValue) : defaultValue;
    }

    // Same as above for the C-ABI's `long` fields (e.g. http_max_body_size, a regular <remote>
    // setting rather than an internal option, but resolved the same way: positive wins).
    std::size_t resolveUnsigned(const long configValue, const std::size_t defaultValue)
    {
        return configValue > 0 ? static_cast<std::size_t>(configValue) : defaultValue;
    }

    // Thread-count fields: a positive caller value wins; otherwise cpp_get_nproc() (optionally
    // scaled), so the pool size tracks the host/cgroup's available CPUs instead of a fixed constant.
    std::size_t resolveThreadCount(const int configValue, const unsigned int nprocMultiplier = 1)
    {
        if (configValue > 0)
        {
            return static_cast<std::size_t>(configValue);
        }
        return static_cast<std::size_t>(cpp_get_nproc()) * nprocMultiplier;
    }

    // An explicitly-configured C-ABI verification_mode wins (already validated by the config
    // parser), including None/0. REMOTED_MODULE_HTTPS_VERIFY_UNSET (-1) is the only value that
    // means "the operator never configured <verification_mode>", and it resolves to the
    // built-in default: verification disabled. Do not treat 0 as unset here: that would
    // silently override an explicit <verification_mode>none</verification_mode>.
    remoted::http::ClientVerificationMode resolveVerificationMode(const int configValue)
    {
        switch (configValue)
        {
            case REMOTED_MODULE_HTTPS_VERIFY_UNSET:
            case REMOTED_MODULE_HTTPS_VERIFY_NONE: return remoted::http::ClientVerificationMode::None;
            case REMOTED_MODULE_HTTPS_VERIFY_CERTIFICATE: return remoted::http::ClientVerificationMode::Certificate;
            case REMOTED_MODULE_HTTPS_VERIFY_FULL: return remoted::http::ClientVerificationMode::Full;
            default:
                // A value this build does not recognise, which can only come from a config
                // library built against a different revision of the C-ABI. It must NOT silently
                // downgrade to no verification at all, so it keeps requiring a client
                // certificate -- the strictest mode that needs no extra configuration.
                return remoted::http::ClientVerificationMode::Certificate;
        }
    }

    // Unlike verification_mode above, dual_stack has no sentinel distinct from its own
    // built-in default: REMOTED_MODULE_HTTPS_DUAL_STACK_UNSET (0) already equals
    // DualStackMode::Unset, so a bare static_cast<> is enough.
    remoted::http::DualStackMode resolveDualStackMode(const int configValue)
    {
        return static_cast<remoted::http::DualStackMode>(configValue);
    }
} // namespace

namespace remoted::http
{
    // ClientVerificationMode is mapped from the C-ABI int in resolveVerificationMode() above,
    // so its enumerator values must stay pinned to REMOTED_MODULE_HTTPS_VERIFY_*
    // (remoted_module.h) -- a silent renumbering of either enum would misconfigure TLS
    // client-certificate verification without any build failure to catch it.
    static_assert(static_cast<int>(ClientVerificationMode::None) == REMOTED_MODULE_HTTPS_VERIFY_NONE,
                  "ClientVerificationMode::None must match REMOTED_MODULE_HTTPS_VERIFY_NONE");
    static_assert(static_cast<int>(ClientVerificationMode::Certificate) == REMOTED_MODULE_HTTPS_VERIFY_CERTIFICATE,
                  "ClientVerificationMode::Certificate must match REMOTED_MODULE_HTTPS_VERIFY_CERTIFICATE");
    static_assert(static_cast<int>(ClientVerificationMode::Full) == REMOTED_MODULE_HTTPS_VERIFY_FULL,
                  "ClientVerificationMode::Full must match REMOTED_MODULE_HTTPS_VERIFY_FULL");

    // Same reasoning as above: DualStackMode is produced from the C-ABI int via a bare
    // static_cast<> in resolveDualStackMode(), so its enumerator order must stay pinned
    // to REMOTED_MODULE_HTTPS_DUAL_STACK_* (remoted_module.h).
    static_assert(static_cast<int>(DualStackMode::Unset) == REMOTED_MODULE_HTTPS_DUAL_STACK_UNSET,
                  "DualStackMode::Unset must match REMOTED_MODULE_HTTPS_DUAL_STACK_UNSET");
    static_assert(static_cast<int>(DualStackMode::Enabled) == REMOTED_MODULE_HTTPS_DUAL_STACK_YES,
                  "DualStackMode::Enabled must match REMOTED_MODULE_HTTPS_DUAL_STACK_YES");
    static_assert(static_cast<int>(DualStackMode::Disabled) == REMOTED_MODULE_HTTPS_DUAL_STACK_NO,
                  "DualStackMode::Disabled must match REMOTED_MODULE_HTTPS_DUAL_STACK_NO");

    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config)
    {
        HttpServerConfig result;

        result.bindAddress = config.bind_address[0] != '\0' ? std::string {config.bind_address} : DEFAULT_BIND_ADDRESS;

        result.port = static_cast<std::uint16_t>(resolveUnsigned(config.port, DEFAULT_HTTPS_PORT));
        result.ioThreads = resolveThreadCount(config.io_threads);
        result.workerThreads = resolveThreadCount(config.http_worker_threads, WORKER_THREADS_NPROC_MULTIPLIER);
        result.maxBodySize = resolveUnsigned(config.http_max_body_size, DEFAULT_MAX_BODY_SIZE);
        result.readTimeoutSec = resolveUnsigned(config.http_read_timeout, DEFAULT_READ_TIMEOUT_SEC);
        result.writeTimeoutSec = resolveUnsigned(config.http_write_timeout, DEFAULT_WRITE_TIMEOUT_SEC);
        result.requestTimeoutSec = resolveUnsigned(config.http_request_timeout, DEFAULT_REQUEST_TIMEOUT_SEC);
        result.maxUrlSize = resolveUnsigned(config.http_max_url_size, DEFAULT_MAX_URL_SIZE);
        result.maxHeaderNameSize = resolveUnsigned(config.http_max_header_name_size, DEFAULT_MAX_HEADER_NAME_SIZE);
        result.maxHeaderValueSize = resolveUnsigned(config.http_max_header_value_size, DEFAULT_MAX_HEADER_VALUE_SIZE);
        result.maxHeaderCount = resolveUnsigned(config.http_max_header_count, DEFAULT_MAX_HEADER_COUNT);
        result.maxPipelinedRequests =
            resolveUnsigned(config.http_max_pipelined_requests, DEFAULT_MAX_PIPELINED_REQUESTS);
        result.concurrentAccepts = resolveUnsigned(config.http_concurrent_accepts, DEFAULT_CONCURRENT_ACCEPTS);
        result.bufferSize = resolveUnsigned(config.http_buffer_size, DEFAULT_BUFFER_SIZE);
        result.streamChunkSize = resolveUnsigned(config.http_stream_chunk_size, DEFAULT_STREAM_CHUNK_SIZE);

        // Memory-management knobs come from remoted's config struct (a positive value wins),
        // otherwise the built-in default -- deliberately NOT env-driven. The transport clamps the
        // in-flight budget to at least one max-size body at start() so a too-small value can't
        // reject everything.
        result.maxInFlightBytes = config.max_inflight_bytes > 0 ? static_cast<std::size_t>(config.max_inflight_bytes)
                                                                : DEFAULT_MAX_INFLIGHT_BYTES;

        result.maxParallelConnections = config.max_parallel_connections > 0
                                            ? static_cast<std::size_t>(config.max_parallel_connections)
                                            : DEFAULT_MAX_PARALLEL_CONNECTIONS;

        result.certificatePath =
            config.certificate_path[0] != '\0' ? std::string {config.certificate_path} : DEFAULT_CERTIFICATE_PATH;

        result.privateKeyPath =
            config.private_key_path[0] != '\0' ? std::string {config.private_key_path} : DEFAULT_PRIVATE_KEY_PATH;

        result.caPath = config.ca_path[0] != '\0' ? std::string {config.ca_path} : DEFAULT_CA_PATH;
        result.ciphers = config.ciphers[0] != '\0' ? std::string {config.ciphers} : DEFAULT_CIPHERS;
        result.verificationMode = resolveVerificationMode(config.verification_mode);
        result.dualStackMode = resolveDualStackMode(config.dual_stack);

        return result;
    }

} // namespace remoted::http
