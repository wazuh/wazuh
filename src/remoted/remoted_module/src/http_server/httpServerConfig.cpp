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
    constexpr std::uint16_t DEFAULT_HTTPS_PORT {9443};
    // Multiplier applied to cpp_get_nproc() for the handler pool: unlike the I/O reactor threads,
    // work here can block (CMAC verification, client.keys file I/O), so it is oversubscribed.
    constexpr unsigned int WORKER_THREADS_NPROC_MULTIPLIER {2};
    // Transport hard cap. Kept above the auth middleware's body limit (AuthConfig::maxBodySize,
    // 10 MiB) so an oversized batch reaches the middleware and gets a clean 413 there, while this
    // still bounds memory as a backstop.
    constexpr std::size_t DEFAULT_MAX_BODY_SIZE {50U * 1024U * 1024U};
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

    // Global cap on in-flight (unprocessed) request payload bytes. Bounds the worker-pool
    // queue + handlers + deferred responses so a burst can't grow memory without limit;
    // over it, new requests get 503.
    constexpr std::size_t DEFAULT_MAX_INFLIGHT_BYTES {256U * 1024U * 1024U};

    // Max simultaneous TCP connections. With DEFAULT_MAX_BODY_SIZE it bounds the read-phase
    // peak (bodies being received before they reach the budget) to conns * max_body_size.
    constexpr std::size_t DEFAULT_MAX_PARALLEL_CONNECTIONS {512};

    // A positive caller value wins; otherwise the built-in default. remoted is expected to
    // always pass an already-validated value read from the `remoted.http_*` internal options.
    std::size_t resolveUnsigned(const int configValue, const std::size_t defaultValue)
    {
        return configValue > 0 ? static_cast<std::size_t>(configValue) : defaultValue;
    }

    // Same as above for the C-ABI's `long` fields (e.g. max_body_size, a regular <remote>
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
} // namespace

namespace remoted::http
{

    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config)
    {
        HttpServerConfig result;

        result.bindAddress =
            config.bind_address[0] != '\0' ? std::string {config.bind_address} : DEFAULT_BIND_ADDRESS;

        result.port = static_cast<std::uint16_t>(resolveUnsigned(config.port, DEFAULT_HTTPS_PORT));
        result.ioThreads = resolveThreadCount(config.io_threads);
        result.workerThreads = resolveThreadCount(config.http_worker_threads, WORKER_THREADS_NPROC_MULTIPLIER);
        result.maxBodySize = resolveUnsigned(config.max_body_size, DEFAULT_MAX_BODY_SIZE);
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

        // Memory-management knobs come from remoted's config struct (a positive value wins),
        // otherwise the built-in default -- deliberately NOT env-driven. The transport clamps the
        // in-flight budget to at least one max-size body at start() so a too-small value can't
        // reject everything.
        result.maxInFlightBytes = config.max_inflight_bytes > 0 ? static_cast<std::size_t>(config.max_inflight_bytes)
                                                                : DEFAULT_MAX_INFLIGHT_BYTES;

        result.maxParallelConnections = config.max_parallel_connections > 0
                                            ? static_cast<std::size_t>(config.max_parallel_connections)
                                            : DEFAULT_MAX_PARALLEL_CONNECTIONS;

        // PEM content (not a path): remoted.c reads the certificate/key files itself while still
        // root and passes the bytes across the C-ABI boundary, so the module never opens a
        // certificate file post-privilege-drop. Empty means unreadable/unconfigured -- caught in
        // createTlsContext().
        result.certificatePem = std::string {config.certificate_pem};
        result.privateKeyPem = std::string {config.private_key_pem};

        // CA/ciphers/verification_mode are mTLS settings: empty/0 means "not configured", which
        // is a valid, meaningful state (verification disabled, library-default cipher list) --
        // not a placeholder to replace with a built-in default.
        result.caPath = config.ca_path;
        result.ciphers = config.ciphers;
        result.verificationMode = static_cast<ClientVerificationMode>(config.verification_mode);

        return result;
    }

} // namespace remoted::http
