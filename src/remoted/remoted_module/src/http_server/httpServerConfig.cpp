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

#include <string>

namespace
{
    constexpr auto DEFAULT_BIND_ADDRESS {"127.0.0.1"};
    constexpr std::uint16_t DEFAULT_HTTPS_PORT {9443};
    constexpr std::size_t DEFAULT_IO_THREADS {2};
    constexpr std::size_t DEFAULT_WORKER_THREADS {4};
    // Transport hard cap. Kept above the auth middleware's body limit (AuthConfig::maxBodySize,
    // 10 MiB) so an oversized batch reaches the middleware and gets a clean 413 there, while this
    // still bounds memory as a backstop.
    constexpr std::size_t DEFAULT_MAX_BODY_SIZE {16U * 1024U * 1024U};
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

    // These paths are evaluated after remoted has entered its chroot.
    // Host paths: /var/ossec/etc/remoted-https/server.{crt,key}
    constexpr auto DEFAULT_CERTIFICATE_PATH {"/etc/remoted-https/server.crt"};
    constexpr auto DEFAULT_PRIVATE_KEY_PATH {"/etc/remoted-https/server.key"};

    // A positive caller value wins; otherwise the built-in default. remoted is expected to
    // always pass an already-validated value read from the `remoted.http_*` internal options.
    std::size_t resolveUnsigned(const int configValue, const std::size_t defaultValue)
    {
        return configValue > 0 ? static_cast<std::size_t>(configValue) : defaultValue;
    }
} // namespace

namespace remoted::http
{

    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config)
    {
        HttpServerConfig result;

        result.bindAddress = DEFAULT_BIND_ADDRESS;

        result.port = static_cast<std::uint16_t>(resolveUnsigned(config.port, DEFAULT_HTTPS_PORT));
        result.ioThreads = resolveUnsigned(config.io_threads, DEFAULT_IO_THREADS);
        result.workerThreads = resolveUnsigned(config.http_worker_threads, DEFAULT_WORKER_THREADS);
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

        result.certificatePath =
            config.certificate_path[0] != '\0' ? std::string {config.certificate_path} : DEFAULT_CERTIFICATE_PATH;

        result.privateKeyPath =
            config.private_key_path[0] != '\0' ? std::string {config.private_key_path} : DEFAULT_PRIVATE_KEY_PATH;

        return result;
    }

} // namespace remoted::http
