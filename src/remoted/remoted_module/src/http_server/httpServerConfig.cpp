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

#include <charconv>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>

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

// These paths are evaluated after remoted has entered its chroot.
// Host paths: /var/ossec/etc/remoted-https/server.{crt,key}
constexpr auto DEFAULT_CERTIFICATE_PATH {"/etc/remoted-https/server.crt"};
constexpr auto DEFAULT_PRIVATE_KEY_PATH {"/etc/remoted-https/server.key"};

std::string readStringEnvironment(const char* name, std::string defaultValue)
{
    const auto* value = std::getenv(name);

    if (value == nullptr || *value == '\0')
    {
        return defaultValue;
    }

    return value;
}

std::size_t readUnsignedEnvironment(const char* name,
                                    const std::size_t defaultValue,
                                    const std::size_t minimum,
                                    const std::size_t maximum)
{
    const auto* rawValue = std::getenv(name);

    if (rawValue == nullptr || *rawValue == '\0')
    {
        return defaultValue;
    }

    const std::string_view value {rawValue};

    std::size_t parsedValue {};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsedValue);

    if (result.ec != std::errc {} || result.ptr != value.data() + value.size() || parsedValue < minimum ||
        parsedValue > maximum)
    {
        throw std::invalid_argument(std::string {name} + " must be an integer between " + std::to_string(minimum) +
                                    " and " + std::to_string(maximum));
    }

    return parsedValue;
}

// Positive C-ABI int wins; otherwise fall back to env (which itself defaults).
std::size_t resolveUnsigned(const int configValue,
                            const char* envName,
                            const std::size_t defaultValue,
                            const std::size_t minimum,
                            const std::size_t maximum)
{
    if (configValue > 0)
    {
        return static_cast<std::size_t>(configValue);
    }

    return readUnsignedEnvironment(envName, defaultValue, minimum, maximum);
}
} // namespace

namespace remoted::http
{

HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config)
{
    HttpServerConfig result;

    result.bindAddress = readStringEnvironment("WAZUH_REMOTED_HTTPS_ADDRESS", DEFAULT_BIND_ADDRESS);

    result.port = static_cast<std::uint16_t>(
        resolveUnsigned(config.port, "WAZUH_REMOTED_HTTPS_PORT", DEFAULT_HTTPS_PORT, 1, 65535));

    result.ioThreads =
        resolveUnsigned(config.io_threads, "WAZUH_REMOTED_HTTPS_IO_THREADS", DEFAULT_IO_THREADS, 1, 64);

    // Worker pool: dedicated field first, then the module's generic worker_threads, then env/default.
    const int workerHint = config.http_worker_threads > 0 ? config.http_worker_threads : config.worker_threads;
    result.workerThreads =
        resolveUnsigned(workerHint, "WAZUH_REMOTED_HTTPS_WORKER_THREADS", DEFAULT_WORKER_THREADS, 1, 256);

    result.maxBodySize = readUnsignedEnvironment(
        "WAZUH_REMOTED_HTTPS_MAX_BODY_SIZE", DEFAULT_MAX_BODY_SIZE, 1, 64U * 1024U * 1024U);

    result.certificatePath = config.certificate_path[0] != '\0'
                                 ? std::string {config.certificate_path}
                                 : readStringEnvironment("WAZUH_REMOTED_HTTPS_CERTIFICATE", DEFAULT_CERTIFICATE_PATH);

    result.privateKeyPath = config.private_key_path[0] != '\0'
                                ? std::string {config.private_key_path}
                                : readStringEnvironment("WAZUH_REMOTED_HTTPS_PRIVATE_KEY", DEFAULT_PRIVATE_KEY_PATH);

    return result;
}

} // namespace remoted::http
