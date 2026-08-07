/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "udsHttpServerConfig.hpp"

#include "proc.hpp"

#include <limits>
#include <string>

namespace
{
    // Relative on purpose: modulesd chdir()s to the install dir and remoted chroot()s into it, so a
    // relative path is the only form both peers resolve to the same file. The name is the SERVICE's,
    // not this transitional module's, so remoted's downstream configuration is written once and does
    // not have to change again when this module replaces inventory_sync.
    constexpr auto DEFAULT_SOCKET_PATH {"queue/sockets/inventory-sync.sock"};

    // bind() applies the umask, so the mode is always set explicitly afterwards. 0660 is what the
    // manager's other Unix sockets use, and it is what lets remoted -- which runs under the wazuh
    // group -- connect to a socket modulesd created.
    constexpr std::uint32_t DEFAULT_SOCKET_MODE {0660};

    constexpr std::size_t DEFAULT_CONCURRENT_ACCEPTS {2};
    constexpr std::size_t DEFAULT_BUFFER_SIZE {8192};

    // Request body cap: NO OWN LIMIT by default. A whole sync session travels as one request, so
    // an arbitrary per-request cap would be an arbitrary session-size cap; what bounds memory is
    // the in-flight byte budget, which start() feeds to the parser so "declares more than the
    // whole budget" is refused with 413 at headers-complete.
    constexpr std::size_t DEFAULT_MAX_BODY_SIZE {invsync::http::UdsHttpServerConfig::UNLIMITED_BODY_SIZE};

    // llhttp enforces none of these itself, so they are applied by hand in the parser.
    constexpr std::size_t DEFAULT_MAX_URL_SIZE {2048};
    constexpr std::size_t DEFAULT_MAX_HEADER_NAME_SIZE {256};
    constexpr std::size_t DEFAULT_MAX_HEADER_VALUE_SIZE {8192};
    /*
     * 32, and NOT configurable (see inventory_sync_server.h): it is a term of the memory ceiling the
     * in-flight byte budget charges for -- the worst-case head is count * (nameSize + valueSize) --
     * and still far more header lines than the peer sends (five).
     */
    constexpr std::size_t DEFAULT_MAX_HEADER_COUNT {32};

    constexpr std::size_t DEFAULT_HEADER_TIMEOUT_SEC {10};
    constexpr std::size_t DEFAULT_BODY_TIMEOUT_SEC {30};

    // Leak backstop, not a deadline: the peer sets its own, shorter, per-target response deadline
    // and gives up first. Five minutes is chosen to be comfortably longer than any legitimate
    // indexer round-trip, because its only job is to stop a lost responder from pinning an fd
    // forever.
    constexpr std::size_t DEFAULT_RESPONSE_TIMEOUT_SEC {300};

    constexpr std::size_t DEFAULT_WRITE_TIMEOUT_SEC {10};

    // Kept short deliberately: modulesd calls every module's stop() sequentially before joining
    // them under one shared 30 s budget, so a long drain here delays every other module's teardown.
    constexpr std::size_t DEFAULT_DRAIN_TIMEOUT_SEC {2};

    // One deferred response costs one fd, so this is the knob that bounds fd usage. Sized well
    // above the few hundred concurrent deferrals the ingestion path is expected to hold, and well
    // under a default RLIMIT_NOFILE.
    constexpr std::size_t DEFAULT_MAX_CONNECTIONS {1024};

    // Global cap on in-flight request payload bytes. Reserved from the declared Content-Length
    // before the body is read, so it bounds the read-phase peak as well as resident payloads.
    constexpr std::size_t DEFAULT_MAX_INFLIGHT_BYTES {256U * 1024U * 1024U};

    // A positive caller value wins; otherwise the built-in default. modulesd is expected to always
    // pass an already-validated value read from the `wazuh_modules.inventory_sync_server_*`
    // internal options, whose own fallback is 0 precisely so the default resolves here.
    std::size_t resolveUnsigned(const int configValue, const std::size_t defaultValue)
    {
        return configValue > 0 ? static_cast<std::size_t>(configValue) : defaultValue;
    }

    // Thread-count fields: a positive caller value wins; otherwise cpp_get_nproc(), so the count
    // tracks the host/cgroup's available CPUs instead of a fixed constant. No multiplier here --
    // unlike remoted's handler pool, these are reactor threads that never block, so oversubscribing
    // them buys nothing.
    std::size_t resolveThreadCount(const int configValue)
    {
        if (configValue > 0)
        {
            return static_cast<std::size_t>(configValue);
        }
        return static_cast<std::size_t>(cpp_get_nproc());
    }
} // namespace

namespace invsync::http
{

    UdsHttpServerConfig buildServerConfig(const inventory_sync_server_config_t& config)
    {
        UdsHttpServerConfig result;

        result.socketPath = config.socket_path[0] != '\0' ? std::string {config.socket_path} : DEFAULT_SOCKET_PATH;
        result.socketMode =
            config.socket_mode > 0 ? static_cast<std::uint32_t>(config.socket_mode) : DEFAULT_SOCKET_MODE;

        result.ioThreads = resolveThreadCount(config.io_threads);
        result.concurrentAccepts = resolveUnsigned(config.concurrent_accepts, DEFAULT_CONCURRENT_ACCEPTS);
        result.bufferSize = resolveUnsigned(config.buffer_size, DEFAULT_BUFFER_SIZE);

        result.maxBodySize = resolveUnsigned(config.max_body_size, DEFAULT_MAX_BODY_SIZE);
        result.maxUrlSize = resolveUnsigned(config.max_url_size, DEFAULT_MAX_URL_SIZE);
        result.maxHeaderNameSize = resolveUnsigned(config.max_header_name_size, DEFAULT_MAX_HEADER_NAME_SIZE);
        result.maxHeaderValueSize = resolveUnsigned(config.max_header_value_size, DEFAULT_MAX_HEADER_VALUE_SIZE);
        result.maxHeaderCount = resolveUnsigned(config.max_header_count, DEFAULT_MAX_HEADER_COUNT);

        result.headerTimeoutSec = resolveUnsigned(config.header_timeout, DEFAULT_HEADER_TIMEOUT_SEC);
        result.bodyTimeoutSec = resolveUnsigned(config.body_timeout, DEFAULT_BODY_TIMEOUT_SEC);
        result.responseTimeoutSec = resolveUnsigned(config.response_timeout, DEFAULT_RESPONSE_TIMEOUT_SEC);
        result.writeTimeoutSec = resolveUnsigned(config.write_timeout, DEFAULT_WRITE_TIMEOUT_SEC);
        result.drainTimeoutSec = resolveUnsigned(config.drain_timeout, DEFAULT_DRAIN_TIMEOUT_SEC);

        result.maxConnections = resolveUnsigned(config.max_parallel_connections, DEFAULT_MAX_CONNECTIONS);

        // long long rather than int, so it cannot be resolved with resolveUnsigned(). The transport
        // clamps this up to at least one max-size body at start(), so a too-small value cannot
        // reject everything.
        /*
         * Three-way, and 0 still means "no opinion" so a zero-filled struct keeps yielding every
         * default -- the invariant the whole C-ABI is written around.
         *
         * The interface documents "disable the byte limit" and InFlightBudget implements it, but that
         * branch was unreachable from configuration: modulesd's absent-value fallback was 0, so an
         * operator writing 0 was indistinguishable from not setting the option at all. The distinction
         * is made in the shim now, which translates an explicit 0 into a NEGATIVE here:
         *   > 0  -> the caller's value
         *   == 0 -> the module default (an absent option, or a zero-filled struct)
         *   < 0  -> effectively unlimited. Expressed as the largest representable budget rather than
         *           InFlightBudget's own 0-means-disabled mode, so the accounting and the observability
         *           counters keep working exactly as they do with a finite budget.
         */
        if (config.max_inflight_bytes < 0)
        {
            result.maxInFlightBytes = std::numeric_limits<std::size_t>::max() - 1;
        }
        else if (config.max_inflight_bytes == 0)
        {
            result.maxInFlightBytes = DEFAULT_MAX_INFLIGHT_BYTES;
        }
        else
        {
            result.maxInFlightBytes = static_cast<std::size_t>(config.max_inflight_bytes);
        }

        return result;
    }

} // namespace invsync::http
