/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "downstreamConfig.hpp"

#include "proc.hpp"

namespace
{
    constexpr int DEFAULT_CONNECT_TIMEOUT_SEC {2};
    constexpr int DEFAULT_WRITE_TIMEOUT_SEC {5};
    constexpr int DEFAULT_RESPONSE_TIMEOUT_SEC {5};
    // Not 5: /stateful's downstream (the inventory sync server) validates, indexes and flushes the
    // whole session inside the request. 20 s keeps the default budget (2+5+20) inside the default
    // http_request_timeout (30 s) so a stock install starts warning-free; calibration with real
    // session sizes is F9's job (inventory_sync_server_docs 13 §3.3).
    constexpr int DEFAULT_STATEFUL_RESPONSE_TIMEOUT_SEC {20};
    // 11 MiB, not 10: strictly larger than the agent-request cap because /stats and /config echo
    // the agent's document back enriched (see DownstreamConfig::maxResponseBodySize).
    constexpr std::size_t DEFAULT_MAX_RESPONSE_BODY_SIZE {11U * 1024U * 1024U};

    // A positive caller value wins; otherwise the built-in default (seconds).
    int resolveSeconds(const int configValue, const int defaultValue)
    {
        return configValue > 0 ? configValue : defaultValue;
    }

    // A positive caller value wins; otherwise the built-in default (bytes).
    std::size_t resolveBytes(const long long configValue, const std::size_t defaultValue)
    {
        return configValue > 0 ? static_cast<std::size_t>(configValue) : defaultValue;
    }

    // Thread-count fields: a positive caller value wins; otherwise cpp_get_nproc(), so the pool
    // size tracks the host/cgroup's available CPUs instead of a fixed constant.
    std::size_t resolveThreadCount(const int configValue)
    {
        return configValue > 0 ? static_cast<std::size_t>(configValue) : static_cast<std::size_t>(cpp_get_nproc());
    }
} // namespace

namespace remoted::downstream
{

    DownstreamConfig buildDownstreamConfig(const remoted_module_config_t& config)
    {
        DownstreamConfig result; // keeps eventsSocketPath's built-in default

        result.connectTimeoutMs = resolveSeconds(config.downstream_connect_timeout, DEFAULT_CONNECT_TIMEOUT_SEC) * 1000;
        result.writeTimeoutMs = resolveSeconds(config.downstream_write_timeout, DEFAULT_WRITE_TIMEOUT_SEC) * 1000;
        result.responseTimeoutMs =
            resolveSeconds(config.downstream_response_timeout, DEFAULT_RESPONSE_TIMEOUT_SEC) * 1000;
        result.statefulResponseTimeoutMs =
            resolveSeconds(config.downstream_stateful_response_timeout, DEFAULT_STATEFUL_RESPONSE_TIMEOUT_SEC) * 1000;
        result.ioThreads = resolveThreadCount(config.downstream_io_threads);
        result.postProcessThreads = resolveThreadCount(config.downstream_post_process_threads);
        result.maxResponseBodySize =
            resolveBytes(config.downstream_max_response_body_size, DEFAULT_MAX_RESPONSE_BODY_SIZE);

        return result;
    }

} // namespace remoted::downstream
