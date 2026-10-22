/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_METADATA_COLLECTOR_HPP
#define _HC_METADATA_COLLECTOR_HPP

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

/// Room for the agent metadata JSON at its worst case: 128 groups of 255 bytes
/// plus the host block is about 36 KiB. The C callback writes with snprintf, so
/// a smaller buffer cuts the JSON and the consumer drops it as unparseable.
constexpr std::size_t AGENT_METADATA_JSON_MAX_BYTES = 64 * 1024;

/// Notify's host block carries no groups, so it fits the historical 4 KiB.
constexpr std::size_t HOST_METADATA_JSON_MAX_BYTES = 4096;

/**
 * @brief Wraps a `void(char*, size_t, void*)`-shaped C metadata callback as a
 *        `std::function<std::string()>` pull-source with a `cap`-byte output
 *        buffer. Returns "" when fn is null, so an unset callback degrades to
 *        "no extra metadata" rather than a crash.
 *
 * The buffer lives on the heap: the pull-sources run on the module's worker
 * threads, and 64 KiB is too much for their stacks. It is not zero-filled:
 * the real JSON is a few hundred bytes, and only the two ends need a NUL.
 */
inline std::function<std::string()> makeMetadataCollector(void (*fn)(char*, size_t, void*),
                                                          void* userData,
                                                          std::size_t cap)
{
    return [fn, userData, cap]() -> std::string
    {
        if (fn == nullptr || cap == 0)
        {
            return {};
        }

        std::unique_ptr<char[]> buffer {new char[cap]};
        buffer[0] = '\0';
        buffer[cap - 1] = '\0';
        fn(buffer.get(), cap, userData);
        buffer[cap - 1] = '\0';
        return std::string(buffer.get());
    };
}

#endif // _HC_METADATA_COLLECTOR_HPP
