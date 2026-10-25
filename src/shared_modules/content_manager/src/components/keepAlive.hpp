/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CONTENT_MANAGER_KEEP_ALIVE_HPP
#define _CONTENT_MANAGER_KEEP_ALIVE_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace content_manager::detail
{
    /**
     * @brief Parse a PIT keep-alive the way OpenSearch accepts it (D84, I189): `<n><unit>` with unit one of
     *        `nanos|micros|ms|s|m|h|d`, lower case, an integer of at least 1 ms, surrounding spaces ignored.
     *        Verified against OpenSearch: `5m`, `300s`, ` 5m` accepted; `5M`, `1.5m`, `5` rejected.
     *
     * @throws std::invalid_argument naming the value and why it is invalid.
     */
    inline std::chrono::milliseconds parseKeepAlive(std::string_view keepAlive)
    {
        const auto invalid = [&keepAlive](const char* why)
        {
            return std::invalid_argument {"Invalid PIT keepAlive '" + std::string {keepAlive} + "': " + why};
        };

        // Surrounding spaces are ignored; the error still names the value as given.
        constexpr std::string_view SPACES {" \t\r\n"};
        const auto first = keepAlive.find_first_not_of(SPACES);
        if (first == std::string_view::npos)
        {
            throw invalid("expected <n>(nanos|micros|ms|s|m|h|d)");
        }
        const auto text = keepAlive.substr(first, keepAlive.find_last_not_of(SPACES) - first + 1);

        std::size_t digits {0};
        std::uint64_t value {0};
        constexpr auto MAX_VALUE =
            static_cast<std::uint64_t>(std::numeric_limits<std::chrono::milliseconds::rep>::max());
        while (digits < text.size() && text[digits] >= '0' && text[digits] <= '9')
        {
            const auto digit = static_cast<std::uint64_t>(text[digits] - '0');
            if (value > (MAX_VALUE - digit) / 10)
            {
                throw invalid("out of range");
            }
            value = value * 10 + digit;
            ++digits;
        }
        if (digits == 0)
        {
            throw invalid("expected <n>(nanos|micros|ms|s|m|h|d)");
        }

        // Sub-millisecond units divide (and truncate); the others multiply.
        const auto unit = text.substr(digits);
        std::uint64_t divisor {1};
        std::uint64_t multiplier {1};
        if (unit == "nanos")
        {
            divisor = 1000000;
        }
        else if (unit == "micros")
        {
            divisor = 1000;
        }
        else if (unit == "ms")
        {
        }
        else if (unit == "s")
        {
            multiplier = 1000;
        }
        else if (unit == "m")
        {
            multiplier = 60ULL * 1000;
        }
        else if (unit == "h")
        {
            multiplier = 60ULL * 60 * 1000;
        }
        else if (unit == "d")
        {
            multiplier = 24ULL * 60 * 60 * 1000;
        }
        else
        {
            throw invalid("expected <n>(nanos|micros|ms|s|m|h|d)");
        }

        if (value > MAX_VALUE / multiplier)
        {
            throw invalid("out of range");
        }
        const auto millis = value * multiplier / divisor;
        if (millis < 1)
        {
            throw invalid("must be at least 1ms");
        }
        return std::chrono::milliseconds {static_cast<std::chrono::milliseconds::rep>(millis)};
    }
} // namespace content_manager::detail

#endif // _CONTENT_MANAGER_KEEP_ALIVE_HPP
