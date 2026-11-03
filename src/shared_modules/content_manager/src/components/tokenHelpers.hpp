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

#ifndef _TOKEN_HELPERS_HPP
#define _TOKEN_HELPERS_HPP

#include <cstdint>
#include <json.hpp>
#include <string>

/// Reading tokens out of documents, shared by the detectors and the paginator.
namespace tokenHelpers
{
    /**
     * @brief Resolve a JSON pointer without throwing.
     *
     * @param document Document to look into.
     * @param pointer JSON pointer, e.g. `/_source/offset`.
     * @return The value, or null when @p pointer is malformed or absent.
     */
    inline const nlohmann::json* resolve(const nlohmann::json& document, const std::string& pointer)
    {
        if (pointer.empty() || pointer.front() != '/')
        {
            return nullptr;
        }
        try
        {
            const nlohmann::json::json_pointer jsonPointer {pointer};
            return document.contains(jsonPointer) ? &document.at(jsonPointer) : nullptr;
        }
        catch (const std::exception&)
        {
            return nullptr;
        }
    }

    /**
     * @brief Parse a token that is a well-formed unsigned integer.
     *
     * @param token Token text.
     * @param[out] value Parsed value, untouched on failure.
     * @return True on success.
     */
    inline bool parseUnsigned(const std::string& token, std::uint64_t& value)
    {
        if (token.empty() || token.find_first_not_of("0123456789") != std::string::npos)
        {
            return false;
        }
        try
        {
            value = std::stoull(token);
        }
        catch (const std::exception&)
        {
            return false;
        }
        return true;
    }
} // namespace tokenHelpers

#endif // _TOKEN_HELPERS_HPP
