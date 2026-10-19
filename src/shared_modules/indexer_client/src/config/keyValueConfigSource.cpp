/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "indexer_client/keyValueConfigSource.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace indexer_client
{
    namespace
    {
        bool isBlank(char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v';
        }

        std::string_view trim(std::string_view text)
        {
            while (!text.empty() && isBlank(text.front()))
            {
                text.remove_prefix(1);
            }
            while (!text.empty() && isBlank(text.back()))
            {
                text.remove_suffix(1);
            }
            return text;
        }
    } // namespace

    Outcome<KeyValueConfigSource> KeyValueConfigSource::parse(std::string_view text, std::string indexerSectionJson)
    {
        try
        {
            KeyValueConfigSource source;
            std::size_t lineNumber = 0;
            while (!text.empty())
            {
                ++lineNumber;
                const auto end = text.find('\n');
                const std::string_view rawLine = text.substr(0, end);
                text.remove_prefix(end == std::string_view::npos ? text.size() : end + 1);

                // Same rule as wazuh's C internal-options reader (`_read_file`, src/shared/src/validate_op.c): a line
                // that is empty or starts with '#' or a space is a comment. A line that starts with a tab is a comment
                // too: the C reader never matches it against any key. A CRLF blank line is blank.
                if (rawLine.empty() || rawLine.front() == '#' || rawLine.front() == ' ' || rawLine.front() == '\t' ||
                    rawLine == "\r")
                {
                    continue;
                }
                const auto line = trim(rawLine);
                const auto where = "line " + std::to_string(lineNumber) + ": ";

                // The C reader judges a line only against the key it is asked for: a line without '=' or with an
                // empty value is a problem of THAT key, not of the file. So it is recorded here and only
                // RuntimeConfig::from() decides, for the keys under its process prefix, that it is fatal.
                const auto equals = line.find('=');
                const auto key = equals == std::string_view::npos ? line : trim(line.substr(0, equals));
                if (key.empty())
                {
                    continue; // No key can ever match it; the C reader logs and skips it.
                }
                // A repeated key keeps the FIRST occurrence, as wazuh's C internal-options reader does (it returns on
                // the first matching line): a later duplicate is never read, so it is neither applied nor validated.
                // This holds for recorded problems too.
                if (source.m_values.count(key) != 0 || source.m_problems.count(key) != 0)
                {
                    continue;
                }
                if (equals == std::string_view::npos)
                {
                    source.m_problems.emplace(
                        std::string {key}, where + "'" + std::string {key} + "' is malformed (expected 'key=value')");
                    continue;
                }
                const auto value = trim(line.substr(equals + 1));
                if (value.empty())
                {
                    // The C reader refuses a key written with no value (merror_exit): an unfinished edit, not unset.
                    source.m_problems.emplace(std::string {key},
                                              where + "key '" + std::string {key} + "' has an empty value");
                    continue;
                }
                source.m_values.emplace(std::string {key}, std::string {value});
            }
            source.m_indexerSectionJson = std::move(indexerSectionJson);
            return Outcome<KeyValueConfigSource>::success(std::move(source));
        }
        catch (const std::exception& e)
        {
            return Outcome<KeyValueConfigSource>::failure(Cause::InvalidConfig,
                                                          std::string {"configuration: "} + e.what());
        }
    }

    std::optional<std::string> KeyValueConfigSource::raw(std::string_view key) const
    {
        const auto it = m_values.find(key);
        if (it == m_values.end())
        {
            return std::nullopt;
        }
        return it->second;
    }

    std::vector<std::string> KeyValueConfigSource::keysWithPrefix(std::string_view prefix) const
    {
        std::vector<std::string> keys;
        for (const auto* map : {&m_values, &m_problems})
        {
            for (auto it = map->lower_bound(prefix); it != map->end(); ++it)
            {
                if (it->first.compare(0, prefix.size(), prefix) != 0)
                {
                    break;
                }
                keys.push_back(it->first);
            }
        }
        std::sort(keys.begin(), keys.end());
        return keys;
    }

    std::optional<std::string> KeyValueConfigSource::problem(std::string_view key) const
    {
        const auto it = m_problems.find(key);
        if (it == m_problems.end())
        {
            return std::nullopt;
        }
        return it->second;
    }

    std::string KeyValueConfigSource::indexerSectionJson() const
    {
        return m_indexerSectionJson;
    }
} // namespace indexer_client
