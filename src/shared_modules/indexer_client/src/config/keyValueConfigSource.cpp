/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexer_client/keyValueConfigSource.hpp"

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
                // that is empty or starts with '#' or a space is a comment. A CRLF blank line is blank too.
                if (rawLine.empty() || rawLine.front() == '#' || rawLine.front() == ' ' || rawLine == "\r")
                {
                    continue;
                }
                const auto line = trim(rawLine);

                const auto equals = line.find('=');
                if (equals == std::string_view::npos)
                {
                    return Outcome<KeyValueConfigSource>::failure(
                        Cause::InvalidConfig, "line " + std::to_string(lineNumber) + ": expected 'key=value'");
                }
                const auto key = trim(line.substr(0, equals));
                if (key.empty())
                {
                    return Outcome<KeyValueConfigSource>::failure(Cause::InvalidConfig,
                                                                  "line " + std::to_string(lineNumber) + ": empty key");
                }
                // A repeated key keeps the FIRST value, as wazuh's C internal-options reader does (it returns on the
                // first matching line): a later duplicate is never read, so it is neither applied nor validated.
                if (source.m_values.count(key) != 0)
                {
                    continue;
                }
                const auto value = trim(line.substr(equals + 1));
                if (value.empty())
                {
                    // The C reader refuses a key written with no value (merror_exit): an unfinished edit, not unset.
                    return Outcome<KeyValueConfigSource>::failure(Cause::InvalidConfig,
                                                                  "line " + std::to_string(lineNumber) + ": key '" +
                                                                      std::string {key} + "' has an empty value");
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
        for (auto it = m_values.lower_bound(prefix); it != m_values.end(); ++it)
        {
            if (it->first.compare(0, prefix.size(), prefix) != 0)
            {
                break;
            }
            keys.push_back(it->first);
        }
        return keys;
    }

    std::string KeyValueConfigSource::indexerSectionJson() const
    {
        return m_indexerSectionJson;
    }
} // namespace indexer_client
