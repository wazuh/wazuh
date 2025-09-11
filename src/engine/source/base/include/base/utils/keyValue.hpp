/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 3, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _KEY_VALUE_HPP
#define _KEY_VALUE_HPP

#include <map>
#include <string>

#include <base/logging.hpp>
#include <base/utils/stringUtils.hpp>

namespace base::utils
{

auto constexpr KEY_VALUE_SEPARATOR {':'};
auto constexpr KEY_VALUE_NEWLINE {'\n'};

class KeyValue
{
private:
    const char m_separator;
    const char m_newLine;
    std::map<std::string, std::string, std::less<>> m_keyValueMap;

    /**
     * @brief Reads the buffer and parses it into a map of key-value pairs.
     *
     * @param buffer The key-value buffer content.
     */
    void parseLines(const std::string& buffer)
    {
        auto lines = base::utils::string::split(buffer, m_newLine);
        for (const auto& line : lines)
        {
            auto separatorPos = line.find(m_separator);
            if (separatorPos == std::string::npos)
            {
                throw std::runtime_error("Invalid key-value format, missing separator");
            }

            m_keyValueMap[line.substr(0, separatorPos)] = line.substr(separatorPos + 1);
        }
    }

public:
    explicit KeyValue(const std::string& keyValueBuffer = "",
                      const char separator = KEY_VALUE_SEPARATOR,
                      const char newLine = KEY_VALUE_NEWLINE)
        : m_separator {separator}
        , m_newLine {newLine}
    {

        parseLines(keyValueBuffer);
    }

    /**
     * @brief Get the value of a key.
     *
     * @param key The key to search for.
     * @param value The value to be returned.
     * @return true If the key is found.
     * @return false If the key is not found.
     */
    bool get(const std::string& key, std::string& value)
    {
        if (m_keyValueMap.find(key) != m_keyValueMap.end())
        {
            LOG_DEBUG("Key '{}' found.", key);
            value = m_keyValueMap.at(key);
            return true;
        }

        LOG_DEBUG("Key '{}' not found.", key);
        return false;
    }

    /**
     * @brief Method to upsert a key-value pair.
     *
     * @param key The key to be inserted or updated.
     * @param value The value to be inserted or updated.
     */
    void put(const std::string& key, std::string_view value)
    {
        if (key.empty() || value.empty())
        {
            throw std::runtime_error("Invalid key-value pair, key or value is empty.");
        }

        if (key.find(m_separator) != std::string::npos || key.find(m_newLine) != std::string::npos
            || value.find(m_separator) != std::string::npos || value.find(m_newLine) != std::string::npos)
        {
            throw std::runtime_error(std::string("Invalid key-value pair, can't contain separator (") + m_separator
                                     + ") or newline.");
        }

        if (m_keyValueMap.find(key) != m_keyValueMap.end())
        {
            LOG_DEBUG("Key '{}' exists, will be replaced.", key);
        }
        else
        {
            LOG_DEBUG("Key '{}' not exists, added.", key);
        }
        m_keyValueMap[key] = value;
    }

    /**
     * @brief Method to dump the key-value map into a buffer.
     *
     * @return std::string The buffer with the key-value pairs.
     */
    std::string dumpMap() const
    {
        std::string buffer;
        for (const auto& [mapKey, mapValue] : m_keyValueMap)
        {
            buffer.insert(buffer.end(), mapKey.begin(), mapKey.end());
            buffer.push_back(m_separator);
            buffer.insert(buffer.end(), mapValue.begin(), mapValue.end());
            buffer.push_back(m_newLine);
        }
        return buffer;
    }
};
} // namespace base::utils

#endif
