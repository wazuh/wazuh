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

#ifndef _KEY_VALUE_FILE_HPP
#define _KEY_VALUE_FILE_HPP

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include <base/logging.hpp>

namespace base::utils
{

auto constexpr KEY_VALUE_SEPARATOR {':'};

class KeyValueFile
{
private:
    std::string m_filePath;
    const char m_separator;

    /**
     * @brief Reads all the content from the file and returns it as a vector of chars.
     *
     * @return std::vector<char> File content.
     */
    std::vector<char> readFromFile()
    {
        std::ifstream file(m_filePath, std::ifstream::binary);
        if (!file.is_open())
        {
            throw std::runtime_error("Error opening key-value file due to: " + std::string(strerror(errno)));
        }

        std::vector<char> buffer(std::istreambuf_iterator<char>(file), {});
        file.close();

        return buffer;
    }

    /**
     * @brief Reads the buffer and parses it into a map of key-value pairs.
     *
     * @param buffer The file content.
     * @return std::map<std::string, std::vector<char>>  The key-value map.
     */
    std::map<std::string, std::vector<char>> parseLines(const std::vector<char>& buffer)
    {
        std::map<std::string, std::vector<char>> keyValueMap;

        size_t pos = 0;
        std::vector<char>::const_iterator it1;
        std::vector<char>::const_iterator it2;
        std::vector<char>::const_iterator currentBufferPos;
        size_t valueSize = 0;
        size_t lineSize = 0;

        while (pos < buffer.size())
        {
            // This iterator jumps to the next line
            currentBufferPos = buffer.begin() + pos;

            // Each line is composed by KEY:VALUE_SIZE:VALUE\n
            it1 = std::find(currentBufferPos, buffer.end(), m_separator);
            it2 = std::find(it1 + 1, buffer.end(), m_separator);

            if (it1 == buffer.end() || it2 == buffer.end())
            {
                throw std::runtime_error("Invalid key-value file format, missing separator");
            }

            std::string valueSizeStr(it1 + 1, it2);
            try
            {
                valueSize = std::stoul(valueSizeStr);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error("Invalid key-value file format, invalid value size");
            }

            // CHARACTERS_UNTIL_SECOND_SEPARATOR + SEPARATOR_SIZE + VALUE_SIZE
            lineSize = it2 - currentBufferPos + 1 + valueSize;
            keyValueMap[std::string(currentBufferPos, it1)] = std::vector<char>(it2 + 1, it2 + 1 + valueSize);
            // Move to the next line considering new line character
            pos += lineSize + 1;
        }

        return keyValueMap;
    }

public:
    KeyValueFile(std::string filePath, const char separator = KEY_VALUE_SEPARATOR)
        : m_filePath {filePath}
        , m_separator {separator}
    {
        // Create file and update permissions only if it does not exist
        if (!std::filesystem::exists(m_filePath))
        {
            std::ofstream file(m_filePath);
            if (!file.is_open())
            {
                throw std::runtime_error("Error creating key-value file due to: " + std::string(strerror(errno)));
            }
            file.close();
            std::filesystem::permissions(m_filePath,
                                         std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
                                             | std::filesystem::perms::group_read);
        }
    }

    /**
     * @brief Overloaded method to get the value of a key.
     *
     * @param key The key to search for.
     * @param value The value to be returned.
     * @return true If the key is found.
     * @return false If the key is not found.
     */
    bool get(const std::string& key, std::string& value)
    {
        std::vector<char> valueVector;
        if (get(key, valueVector))
        {
            value = std::string(valueVector.begin(), valueVector.end());
            return true;
        }
        return false;
    }

    /**
     * @brief Get the value of a key.
     *
     * @param key The key to search for.
     * @param value The value to be returned.
     * @return true If the key is found.
     * @return false If the key is not found.
     */
    bool get(const std::string& key, std::vector<char>& value)
    {
        auto keyValueMap = parseLines(readFromFile());

        if (keyValueMap.find(key) != keyValueMap.end())
        {
            LOG_DEBUG("Key '{}' found in file '{}'.", key, m_filePath);
            value = keyValueMap.at(key);
            return true;
        }

        LOG_DEBUG("Key '{}' not found in file '{}'.", key, m_filePath);
        return false;
    }

    /**
     * @brief Overloaded method to put a key-value pair in the file.
     *
     * @param key The key to be inserted or updated.
     * @param value The value to be inserted or updated.
     */
    void put(const std::string& key, const std::string& value)
    {
        put(key, std::vector<char>(value.begin(), value.end()));
    }

    /**
     * @brief Method to put a key-value pair in the file.
     *
     * @param key The key to be inserted or updated.
     * @param value The value to be inserted or updated.
     */
    void put(const std::string& key, const std::vector<char>& value)
    {
        if (key.empty() || value.empty())
        {
            throw std::runtime_error("Invalid key-value pair, key or value is empty.");
        }

        if (key.find(m_separator) != std::string::npos)
        {
            throw std::runtime_error("Invalid key-value pair, key contains separator.");
        }

        auto keyValueMap = parseLines(readFromFile());
        if (keyValueMap.find(key) != keyValueMap.end())
        {
            LOG_DEBUG("Key '{}' found in file '{}', will be replaced.", key, m_filePath);
        }
        else
        {
            LOG_DEBUG("Key '{}' added to file '{}'.", key, m_filePath);
        }
        keyValueMap[key] = value;

        std::ofstream outFile(m_filePath, std::ios_base::trunc | std::ios_base::binary);
        if (!outFile.is_open())
        {
            throw std::runtime_error("Error opening key-value file due to: " + std::string(strerror(errno)));
        }

        for (const auto& [mapKey, mapValue] : keyValueMap)
        {
            outFile << mapKey << m_separator << mapValue.size() << m_separator;
            outFile.write(mapValue.data(), mapValue.size());
            outFile.put('\n');
        }
        outFile.close();
    }
};
} // namespace base::utils

#endif
