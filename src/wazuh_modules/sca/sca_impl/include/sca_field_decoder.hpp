/*
 * Wazuh SCA
 * Copyright (C) 2015, Wazuh Inc.
 * September 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <json.hpp>
#include <sstream>
#include <string>

#include "stringHelper.h"

namespace sca
{
    /// @brief Splits a comma-separated string into a JSON array.
    /// @param input A string with elements separated by commas.
    /// @return A JSON array of trimmed, non-empty elements.
    inline nlohmann::json CommaSeparatedToJsonArray(const std::string& input)
    {
        nlohmann::json result = nlohmann::json::array();
        std::istringstream stream(input);
        std::string token;

        while (std::getline(stream, token, ','))
        {
            // Trim all whitespace characters including \n, \r, \t, \v, \f, and spaces
            token = Utils::trim(token, " \t\n\r\v\f");

            if (!token.empty())
            {
                result.push_back(token);
            }
        }

        return result;
    }

    /// @brief Decodes a database TEXT column that holds a list of strings.
    ///
    /// SCAPolicyLoader::NormalizeData writes the "refs" and "rules" columns through
    /// nlohmann::json::dump(), so each column holds a serialised JSON array. Parsing it back is
    /// what keeps every element a plain value: splitting the dump on commas instead would leave
    /// the array's own brackets and quotes glued to the first and last elements, keep every
    /// backslash escaped, and cut any element that legitimately contains a comma.
    ///
    /// Values that are not a serialised array are still accepted, so rows written before the
    /// column was dumped, and policies whose field is a scalar rather than a list, keep decoding
    /// as a comma-separated list.
    ///
    /// @param input The stored column value.
    /// @return A JSON array of elements.
    inline nlohmann::json DecodeStringListField(const std::string& input)
    {
        try
        {
            const auto parsed = nlohmann::json::parse(input);

            if (parsed.is_array())
            {
                nlohmann::json result = nlohmann::json::array();

                for (const auto& element : parsed)
                {
                    result.push_back(element.is_string() ? element.get<std::string>() : element.dump());
                }

                return result;
            }

            // A scalar field round-trips as a JSON string; treat its content as a list.
            if (parsed.is_string())
            {
                return CommaSeparatedToJsonArray(parsed.get<std::string>());
            }
        }
        catch (const nlohmann::json::parse_error&)
        {
            // Not a serialised JSON value: fall through to the legacy representation.
        }

        return CommaSeparatedToJsonArray(input);
    }
} // namespace sca
