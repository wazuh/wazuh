/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string>
#include "json.hpp"

/// Type-checked accessors for fields of browser metadata JSON files.
namespace JsonFieldHelpers
{
    /// @brief Returns the string stored under key, or an empty string if it is missing or has another type.
    inline std::string getStringField(const nlohmann::json& object, const char* key)
    {
        const auto it = object.find(key);
        return (it != object.end() && it->is_string()) ? it->get<std::string>() : "";
    }

    /// @brief Returns the boolean stored under key, or defaultValue if it is missing or has another type.
    inline bool getBoolField(const nlohmann::json& object, const char* key, bool defaultValue)
    {
        const auto it = object.find(key);
        return (it != object.end() && it->is_boolean()) ? it->get<bool>() : defaultValue;
    }

    /// @brief Returns the object stored under key, or an empty object if it is missing or has another type.
    inline const nlohmann::json& getObjectField(const nlohmann::json& object, const char* key)
    {
        static const nlohmann::json EMPTY_OBJECT = nlohmann::json::object();
        const auto it = object.find(key);
        return (it != object.end() && it->is_object()) ? *it : EMPTY_OBJECT;
    }
} // namespace JsonFieldHelpers
