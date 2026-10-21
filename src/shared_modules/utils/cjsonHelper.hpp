/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CJSON_HELPER_HPP
#define _CJSON_HELPER_HPP

#include <cmath>
#include "cJSON.h"
#include "json.hpp"

namespace Utils
{
    /**
     * @brief Builds a cJSON copy of a nlohmann::json value.
     *
     * Same result as cJSON_Parse(value.dump()), but strings are copied as raw bytes, so a string
     * that is not valid UTF-8 (e.g. a file name) does not throw.
     *
     * @param value Value to copy.
     * @return New cJSON tree owned by the caller, or nullptr if an allocation fails.
     */
    static inline cJSON* toCJSON(const nlohmann::json& value)
    {
        switch (value.type())
        {
            case nlohmann::json::value_t::object:
            case nlohmann::json::value_t::array:
                {
                    const auto isObject {value.is_object()};
                    auto result {isObject ? cJSON_CreateObject() : cJSON_CreateArray()};

                    for (auto it = value.begin(); result && it != value.end(); ++it)
                    {
                        auto item {toCJSON(*it)};

                        if (!item || !(isObject ? cJSON_AddItemToObject(result, it.key().c_str(), item)
                                       : cJSON_AddItemToArray(result, item)))
                        {
                            cJSON_Delete(item);
                            cJSON_Delete(result);
                            result = nullptr;
                        }
                    }

                    return result;
                }

            case nlohmann::json::value_t::string:
                return cJSON_CreateString(value.get_ref<const std::string&>().c_str());

            case nlohmann::json::value_t::boolean:
                return cJSON_CreateBool(value.get<bool>());

            case nlohmann::json::value_t::number_integer:
                return cJSON_CreateNumber(static_cast<double>(value.get<int64_t>()));

            case nlohmann::json::value_t::number_unsigned:
                return cJSON_CreateNumber(static_cast<double>(value.get<uint64_t>()));

            case nlohmann::json::value_t::number_float:
                {
                    // dump() writes NaN and infinity as null.
                    const auto number {value.get<double>()};
                    return std::isfinite(number) ? cJSON_CreateNumber(number) : cJSON_CreateNull();
                }

            default:
                return cJSON_CreateNull();
        }
    }
} // namespace Utils

#endif // _CJSON_HELPER_HPP
