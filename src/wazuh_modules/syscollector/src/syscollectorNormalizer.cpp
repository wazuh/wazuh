/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 12, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <iostream>
#include <fstream>
#include <regex>
#include <syscollectorNormalizer.h>

SysNormalizer::SysNormalizer(const std::string& configFile,
                             const std::string& target)
: m_typeExclusions{getTypeExclusions(configFile, target)}
, m_typeDictionary{getTypeDictionary(configFile, target)}
{
}

nlohmann::json SysNormalizer::removeExcluded(const std::string& type,
                                             const nlohmann::json& data) const
{
    nlohmann::json ret(data);
    const auto exclusionsIt{m_typeExclusions.find(type)};
    if (exclusionsIt != m_typeExclusions.cend())
    {
        for (const auto& exclusionItem : exclusionsIt->second)
        {
            std::regex pattern{exclusionItem.pattern};
            if (ret.is_array())
            {
                for (auto item{ret.begin()}; item != ret.end(); ++item)
                {
                    const auto fieldIt{item->find(exclusionItem.fieldName)};
                    if (fieldIt != item->end() && std::regex_match(fieldIt->get_ref<const std::string&>(), pattern))
                    {
                        ret.erase(item);
                    }
                }
            }
            else
            {
                const auto fieldIt{ret.find(exclusionItem.fieldName)};
                if (fieldIt != ret.end() && std::regex_match(fieldIt->get_ref<const std::string&>(), pattern))
                {
                    ret.clear();
                }
            }
        }
    }
    return ret;
}

nlohmann::json SysNormalizer::normalize(const std::string& type,
                                        const nlohmann::json& data) const
{
    nlohmann::json ret(data);
    const auto dictionaryIt{m_typeDictionary.find(type)};
    if (dictionaryIt != m_typeDictionary.cend())
    {
        for (const auto& dictionaryItem : dictionaryIt->second)
        {
            std::regex pattern{dictionaryItem.pattern};
            if (ret.is_array())
            {
                for (auto& item : ret)
                {
                    const auto fieldIt{item.find(dictionaryItem.srcFieldName)};
                    if (fieldIt != item.end())
                    {
                        switch(dictionaryItem.action)
                        {
                            case REPLACE_VALUE:
                                *fieldIt = std::regex_replace(fieldIt->get_ref<const std::string&>(), pattern, dictionaryItem.value);
                                break;
                            case ADD_VALUE:
                                if (std::regex_match(fieldIt->get_ref<const std::string&>(), pattern))
                                {
                                    item[dictionaryItem.destFieldName] = dictionaryItem.value;
                                }
                                break;
                        }
                    }
                }
            }
            else
            {
                const auto fieldIt{ret.find(dictionaryItem.srcFieldName)};
                if (fieldIt != ret.end())
                {
                    switch(dictionaryItem.action)
                    {
                        case REPLACE_VALUE:
                            *fieldIt = std::regex_replace(fieldIt->get_ref<const std::string&>(), pattern, dictionaryItem.value);
                            break;
                        case ADD_VALUE:
                            if (std::regex_match(fieldIt->get_ref<const std::string&>(), pattern))
                            {
                                ret[dictionaryItem.destFieldName] = dictionaryItem.value;
                            }
                            break;
                    }
                }
            }
        }
    }
    return ret;
}

std::map<SysNormalizer::DataType, SysNormalizer::Exclusions> SysNormalizer::getTypeExclusions(const std::string& configFile,
                                                                                              const std::string& target)
{
    std::map<DataType, Exclusions> ret;
    try
    {
        std::ifstream config{ configFile };
        if (config.is_open())
        {
            const nlohmann::json& jsonConfigFile { nlohmann::json::parse(config) };
            const auto it{jsonConfigFile.find("exclusions")};
            if (it != jsonConfigFile.end())
            {
                for (const auto& exclusion : *it)
                {
                    if (exclusion["target"] == target)
                    {
                        const auto& type{exclusion["data_type"]};
                        const auto& field{exclusion["field_name"]};
                        const auto& pattern{exclusion["pattern"]};
                        ret[type].push_back({field, pattern});
                    }
                }
            }
        }
    }
    catch(...)
    {
    }
    return ret;
}

std::map<SysNormalizer::DataType, SysNormalizer::Dictionary> SysNormalizer::getTypeDictionary(const std::string& configFile,
                                                                                              const std::string& target)
{
    std::map<DataType, Dictionary> ret;
    // LCOV_EXCL_START
    static const std::map<std::string, DictionaryAction> s_actionsMap
    {
        {"replace", REPLACE_VALUE},
        {"add", ADD_VALUE},
    };
    // LCOV_EXCL_STOP
    try
    {
        std::ifstream config{ configFile };
        if (config.is_open())
        {
            const nlohmann::json& jsonConfigFile { nlohmann::json::parse(config) };
            const auto it{jsonConfigFile.find("dictionary")};
            if (it != jsonConfigFile.end())
            {
                for (const auto& dictionaryItem : *it)
                {
                    if (dictionaryItem["target"] == target)
                    {
                        const auto& type{dictionaryItem["data_type"]};
                        const auto& srcField{dictionaryItem["src_field_name"]};
                        const auto& destField{dictionaryItem["dest_field_name"]};
                        const auto& pattern{dictionaryItem["pattern"]};
                        const auto& value{dictionaryItem["value"]};
                        const auto& action{s_actionsMap.at(dictionaryItem["action"])};
                        ret[type].push_back({srcField, destField, pattern, value, action});
                    }
                }
            }
        }
    }
    catch(...)
    {
    }
    return ret;
}
