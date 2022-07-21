/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
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
    : m_typeExclusions{getTypeValues(configFile, target, "exclusions")}
    , m_typeDictionary{getTypeValues(configFile, target, "dictionary")}
{
}

void SysNormalizer::removeExcluded(const std::string& type,
                                   nlohmann::json& data) const
{
    const auto exclusionsIt{m_typeExclusions.find(type)};

    if (exclusionsIt != m_typeExclusions.cend())
    {
        for (const auto& exclusionItem : exclusionsIt->second)
        {
            try
            {
                std::regex pattern{exclusionItem["pattern"].get_ref<const std::string&>()};
                const auto& fieldName{exclusionItem["field_name"].get_ref<const std::string&>()};

                if (data.is_array())
                {
                    for (auto item{data.begin()}; item != data.end(); ++item)
                    {
                        const auto fieldIt{item->find(fieldName)};

                        if (fieldIt != item->end() && std::regex_match(fieldIt->get_ref<const std::string&>(), pattern))
                        {
                            data.erase(item);
                        }
                    }
                }
                else
                {
                    const auto fieldIt{data.find(fieldName)};

                    if (fieldIt != data.end() && std::regex_match(fieldIt->get_ref<const std::string&>(), pattern))
                    {
                        data.clear();
                    }
                }
            }
            // LCOV_EXCL_START
            catch (...)
            {}

            // LCOV_EXCL_STOP
        }
    }
}


static void normalizeItem(const nlohmann::json& dictionary,
                          nlohmann::json& item)
{
    for (const auto& dictItem : dictionary)
    {
        const auto itFindPattern{dictItem.find("find_pattern")};
        const auto itFindField{dictItem.find("find_field")};

        if (itFindPattern != dictItem.end() && itFindField != dictItem.end())
        {
            const auto fieldIt{item.find(itFindField->get_ref<const std::string&>())};
            std::regex pattern{itFindPattern->get_ref<const std::string&>()};

            if (fieldIt == item.end() ||
                    !std::regex_match(fieldIt->get_ref<const std::string&>(), pattern))
            {
                //no field in the item or no matching, we continue
                continue;
            }
        }
        else if (itFindPattern != dictItem.end() || itFindField != dictItem.end())
        {
            //we won't evaluate an incomplete item.
            continue;
        }

        const auto itReplacePattern{dictItem.find("replace_pattern")};
        const auto itReplaceField{dictItem.find("replace_field")};
        const auto itReplaceValue{dictItem.find("replace_value")};

        if (itReplacePattern != dictItem.end() && itReplaceField != dictItem.end() && itReplaceValue != dictItem.end())
        {
            std::regex pattern{itReplacePattern->get_ref<const std::string&>()};
            const auto fieldIt{item.find(itReplaceField->get_ref<const std::string&>())};

            if (fieldIt != item.end())
            {
                *fieldIt = std::regex_replace(fieldIt->get_ref<const std::string&>(), pattern, itReplaceValue->get_ref<const std::string&>());
            }
        }

        const auto itAddField{dictItem.find("add_field")};
        const auto itAddValue{dictItem.find("add_value")};

        if (itAddField != dictItem.end() && itAddValue != dictItem.end())
        {
            item[itAddField->get_ref<const std::string&>()] = itAddValue->get_ref<const std::string&>();
        }
    }
}

void SysNormalizer::normalize(const std::string& type,
                              nlohmann::json& data) const
{
    const auto dictionaryIt{m_typeDictionary.find(type)};

    if (dictionaryIt != m_typeDictionary.cend())
    {
        if (data.is_array())
        {
            for (auto& item : data)
            {
                normalizeItem(dictionaryIt->second, item);
            }
        }
        else
        {
            normalizeItem(dictionaryIt->second, data);
        }
    }
}

std::map<std::string, nlohmann::json> SysNormalizer::getTypeValues(const std::string& configFile,
                                                                   const std::string& target,
                                                                   const std::string& type)
{
    std::map<std::string, nlohmann::json> ret;

    try
    {
        std::ifstream config{ configFile };
        nlohmann::json data;

        if (config.is_open())
        {
            const nlohmann::json& jsonConfigFile { nlohmann::json::parse(config) };
            const auto it{jsonConfigFile.find(type)};

            if (it != jsonConfigFile.end())
            {
                for (const auto& item : *it)
                {
                    if (item["target"] == target)
                    {
                        ret[item["data_type"]].push_back(item);
                    }
                }
            }
        }
    }
    catch (...)
    {
    }

    return ret;
}
