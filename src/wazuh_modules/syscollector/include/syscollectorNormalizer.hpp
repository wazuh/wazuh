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

#pragma once

#include <json.hpp>
#include <map>
#include <optional>
#include <regex>
#include <string>
#include <vector>

class SysNormalizer
{
    public:
        struct ExclusionRule
        {
            std::regex pattern;
            std::string fieldName;
        };

        struct FindRule
        {
            std::regex pattern;
            std::string fieldName;
        };

        struct ReplaceRule
        {
            std::regex pattern;
            std::string fieldName;
            std::string value;
        };

        struct AddRule
        {
            std::string fieldName;
            std::string value;
        };

        struct DictionaryRule
        {
            std::optional<FindRule> find;
            std::optional<ReplaceRule> replace;
            std::optional<AddRule> add;
        };

        SysNormalizer(const std::string& configFile,
                      const std::string& target);
        ~SysNormalizer() = default;
        void normalize(const std::string& type,
                       nlohmann::json& data) const;
        void removeExcluded(const std::string& type,
                            nlohmann::json& data) const;
    private:
        static std::map<std::string, nlohmann::json> getTypeValues(const std::string& configFile,
                                                                   const std::string& target,
                                                                   const std::string& type);
        static std::map<std::string, std::vector<ExclusionRule>> compileExclusions(
            const std::map<std::string, nlohmann::json>& rawExclusions);
        static std::map<std::string, std::vector<DictionaryRule>> compileDictionary(
            const std::map<std::string, nlohmann::json>& rawDictionary);

        const std::map<std::string, std::vector<ExclusionRule>> m_typeExclusions;
        const std::map<std::string, std::vector<DictionaryRule>> m_typeDictionary;
};
