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
#ifndef _SYSCOLLECTOR_NORMALIZER_H
#define _SYSCOLLECTOR_NORMALIZER_H
#include <json.hpp>
#include <string>
#include <map>

class SysNormalizer
{
    public:
        SysNormalizer(const std::string& configFile,
                      const std::string& target);
        ~SysNormalizer() = default;
        nlohmann::json normalize(const std::string& type,
                                 const nlohmann::json& data) const;
        nlohmann::json removeExcluded(const std::string& type,
                                      const nlohmann::json& data) const;
    private:
        static std::map<std::string, nlohmann::json> getTypeValues(const std::string& configFile,
                                                                   const std::string& target,
                                                                   const std::string& type);
        const std::map<std::string, nlohmann::json> m_typeExclusions;
        const std::map<std::string, nlohmann::json> m_typeDictionary;
};


#endif //_SYSCOLLECTOR_NORMALIZER_H