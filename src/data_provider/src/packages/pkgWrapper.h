/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2020, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PKG_WRAPPER_H
#define _PKG_WRAPPER_H

#include <fstream>
#include "ipackageWrapper.h"
#include "sharedDefs.h"

class PKGWrapper final : public IPackageWrapper
{
public:
    explicit PKGWrapper(const std::string& filePath)
      : m_filePath{filePath}
      , m_name{ DEFAULT_STRING_VALUE }
      , m_version{ DEFAULT_STRING_VALUE }
      , m_groups{ DEFAULT_STRING_VALUE }
      , m_description{ DEFAULT_STRING_VALUE }
      , m_architecture{ DEFAULT_STRING_VALUE }
      , m_format{ DEFAULT_STRING_VALUE }
      , m_osPatch{ DEFAULT_STRING_VALUE }
    { }

    ~PKGWrapper() = default;

    std::string name() const override
    {
        nlohmann::json jsonData{};
        getData(jsonData);
        return jsonData.empty() ? DEFAULT_STRING_VALUE
                                : jsonData.at("name");
    }
    std::string version() const override
    {
        nlohmann::json jsonData{};
        getData(jsonData);
        return jsonData.empty() ? DEFAULT_STRING_VALUE
                                : jsonData.at("version");
    }
    std::string groups() const override
    {
        nlohmann::json jsonData{};
        getData(jsonData);
        return jsonData.empty() ? DEFAULT_STRING_VALUE
                                : jsonData.at("groups");
    }
    std::string description() const override
    {
        nlohmann::json jsonData{};
        getData(jsonData);
        return jsonData.empty() ? DEFAULT_STRING_VALUE
                                : jsonData.at("description");
    }
    std::string architecture() const override
    {
        nlohmann::json jsonData{};
        getData(jsonData);
        return jsonData.empty() ? DEFAULT_STRING_VALUE
                                : jsonData.at("architecture");
    }
    std::string format() const override
    {
        nlohmann::json jsonData{};
        getData(jsonData);
        return jsonData.empty() ? DEFAULT_STRING_VALUE
                                : jsonData.at("format");
    }
    std::string osPatch() const override
    {
        nlohmann::json jsonData{};
        getData(jsonData);
        return jsonData.empty() ? DEFAULT_STRING_VALUE
                                : jsonData.at("osPatch");
    }
private:
    static void getData(nlohmann::json& data)
    {
        std::fstream file {m_filePath, std::ios_base::in};
        static const auto getValueFnc
        {
            [](const std::string& val)
            {
                const auto start{val.find(">")};
                const auto end{val.rfind("<")};
                return val.substr(start+1, end - start -1);
            }
        };
        if (file.is_open())
        {
            std::string line;
            nlohmann::json package;
            while(std::getline(file, line))
            {
                line = Utils::trim(line," \t");

                if (line == "<key>CFBundleName</key>" &&
                    std::getline(file, line))
                {
                    m_name = getValueFnc(line);
                }
                else if (line == "<key>CFBundleShortVersionString</key>" &&
                    std::getline(file, line))
                {
                    m_version = getValueFnc(line);
                }
                else if (line == "<key>LSApplicationCategoryType</key>" &&
                    std::getline(file, line))
                {
                    m_groups = getValueFnc(line);
                }
                else if (line == "<key>CFBundleIdentifier</key>" &&
                    std::getline(file, line))
                {
                    m_description = getValueFnc(line);
                }
            }

            if (UNKNOWN_VALUE != m_name)
            {
                package["name"]         = m_name;
                package["version"]      = m_version;
                package["groups"]       = m_groups;
                package["description"]  = m_description;
                package["architecture"] = UNKNOWN_VALUE;
                package["format"]       = "pkg";
                package["os_patch"]     = UNKNOWN_VALUE;
                data.push_back(package);
            }
        }
    }

    std::string m_filePath;
    std::string m_name;
    std::string m_version;
    std::string m_groups;
    std::string m_description;
    std::string m_architecture;
    std::string m_format;
    std::string m_osPatch;
};

#endif //_PKG_WRAPPER_H
