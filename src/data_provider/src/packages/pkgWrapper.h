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
#include "stringHelper.h"
#include "ipackageWrapper.h"
#include "sharedDefs.h"

class PKGWrapper final : public IPackageWrapper
{
public:
    explicit PKGWrapper(const std::string& filePath)
      : m_filePath{filePath}
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
    void getData(nlohmann::json& data) const
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

            std::string name         { DEFAULT_STRING_VALUE };
            std::string version      { DEFAULT_STRING_VALUE };
            std::string groups       { DEFAULT_STRING_VALUE };
            std::string description  { DEFAULT_STRING_VALUE };
            std::string architecture { DEFAULT_STRING_VALUE };
            std::string format       { DEFAULT_STRING_VALUE };
            std::string osPatch      { DEFAULT_STRING_VALUE };

            while(std::getline(file, line))
            {
                line = Utils::trim(line," \t");

                if (line == "<key>CFBundleName</key>" &&
                    std::getline(file, line))
                {
                    name = getValueFnc(line);
                }
                else if (line == "<key>CFBundleShortVersionString</key>" &&
                    std::getline(file, line))
                {
                    version = getValueFnc(line);
                }
                else if (line == "<key>LSApplicationCategoryType</key>" &&
                    std::getline(file, line))
                {
                    groups = getValueFnc(line);
                }
                else if (line == "<key>CFBundleIdentifier</key>" &&
                    std::getline(file, line))
                {
                    description = getValueFnc(line);
                }
            }

            if (UNKNOWN_VALUE != name)
            {
                package["name"]         = name;
                package["version"]      = version;
                package["groups"]       = groups;
                package["description"]  = description;
                package["architecture"] = UNKNOWN_VALUE;
                package["format"]       = "pkg";
                package["os_patch"]     = UNKNOWN_VALUE;
                data.push_back(package);
            }
        }
    }

    std::string m_filePath;
};

#endif //_PKG_WRAPPER_H
