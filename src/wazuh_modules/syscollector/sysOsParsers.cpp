/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysOsParsers.h"
#include "stringHelper.h"
#include <regex>

bool UnixOsParser::parseFile(std::istream& in, nlohmann::json& info)
{
    static const std::map<std::string, std::string> KEY_MAP
    {
        {"NAME",    "os_name"},
        {"VERSION", "os_version"},
        {"ID",      "os_platform"}
    };
    enum ValueIds
    {
        KEY_ID,
        DATA_ID,
        MAX_ID
    };
    bool ret{false};
    std::string line;
    while(std::getline(in, line))
    {
        line = Utils::trim(line);
        const auto data{Utils::split(line, '=')};
        if (data.size() == MAX_ID)
        {
            const auto it{KEY_MAP.find(data[KEY_ID])};
            if (it != KEY_MAP.end())
            {
                info[it->second] = Utils::trim(data[DATA_ID], " \"");
                ret = true;
            }
        }
    }
    return ret;
}

static bool findRegexInString(const std::string& in,
                              std::string& match,
                              const std::regex& pattern,
                              const size_t matchIndex = 0,
                              const std::string& start = "")
{
    bool ret{false};
    if (start.empty() || Utils::startsWith(in, start))
    {
        std::smatch sm;
        ret = std::regex_search(in, sm, pattern);
        if (ret && sm.size() >= matchIndex)
        {
            match = sm[matchIndex];
        }
    }
    return ret;
}

static bool findVersionInStream(std::istream& in,
                                nlohmann::json& output,
                                const std::string& regex,
                                const size_t matchIndex = 0,
                                const std::string& start = "")
{
    bool ret{false};
    std::string line;
    std::string match;
    std::regex pattern{regex};
    while(!ret && std::getline(in, line))
    {
        line = Utils::trim(line);
        ret = findRegexInString(line, match, pattern, matchIndex, start);
    }
    if (ret)
    {
        output["os_version"] = match;
    }
    return ret;
}

bool UbuntuOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    constexpr auto DISTRIB_FIELD{"DISTRIB_DESCRIPTION"};
    output["os_name"] = "Ubuntu";
    output["os_platform"] = "ubuntu";
    return findVersionInStream(in, output, PATTERN_MATCH, 0, DISTRIB_FIELD);
}

bool CentosOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    output["os_name"] = "Centos Linux";
    output["os_platform"] = "centos";
    return findVersionInStream(in, output, PATTERN_MATCH);
}

bool BSDOsParser::parseUname(const std::string& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    std::string match;
    std::regex pattern{PATTERN_MATCH};
    const auto ret {findRegexInString(in, match, pattern)};
    if (ret)
    {
        output["os_version"] = match;
    }
    output["os_name"] = "BSD";
    output["os_platform"] = "bsd";
    return ret;
}

bool RedHatOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    bool ret{false};
    std::string line;
    std::regex pattern{PATTERN_MATCH};
    while(std::getline(in, line))
    {
        std::string match;
        line = Utils::trim(line);
        ret = findRegexInString(line, match, pattern);
        if (ret)
        {
            output["os_version"] = match;
        }
        if (line.find("CentOS") != std::string::npos)
        {
            output["os_name"] = "Centos Linux";
            output["os_platform"] = "centos";
        }
        else if (line.find("Fedora") != std::string::npos)
        {
            output["os_name"] = "Fedora";
            output["os_platform"] = "fedora";
        }
        else if (line.find("Server") != std::string::npos)
        {
            output["os_name"] = "Red Hat Enterprise Linux Server";
            output["os_platform"] = "rhel";
        }
        else
        {
            output["os_name"] = "Red Hat Enterprise Linux";
            output["os_platform"] = "rhel";
        }
    }
    return ret;
}

bool DebianOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    output["os_name"] = "Debian GNU/Linux";
    output["os_platform"] = "debian";
    return findVersionInStream(in, output, PATTERN_MATCH);
}

bool ArchOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    output["os_name"] = "Arch Linux";
    output["os_platform"] = "arch";
    return findVersionInStream(in, output, PATTERN_MATCH);
}

bool SlackwareOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    output["os_name"] = "Slackware";
    output["os_platform"] = "slackware";
    return findVersionInStream(in, output, PATTERN_MATCH);
}

bool GentooOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    output["os_name"] = "Gentoo";
    output["os_platform"] = "gentoo";
    return findVersionInStream(in, output, PATTERN_MATCH);
}

bool SuSEOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    constexpr auto VERSION_FIELD{"VERSION"};
    output["os_name"] = "SuSE Linux";
    output["os_platform"] = "suse";
    return findVersionInStream(in, output, PATTERN_MATCH, 0, VERSION_FIELD);
}

bool FedoraOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9]+\.*)"};
    output["os_name"] = "Fedora";
    output["os_platform"] = "fedora";
    return findVersionInStream(in, output, PATTERN_MATCH);
}

bool SolarisOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    const std::string HEADER_STRING{"Oracle Solaris "};
    output["os_name"] = "SunOS";
    output["os_platform"] = "sunos";
    std::string line;
    bool ret{false};
    while(!ret && std::getline(in, line))
    {
        line = Utils::trim(line);
        ret = Utils::startsWith(line, HEADER_STRING);
        if (ret)
        {
            line = line.substr(HEADER_STRING.size());
            const auto pos{line.find(" ")};
            if (pos != std::string::npos)
            {
                line = line.substr(0, pos);
            }
            output["os_version"] = Utils::trim(line);
        }
    }
    return ret;
}

bool HpUxOsParser::parseUname(const std::string& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"(B\.([0-9].*\.[0-9]*))"};
    std::string match;
    std::regex pattern{PATTERN_MATCH};
    const auto ret {findRegexInString(in, match, pattern, 1)};
    if (ret)
    {
        output["os_version"] = match;
    }
    output["os_name"] = "HP-UX";
    output["os_platform"] = "hp-ux";
    return ret;
}