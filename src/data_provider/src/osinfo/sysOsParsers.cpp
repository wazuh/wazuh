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

#include "osinfo/sysOsParsers.h"
#include "stringHelper.h"
#include "sharedDefs.h"
#include <regex>

static bool parseUnixFile(const std::map<std::string, std::string>& keyMap,
                          const char separator,
                          std::istream& in,
                          nlohmann::json& info)
{
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
        const auto data{Utils::split(line, separator)};
        if (data.size() == MAX_ID)
        {
            const auto it
            {
                std::find_if(keyMap.cbegin(), keyMap.cend(),
                [&data](const auto& value)
                {
                    return value.first == Utils::trim(data[KEY_ID]);
                })
            };
            if (it != keyMap.cend())
            {
                info[it->second] = Utils::trim(data[DATA_ID], " \"\t");
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

static bool findCodeNameInString(const std::string& in,
                                 std::string& output)
{
    const auto end{in.rfind(")")};
    const auto start{in.rfind("(")};
    const bool ret
    {
        start != std::string::npos && end != std::string::npos
    };
    if (ret)
    {
        output = Utils::trim(in.substr(start + 1, end - (start + 1)));
    }
    return ret;
}

static void findMajorMinorVersionInString(const std::string& in,
                                          nlohmann::json& output)
{
    constexpr auto PATCH_VERSION_PATTERN{"^[0-9]+\\.[0-9]+\\.([0-9]+)\\.*"};
    constexpr auto MINOR_VERSION_PATTERN{"^[0-9]+\\.([0-9]+)\\.*"};
    constexpr auto MAJOR_VERSION_PATTERN{"^([0-9]+)\\.*"};
    std::string version;
    std::regex pattern{MAJOR_VERSION_PATTERN};
    if (findRegexInString(in, version, pattern, 1))
    {
        output["os_major"] = version;
    }
    pattern = MINOR_VERSION_PATTERN;
    if (findRegexInString(in, version, pattern, 1))
    {
        output["os_minor"] = version;
    }
    pattern = PATCH_VERSION_PATTERN;
    if (findRegexInString(in, version, pattern, 1))
    {
        output["os_patch"] = version;
    }
}


static bool findVersionInStream(std::istream& in,
                                nlohmann::json& output,
                                const std::string& regex,
                                const size_t matchIndex = 0,
                                const std::string& start = "")
{
    bool ret{false};
    std::string line;
    std::string data;
    std::regex pattern{regex};
    while(std::getline(in, line))
    {
        line = Utils::trim(line);
        ret |= findRegexInString(line, data, pattern, matchIndex, start);
        if (ret)
        {
            output["os_version"] = data;
            findMajorMinorVersionInString(data, output);
        }
        if (findCodeNameInString(line, data))
        {
            output["os_codename"] = data;
        }
    }
    return ret;
}

bool UnixOsParser::parseFile(std::istream& in, nlohmann::json& info)
{
    constexpr auto SEPARATOR{'='};
    static const std::map<std::string, std::string> KEY_MAP
    {
        {"NAME",             "os_name"},
        {"VERSION",          "os_version"},
        {"ID",               "os_platform"},
        {"VERSION_CODENAME", "os_codename"}
    };
    const auto ret {parseUnixFile(KEY_MAP, SEPARATOR, in, info)};
    if (ret && info.find("os_version") != info.end())
    {
        findMajorMinorVersionInString(info["os_version"], info);
    }
    return ret;
}

bool UbuntuOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9].*\.[0-9]*)"};
    constexpr auto DISTRIB_FIELD{"DISTRIB_DESCRIPTION"};
    static const std::string CODENAME_FIELD{"DISTRIB_CODENAME"};
    bool ret{false};
    std::string line;
    std::regex pattern{PATTERN_MATCH};
    while(std::getline(in, line))
    {
        line = Utils::trim(line);
        std::string match;
        if (findRegexInString(line, match, pattern, 0, DISTRIB_FIELD))
        {
            output["os_version"] = match;
            findMajorMinorVersionInString(match, output);
            ret = true;
        }
        else if (Utils::startsWith(line, CODENAME_FIELD))
        {
            output["os_codename"] = Utils::trim(line.substr(CODENAME_FIELD.size()), " =");
            ret = true;
        }
    }
    output["os_name"] = "Ubuntu";
    output["os_platform"] = "ubuntu";
    return ret;
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
        findMajorMinorVersionInString(match, output);
    }
    output["os_name"] = "BSD";
    output["os_platform"] = "bsd";
    return ret;
}

bool RedHatOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    static const std::string FIRST_DELIMITER{"release"};
    static const std::string SECOND_DELIMITER{"("};
    bool ret{false};
    std::string data;
    if(std::getline(in, data))
    {
        //format is: OSNAME release VERSION (CODENAME)
        auto pos{data.find(FIRST_DELIMITER)};
        if(pos != std::string::npos)
        {
            output["os_name"] = Utils::trim(data.substr(0, pos));
            data = data.substr(pos + FIRST_DELIMITER.size());
            pos = data.find(SECOND_DELIMITER);
            ret = true;
        }
        if (pos != std::string::npos)
        {
            const auto fullVersion{Utils::trim(data.substr(0, pos))};
            const auto versions{Utils::split(fullVersion, '.')};
            output["os_version"] = fullVersion;
            output["os_major"] = versions[0];
            if (versions.size() > 1)
            {
                output["os_minor"] = versions[1];
            }
            output["os_codename"] = Utils::trim(data.substr(pos), " ()");
        }
        output["os_platform"] = "rhel";

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
    constexpr auto SEPARATOR{'='};
    static const std::map<std::string, std::string> KEY_MAP
    {
        {"VERSION",          "os_version"},
        {"CODENAME",         "os_codename"},
    };
    output["os_name"] = "SuSE Linux";
    output["os_platform"] = "suse";
    const auto ret{ parseUnixFile(KEY_MAP, SEPARATOR, in, output) };
    if (ret)
    {
        findMajorMinorVersionInString(output["os_version"], output);
    }
    return ret;
}

bool FedoraOsParser::parseFile(std::istream& in, nlohmann::json& output)
{
    constexpr auto PATTERN_MATCH{R"([0-9]+\.*)"};
    output["os_name"] = "Fedora";
    output["os_platform"] = "fedora";
    const auto ret{ findVersionInStream(in, output, PATTERN_MATCH) };
    if (ret)
    {
        findMajorMinorVersionInString(output["os_version"], output);
    }
    return ret;
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
            findMajorMinorVersionInString(Utils::trim(line), output);
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
        findMajorMinorVersionInString(match, output);
    }
    output["os_name"] = "HP-UX";
    output["os_platform"] = "hp-ux";
    return ret;
}

bool MacOsParser::parseSwVersion(const std::string& in, nlohmann::json& output)
{
    constexpr auto SEPARATOR{':'};
    static const std::map<std::string, std::string> KEY_MAP
    {
        {"ProductName",     "os_name"},
        {"ProductVersion",  "os_version"},
        {"BuildVersion",    "os_build"},
    };
    output["os_platform"] = "darwin";
    std::stringstream data{in};
    const auto ret{ parseUnixFile(KEY_MAP, SEPARATOR, data, output) };
    if (ret)
    {
        findMajorMinorVersionInString(output["os_version"], output);
    }
    return ret;
}

bool MacOsParser::parseUname(const std::string& in, nlohmann::json& output)
{
    static const std::map<std::string, std::string> MAC_CODENAME_MAP
    {
        {"10", "Snow Leopard"},
        {"11", "Lion"},
        {"12", "Mountain Lion"},
        {"13", "Mavericks"},
        {"14", "Yosemite"},
        {"15", "El Capitan"},
        {"16", "Sierra"},
        {"17", "High Sierra"},
        {"18", "Mojave"},
        {"19", "Catalina"},
    };
    constexpr auto PATTERN_MATCH{"[0-9]+"};
    std::string match;
    std::regex pattern{PATTERN_MATCH};
    const auto ret {findRegexInString(in, match, pattern, 0)};
    if (ret)
    {
        const auto it{MAC_CODENAME_MAP.find(match)};
        output["os_codename"] = it != MAC_CODENAME_MAP.end() ? it->second : "";
    }
    return ret;
}
