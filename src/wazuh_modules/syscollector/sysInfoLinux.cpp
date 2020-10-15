/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo.hpp"
#include <fstream>
#include <iostream>
#include "stringHelper.h"

constexpr auto WM_SYS_HW_DIR{"/sys/class/dmi/id/board_serial"};
constexpr auto WM_SYS_CPU_DIR{"/proc/cpuinfo"};
constexpr auto WM_SYS_MEM_DIR{"/proc/meminfo"};

static std::string getSerialNumber()
{
    std::string serial;
    std::fstream file{WM_SYS_HW_DIR, std::ios_base::in};
    if (file.is_open())
    {
        file >> serial;
    }
    else
    {
        serial = "unknown";
    }
    return serial;
}

static void parseLineAndFillMap(const std::string& line, const std::string& separator, std::map<std::string, std::string>& systemInfo)
{
    const auto pos{line.find(separator)};
    if (pos != std::string::npos)
    {
        const auto key{Utils::trim(line.substr(0, pos), " \t\"")};
        const auto value{Utils::trim(line.substr(pos + 1), " \t\"")};
        systemInfo[key] = value;
        std::cout << key << ":" << value << std::endl;
    }
}
static bool getSystemInfo(const std::string& fileName, const std::string& separator, std::map<std::string, std::string>& systemInfo)
{
    std::string info;
    std::fstream file{fileName, std::ios_base::in};
    const bool ret{file.is_open()};
    if (ret)
    {
        std::string line;
        while(file.good())
        {
            std::getline(file, line);
            parseLineAndFillMap(line, separator, systemInfo);
        }
    }
    return ret;
}

nlohmann::json SysInfo::hardware()
{
    std::map<std::string, std::string> systemInfo;
    nlohmann::json ret;
    ret["board_serial"] = getSerialNumber();
    getSystemInfo(WM_SYS_CPU_DIR, ":", systemInfo);
    getSystemInfo(WM_SYS_MEM_DIR, ":", systemInfo);
    ret["cpu_name"] = systemInfo.at("model name");
    ret["cpu_cores"] = (std::stoi(systemInfo.at("processor")) + 1);
    ret["cpu_MHz"] = (std::stod(systemInfo.at("cpu MHz")));
    const auto memTotal{std::stod(systemInfo.at("MemTotal"))};
    const auto memFree{std::stod(systemInfo.at("MemFree"))};
    ret["ram_total"] = memTotal;
    ret["ram_free"] = memFree;
    ret["ram_usage"] = 100.0*(1.0 - memFree/memTotal);
    return ret;
}
