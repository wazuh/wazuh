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

constexpr auto WM_SYS_HW_DIR{"/sys/class/dmi/id/board_serial"};
constexpr auto WM_SYS_CPU_DIR{"/proc/cpuinfo"};

struct BufferSmartDeleter
{
	void operator()(char* buffer)
	{
		delete[] buffer;
	}
};

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


static void parseLineAndFillMap(const std::string& line, std::map<std::string, std::string>& map)
{
	const auto pos{line.find(":")};
	if (pos != std::string::npos)
	{
		const auto key{line.substr(0, pos)};
		const auto value{line.substr(pos + 1)};
		std::cout << "key: " << key << ", value: " << value << std::endl;
	}
}
static std::string getSystemInfo()
{
	std::map<std::string, std::string> hwInfo;
    std::string info;
    std::fstream file{WM_SYS_CPU_DIR, std::ios_base::in};
    if (file.is_open())
    {
    	std::string line;
    	while(file.good())
    	{
    		std::getline(file, line);
    		parseLineAndFillMap(line, hwInfo);
    	}
    }
    else
    {
    	info = "unknown";
    }
    return info;
}


nlohmann::json SysInfo::hardware()
{
	nlohmann::json ret;
	ret["board_serial"] = getSerialNumber();
	ret["cpu"] = getSystemInfo();
	return ret;
}
