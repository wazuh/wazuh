/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <fstream>
#include <iostream>
#include "stringHelper.h"
#include "sysInfo.hpp"

extern "C"
{
#include "shared.h"
#include "readproc.h"
}

constexpr auto WM_SYS_HW_DIR{"/sys/class/dmi/id/board_serial"};
constexpr auto WM_SYS_CPU_DIR{"/proc/cpuinfo"};
constexpr auto WM_SYS_MEM_DIR{"/proc/meminfo"};

struct ProcTableDeleter
{
    void operator()(PROCTAB* proc)
    {
        closeproc(proc);
    }
    void operator()(proc_t* proc)
    {
        freeproc(proc);
    }
};

using SysInfoProcessesTable = std::unique_ptr<PROCTAB, ProcTableDeleter>;
using SysInfoProcess        = std::unique_ptr<proc_t, ProcTableDeleter>;

static void parseLineAndFillMap(const std::string& line, const std::string& separator, std::map<std::string, std::string>& systemInfo)
{
    const auto pos{line.find(separator)};
    if (pos != std::string::npos)
    {
        const auto key{Utils::trim(line.substr(0, pos), " \t\"")};
        const auto value{Utils::trim(line.substr(pos + 1), " \t\"")};
        systemInfo[key] = value;
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

static nlohmann::json getProcessInfo(const SysInfoProcess& process)
{
	nlohmann::json jsProcessInfo{};
	// Current process information
	jsProcessInfo["pid"]   		= process->tid;
	jsProcessInfo["name"]  		= process->cmd;
	jsProcessInfo["state"] 		= &process->state;
	jsProcessInfo["ppid"]  		= process->ppid;
	jsProcessInfo["utime"] 		= process->utime;
	jsProcessInfo["stime"] 		= process->stime;

	if (process->cmdline && process->cmdline[0])
	{
		nlohmann::json jsCmdlineArgs{};
		jsProcessInfo["cmd"] 	= process->cmdline[0];
		for (int idx = 1; process->cmdline[idx]; ++idx)
		{
			const auto cmdlineArgSize { sizeof(process->cmdline[idx]) };
			if(strnlen(process->cmdline[idx], cmdlineArgSize) != 0)
			{
				jsCmdlineArgs += process->cmdline[idx];
			}
		}
		if (!jsCmdlineArgs.empty())
		{
			jsProcessInfo["argvs"] 	= jsCmdlineArgs;
		}
	}

	jsProcessInfo["euser"]      = process->euser;
	jsProcessInfo["ruser"]      = process->ruser;
	jsProcessInfo["suser"]      = process->suser;
	jsProcessInfo["egroup"]     = process->egroup;
	jsProcessInfo["rgroup"]     = process->rgroup;
	jsProcessInfo["sgroup"]     = process->sgroup;
	jsProcessInfo["fgroup"]     = process->fgroup;
	jsProcessInfo["priority"]   = process->priority;
	jsProcessInfo["nice"]       = process->nice;
	jsProcessInfo["size"]       = process->size;
	jsProcessInfo["vm_size"]    = process->vm_size;
	jsProcessInfo["resident"]   = process->resident;
	jsProcessInfo["share"]      = process->share;
	jsProcessInfo["start_time"] = process->start_time;
	jsProcessInfo["pgrp"] 		= process->pgrp;
	jsProcessInfo["session"] 	= process->session;
	jsProcessInfo["tgid"] 		= process->tgid;
	jsProcessInfo["tty"] 		= process->tty;
	jsProcessInfo["processor"] 	= process->processor;
	jsProcessInfo["nlwp"] 		= process->nlwp;
	return jsProcessInfo;
}

std::string SysInfo::getSerialNumber()
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

std::string SysInfo::getCpuName()
{
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_CPU_DIR, ":", systemInfo);
    return systemInfo.at("model name");
}

int SysInfo::getCpuCores()
{
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_CPU_DIR, ":", systemInfo);
    return (std::stoi(systemInfo.at("processor")) + 1);
}

int SysInfo::getCpuMHz()
{
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_CPU_DIR, ":", systemInfo);
    return (std::stoi(systemInfo.at("cpu MHz")));
}

void SysInfo::getMemory(nlohmann::json& info)
{
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_MEM_DIR, ":", systemInfo);
    const auto memTotal{std::stoi(systemInfo.at("MemTotal"))};
    const auto memFree{std::stoi(systemInfo.at("MemFree"))};
    info["ram_total"] = memTotal;
    info["ram_free"] = memFree;
    info["ram_usage"] = 100 - (100*memFree/memTotal);
}

nlohmann::json SysInfo::getProcessesInfo()
{
	nlohmann::json jsProcessesList{};

	const SysInfoProcessesTable spProcTable
	{
		openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLARG | PROC_FILLGRP | PROC_FILLUSR | PROC_FILLCOM | PROC_FILLENV) 
	};

	SysInfoProcess spProcInfo { readproc(spProcTable.get(), nullptr) };
	while (nullptr != spProcInfo)
	{
		// Append the current json process object to the list of processes
		jsProcessesList += getProcessInfo(spProcInfo);
		spProcInfo.reset(readproc(spProcTable.get(), nullptr));
	}
	return jsProcessesList;
}