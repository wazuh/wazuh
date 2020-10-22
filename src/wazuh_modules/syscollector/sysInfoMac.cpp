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
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include <libproc.h>
#include <pwd.h>
#include <grp.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>

using ProcessTaskInfo = struct proc_taskallinfo;

static const std::map<int, std::string> s_mapTaskInfoState =
{
    { 1, "I"},  // Idle
    { 2, "R"},  // Running
    { 3, "S"},  // Sleep
    { 4, "T"},  // Stopped
    { 5, "Z"}   // Zombie
};

static nlohmann::json getProcessInfo(const ProcessTaskInfo& taskInfo, const pid_t pid)
{
    nlohmann::json jsProcessInfo{};
    jsProcessInfo["pid"] 		= pid;
    jsProcessInfo["name"] 		= taskInfo.pbsd.pbi_name;

    const auto procState { s_mapTaskInfoState.find(taskInfo.pbsd.pbi_status) };
    jsProcessInfo["state"] 		= (procState != s_mapTaskInfoState.end()) ? procState->second : "E";
    jsProcessInfo["ppid"] 		= taskInfo.pbsd.pbi_ppid;

    const auto eUser { getpwuid(taskInfo.pbsd.pbi_uid) };
    if (eUser)
    {
        jsProcessInfo["euser"] 	= eUser->pw_name;
    }

    const auto rUser { getpwuid(taskInfo.pbsd.pbi_ruid) };
    if (rUser)
    {
        jsProcessInfo["ruser"] 	= rUser->pw_name;
    }

    const auto rGroup { getgrgid(taskInfo.pbsd.pbi_rgid) };
    if (rGroup)
    {
        jsProcessInfo["rgroup"] = rGroup->gr_name;
    }

    jsProcessInfo["priority"]	= taskInfo.ptinfo.pti_priority;
    jsProcessInfo["nice"] 	    = taskInfo.pbsd.pbi_nice;
    jsProcessInfo["vm_size"] 	= taskInfo.ptinfo.pti_virtual_size / KByte;
    return jsProcessInfo;
}

void SysInfo::getMemory(nlohmann::json& info) const
{
    constexpr auto vmPageSize{"vm.pagesize"};
    constexpr auto vmPageFreeCount{"vm.page_free_count"};
    uint64_t ram{0};
    const std::vector<int> mib{CTL_HW, HW_MEMSIZE};
    size_t len{sizeof(ram)};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &ram, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading total RAM."
        };
    }
    const auto ramTotal{ram/KByte};
    info["ram_total"] = ramTotal;
    u_int pageSize{0};
    len = sizeof(pageSize);
    ret = sysctlbyname(vmPageSize, &pageSize, &len, nullptr, 0);
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading page size."
        };
    }
    uint64_t freePages{0};
    len = sizeof(freePages);
    ret = sysctlbyname(vmPageFreeCount, &freePages, &len, nullptr, 0);
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading free pages."
        };
    }
    const auto ramFree{(freePages * pageSize)/KByte};
    info["ram_free"] = ramFree;
    info["ram_usage"] = 100 - (100 * ramFree / ramTotal);
}

int SysInfo::getCpuMHz() const
{
    constexpr auto MHz{1000000};
    unsigned long cpuMHz{0};
    constexpr auto clockRate{"hw.cpufrequency"};
    size_t len{sizeof(cpuMHz)};
    const auto ret{sysctlbyname(clockRate, &cpuMHz, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu frequency."
        };
    }
    return cpuMHz/MHz;
}

std::string SysInfo::getSerialNumber() const
{
    const auto rawData{Utils::exec("system_profiler SPHardwareDataType | grep Serial")};
    return Utils::trim(rawData.substr(rawData.find(":")), " :\t\r\n");
}

nlohmann::json SysInfo::getProcessesInfo() const
{
    nlohmann::json jsProcessesList{};

    int32_t maxProc;
    size_t len { sizeof(maxProc) };
    const auto ret { sysctlbyname("kern.maxproc", &maxProc, &len, NULL, 0) };
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading kernel max processes."
        };
    }

    const auto spPids         { std::make_unique<pid_t[]>(maxProc) };
    const auto processesCount { proc_listallpids(spPids.get(), maxProc) };

    for(int index = 0; index < processesCount; ++index)
    {
        ProcessTaskInfo taskInfo{};
        const auto pid { spPids.get()[index] };
        const auto sizeTask
        {
            proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &taskInfo, PROC_PIDTASKALLINFO_SIZE)
        };

        if(PROC_PIDTASKALLINFO_SIZE == sizeTask)
        {
            jsProcessesList += getProcessInfo(taskInfo, pid);
        }
    }

	return jsProcessesList;
}