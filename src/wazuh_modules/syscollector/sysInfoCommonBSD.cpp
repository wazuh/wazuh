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
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/proc_info.h>

using ProcessTaskInfo = struct proc_taskallinfo;
using ProcessPasswd   = struct passwd;
using ProcessGroup    = struct group;

static const std::map<int, std::string> s_s_mapTaskInfoState =
{
    { 1, "I"},  // Idle
    { 2, "R"},  // Running
    { 3, "S"},  // Sleep
    { 4, "T"},  // Stopped
    { 5, "Z"}   // Zombie
};

struct PIDsDeleter
{
    void operator()(pid_t* pids)
    {
        os_free(pids);
    }
};

static nlohmann::json getProcessInfo(const ProcessTaskInfo& taskInfo, const pid_t pid)
{
    nlohmann::json jsProcessInfo{};
    jsProcessInfo["pid"] 		= pid;
    jsProcessInfo["name"] 		= taskInfo.pbsd.pbi_name;

    const auto procState { s_mapTaskInfoState.find(taskInfo.pbsd.pbi_status) };
    jsProcessInfo["state"] 		= (procState != s_mapTaskInfoState.end()) ? procState.second : "E";
    jsProcessInfo["ppid"] 		= taskInfo.pbsd.pbi_ppid;

    const std::unique_ptr<ProcessPasswd> spEUser { getpwuid(const_cast<int*>(taskInfo.pbsd.pbi_uid)) };
    if (spEUser)
    {
        jsProcessInfo["euser"] 	= spEUser->pw_name;
    }

    const std::unique_ptr<ProcessPasswd> spRUser { getpwuid(const_cast<int*>(taskInfo.pbsd.pbi_ruid)) };
    if (spRUser)
    {
        jsProcessInfo["ruser"] 	= spRUser->pw_name;
    }

    const std::unique_ptr<ProcessGroup> spRGroup { getgrgid(const_cast<int*>(taskInfo.pbsd.pbi_rgid)) };
    if (spRGroup)
    {
        jsProcessInfo["rgroup"] = spRGroup->gr_name;
    }

    jsProcessInfo["priority"]	= taskInfo.ptinfo.pti_priority;
    jsProcessInfo["nice"] 	    = taskInfo.pbsd.pbi_nice;
    jsProcessInfo["vm_size"] 	= taskInfo.ptinfo.pti_virtual_size / 1024;
    return jsProcessInfo;
}

int SysInfo::getCpuCores() const
{
    int cores{0};
    size_t len{sizeof(cores)};
    const std::vector<int> mib{CTL_HW, HW_NCPU};
    const auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &cores, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu cores number."
        };
    }
    return cores;
}

std::string SysInfo::getCpuName() const
{
    const std::vector<int> mib{CTL_HW, HW_MODEL};
    size_t len{0};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), nullptr, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error getting cpu name size."
        };
    }
    const auto spBuff{std::make_unique<char[]>(len+1)};
    if(!spBuff)
    {
        throw std::runtime_error
        {
            "Error allocating memory to read the cpu name."
        };
    }
    ret = sysctl(const_cast<int*>(mib.data()), mib.size(), spBuff.get(), &len, nullptr, 0);
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error getting cpu name"
       };
    }
    spBuff.get()[len] = 0;
    return std::string{reinterpret_cast<const char*>(spBuff.get())};
}

nlohmann::json SysInfo::getProcessesInfo() const
{
    nlohmann::json jsProcessesList{};

    int32_t maxProc;
    size_t len { sizeof(maxProc) };
    sysctlbyname("kern.maxproc", &maxProc, &len, NULL, 0);

    std::unique_ptr<pid_t, PIDsDeleter> spPids{};
    //os_calloc(maxProc, 1, spPids);
    const auto processCount { proc_listallpids(spPids.get(), maxProc) };

    for(int index = 0; index < processCount; ++index)
    {
        ProcessTaskInfo taskInfo{};
        const auto pid { spPids.get()[index] };

        const auto sizeTask { proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &taskInfo, PROC_PIDTASKALLINFO_SIZE) };

        if(st != PROC_PIDTASKALLINFO_SIZE)
        {
            throw std::system_error
            {
                ret,
                std::system_category(),
                "Error getting cpu name"
            };
            mterror(WM_SYS_LOGTAG, "Cannot get process info for PID %d", pid);
            continue;
        }
        jsProcessesList += getProcessInfo(taskInfo, pid);
    }

	return jsProcessesList;
}
