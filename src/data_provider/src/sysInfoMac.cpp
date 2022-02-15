/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <array>
#include <vector>
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "filesystemHelper.h"
#include "osinfo/sysOsParsers.h"
#include <libproc.h>
#include <pwd.h>
#include <grp.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/thread_info.h>
#include "ports/portBSDWrapper.h"
#include "ports/portImpl.h"
#include "packages/packageFamilyDataAFactory.h"
#include "packages/pkgWrapper.h"
#include "packages/packageMac.h"
#include "defer.hpp"
#include <unistd.h>

const std::string MAC_APPS_PATH{"/Applications"};
const std::string MAC_UTILITIES_PATH{"/Applications/Utilities"};

using ProcessTaskInfo = struct proc_taskallinfo;


static const std::vector<int> s_validFDSock =
{
    {
        SOCKINFO_TCP,
        SOCKINFO_IN
    }
};

static const std::map<std::string, int> s_mapPackagesDirectories =
{
    { "/Applications", PKG },
    { "/Applications/Utilities", PKG},
    { "/System/Applications", PKG},
    { "/System/Applications/Utilities", PKG},
    { "/System/Library/CoreServices", PKG},
    { "/usr/local/Cellar", BREW},
};

static const std::array<std::string, 9> s_mapTaskInfoState =
{
#define STATE_UNKNOWN 0
    "E",   // Error/invalid
#define STATE_RUN 1
    "R",   // Idle
#define STATE_UNINTERRUPTIBLE 2
    "S",   // Uninterruptible sleep
#define STATE_STUCK 3
    "S",   // Sleep
#define STATE_STOP 4
    "T",   // Stopped
#define STATE_HALT 5
    "T",   // Halt
#define STATE_IDLE 6
    "S",   // Sleep
#define STATE_SLEEP 7
    "S",   // Sleep
#define STATE_ZOMBIE 8
    "Z"
};


static int toProcessState(int state, long sleeptime)
{
    switch (state)
    {
        case TH_STATE_RUNNING:
            return STATE_RUN;

        case TH_STATE_UNINTERRUPTIBLE:
            return STATE_STUCK;

        case TH_STATE_STOPPED:
            return STATE_STOP;

        case TH_STATE_HALTED:
            return STATE_HALT;

        case TH_STATE_WAITING:
            return (sleeptime > 0) ? STATE_IDLE : STATE_SLEEP;

        default:
            return STATE_UNKNOWN;
    }
}

static struct kinfo_proc infoForPid(pid_t pid)
{
    kinfo_proc ret;

    std::array<int, 4> mib =
    {
        CTL_KERN,
        KERN_PROC,
        KERN_PROC_PID,
        pid
    };
    size_t len { sizeof(struct kinfo_proc) };

    if (sysctl(mib.data(), mib.size(), &ret, &len, NULL, 0) == -1)
    {
        throw std::system_error
        {
            errno,
            std::system_category(),
            "Error looking up process info by PID."
        };
    }

    return ret;
}

struct DarwinProcessInfo
{
    DarwinProcessInfo(const kinfo_proc& kinfo)
        : name { kinfo.kp_proc.p_comm }
        , state { STATE_UNKNOWN }
        , pid { kinfo.kp_proc.p_pid }
        , ppid { kinfo.kp_eproc.e_ppid  }
        , euid { kinfo.kp_eproc.e_ucred.cr_uid}
        , ruid { kinfo.kp_eproc.e_pcred.p_ruid}
        , rgid { kinfo.kp_eproc.e_pcred.p_rgid}
        , priority { kinfo.kp_proc.p_priority }
        , nice { kinfo.kp_proc.p_nice }
        , virtualMemorySizeKiB {}
        , startTime { kinfo.kp_proc.p_un.__p_starttime.tv_sec  }
    {
        // Get total virtual memory size
        // It is way easier to use proc_pidinfo than to manually compute this number with
        // what we get on kinfo.
        struct proc_taskinfo pti;

        if (sizeof(pti) != proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti)))
        {
            throw std::runtime_error("proc_pidinfo: failed to get process info by pid");
        }

        virtualMemorySizeKiB = pti.pti_virtual_size / 1024;
    }
    // Might return null if the process disappears while retrieving its data.
    nlohmann::json toJson()
    {
        nlohmann::json result{};
        const auto maxBufferSize { sysconf(_SC_GETPW_R_SIZE_MAX) };

        if (maxBufferSize == -1)
        {
            throw std::system_error
            {
                errno,
                std::system_category(),
                "Error getting max buffer size for passwd buffers."
            };
        }

        std::vector<char> buff(maxBufferSize, '\0');
        passwd userInfo;
        group groupInfo;
        // infoPtr will point to "info" if calls to getpwuid_r are successful.
        passwd* userInfoPtr { nullptr };
        group* groupInfoPtr { nullptr };

        result["pid"]        = std::to_string(pid);
        result["name"]       = std::move(name);
        result["state"]      = s_mapTaskInfoState[state];
        result["ppid"]       = ppid;
        result["priority"]   = priority;
        result["nice"]       = nice;
        result["vm_size"]    = virtualMemorySizeKiB;
        result["start_time"] = startTime;

        memset(&userInfo, 0, sizeof userInfo);
        getpwuid_r(euid, &userInfo, buff.data(), buff.size(), &userInfoPtr);

        if (userInfoPtr)
        {
            if (userInfoPtr->pw_name)
            {
                result["euser"]  = userInfoPtr->pw_name;
            }
        }

        memset(&userInfo, 0, sizeof userInfo);
        getpwuid_r(ruid, &userInfo, buff.data(), buff.size(), &userInfoPtr);

        if (userInfoPtr)
        {
            if (userInfoPtr->pw_name)
            {
                result["ruser"]  = userInfoPtr->pw_name;
            }
        }

        memset(&groupInfo, 0, sizeof groupInfo);
        getgrgid_r(rgid, &groupInfo, buff.data(), buff.size(), &groupInfoPtr);

        if (groupInfoPtr)
        {
            if (groupInfoPtr->gr_name)
            {
                result["rgroup"] = groupInfoPtr->gr_name;
            }
        }

        return result;

    }
    std::string name;
    char state;
    pid_t pid;
    pid_t ppid;
    uid_t euid;
    uid_t ruid;
    gid_t rgid;
    int32_t priority = 0;
    int32_t nice = 0;
    uint64_t virtualMemorySizeKiB = 0;
    __darwin_time_t startTime = 0;
};

static std::map<pid_t, DarwinProcessInfo> processesMap;

void SysInfo::getMemory(nlohmann::json& info) const
{
    constexpr auto vmPageSize{"vm.pagesize"};
    constexpr auto vmPageFreeCount{"vm.page_free_count"};
    uint64_t ram{0};
    const std::vector<int> mib{CTL_HW, HW_MEMSIZE};
    size_t len{sizeof(ram)};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &ram, &len, nullptr, 0)};

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading total RAM."
        };
    }

    const auto ramTotal{ram / KByte};
    info["ram_total"] = ramTotal;
    u_int pageSize{0};
    len = sizeof(pageSize);
    ret = sysctlbyname(vmPageSize, &pageSize, &len, nullptr, 0);

    if (ret)
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

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading free pages."
        };
    }

    const auto ramFree{(freePages * pageSize) / KByte};
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

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu frequency."
        };
    }

    return cpuMHz / MHz;
}

std::string SysInfo::getSerialNumber() const
{
    const auto rawData{Utils::exec("system_profiler SPHardwareDataType | grep Serial")};
    return Utils::trim(rawData.substr(rawData.find(":")), " :\t\r\n");
}

static void getPackagesFromPath(const std::string& pkgDirectory, const int pkgType, std::function<void(nlohmann::json&)> callback)
{
    const auto packages { Utils::enumerateDir(pkgDirectory) };

    for (const auto& package : packages)
    {
        if (PKG == pkgType)
        {
            if (Utils::endsWith(package, ".app"))
            {
                nlohmann::json jsPackage;
                FactoryPackageFamilyCreator<OSType::BSDBASED>::create(std::make_pair(PackageContext{pkgDirectory, package, ""}, pkgType))->buildPackageData(jsPackage);

                if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                {
                    // Only return valid content packages
                    callback(jsPackage);
                }
            }
        }
        else if (BREW == pkgType)
        {
            if (!Utils::startsWith(package, "."))
            {
                const auto packageVersions { Utils::enumerateDir(pkgDirectory + "/" + package) };

                for (const auto& version : packageVersions)
                {
                    if (!Utils::startsWith(version, "."))
                    {
                        nlohmann::json jsPackage;
                        FactoryPackageFamilyCreator<OSType::BSDBASED>::create(std::make_pair(PackageContext{pkgDirectory, package, version}, pkgType))->buildPackageData(jsPackage);

                        if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                        {
                            // Only return valid content packages
                            callback(jsPackage);
                        }
                    }
                }
            }
        }

        // else: invalid package
    }
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json jsPackages;
    getPackages([&jsPackages](nlohmann::json & package)
    {
        jsPackages.push_back(package);
    });
    return jsPackages;
}

nlohmann::json SysInfo::getProcessesInfo() const
{
    nlohmann::json jsProcessesList{};

    getProcessesInfo([&jsProcessesList](nlohmann::json & processInfo)
    {
        // Append the current json process object to the list of processes
        jsProcessesList.push_back(processInfo);
    });

    return jsProcessesList;
}

nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts {};
    MacOsParser parser;
    parser.parseSwVersion(Utils::exec("sw_vers"), ret);
    parser.parseUname(Utils::exec("uname -r"), ret);

    if (uname(&uts) >= 0)
    {
        ret["sysname"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["release"] = uts.release;
    }

    return ret;
}

static void getProcessesSocketFD(std::map<ProcessInfo, std::vector<std::shared_ptr<socket_fdinfo>>>& processSocket)
{
    int32_t maxProcess { 0 };
    auto maxProcessLen { sizeof(maxProcess) };

    if (!sysctlbyname("kern.maxproc", &maxProcess, &maxProcessLen, nullptr, 0))
    {
        auto pids { std::make_unique<pid_t[]>(maxProcess) };
        const auto processesCount { proc_listallpids(pids.get(), maxProcess) };

        for (auto i = 0 ; i < processesCount ; ++i)
        {
            const auto pid { pids[i] };

            proc_bsdinfo processInformation {};

            if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &processInformation, PROC_PIDTBSDINFO_SIZE) != -1)
            {
                const std::string processName { processInformation.pbi_name };
                const ProcessInfo processData { pid, processName };

                const auto processFDBufferSize { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0) };

                if (processFDBufferSize != -1)
                {
                    auto processFDInformationBuffer { std::make_unique<char[]>(processFDBufferSize) };

                    if (proc_pidinfo(pid, PROC_PIDLISTFDS, 0, processFDInformationBuffer.get(), processFDBufferSize) != -1)
                    {
                        auto processFDInformation { reinterpret_cast<proc_fdinfo*>(processFDInformationBuffer.get())};

                        for (auto j = 0ul; j < processFDBufferSize / PROC_PIDLISTFD_SIZE; ++j )
                        {
                            if (PROX_FDTYPE_SOCKET == processFDInformation[j].proc_fdtype)
                            {
                                auto socketInfo { std::make_shared<socket_fdinfo>() };

                                if (PROC_PIDFDSOCKETINFO_SIZE == proc_pidfdinfo(pid, processFDInformation[j].proc_fd, PROC_PIDFDSOCKETINFO, socketInfo.get(), PROC_PIDFDSOCKETINFO_SIZE))
                                {
                                    if (socketInfo && std::find(s_validFDSock.begin(), s_validFDSock.end(), socketInfo->psi.soi_kind) != s_validFDSock.end())
                                    {
                                        processSocket[processData].push_back(socketInfo);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

nlohmann::json SysInfo::getPorts() const
{
    nlohmann::json ports;
    std::map<ProcessInfo, std::vector<std::shared_ptr<socket_fdinfo>>> fdMap;
    getProcessesSocketFD(fdMap);

    for (const auto& processInfo : fdMap)
    {
        for (const auto& fdSocket : processInfo.second )
        {
            nlohmann::json port;
            std::make_unique<PortImpl>(std::make_shared<BSDPortWrapper>(processInfo.first, fdSocket))->buildPortData(port);

            const auto portFound
            {
                std::find_if(ports.begin(), ports.end(),
                             [&port](const auto & element)
                {
                    return 0 == port.dump().compare(element.dump());
                })
            };

            if (ports.end() == portFound)
            {
                ports.push_back(port);
            }
        }
    }

    return ports;
}

void SysInfo::getProcessesInfo(std::function<void(nlohmann::json&)> callback) const
{
    // Get the Mach port we will use for all communication with kernel.
    const auto port { mach_host_self() };

    if (!port)
    {
        throw std::runtime_error { "failed to get mach port: not enough permissions" };
    }

    // To iterate through all processes, we need to iterate over all processors sets.
    // Within each processor set we iterate through Mach tasks, discovering any new pids that appear while iterating
    // and creating a ProcessInfo.
    // For each task, we iterate over its threads to establish the overall process state.

    processor_set_name_array_t psets;
    mach_msg_type_number_t  pcnt;
    kern_return_t kr = 0;
    kr = host_processor_sets(port, &psets, &pcnt);

    if (kr != KERN_SUCCESS)
    {
        throw std::runtime_error { "error getting processor sets: " + std::to_string(kr) };
    }

    defer(mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)(uintptr_t)psets, pcnt * sizeof(*psets)));

    for (mach_msg_type_number_t i = 0; i < pcnt; i++)
    {
        processor_set_t pset;
        kr = host_processor_set_priv(port, psets[i], &pset);

        if (kr != KERN_SUCCESS)
        {
            throw std::runtime_error { "processor_set_priv failed" + std::to_string(kr) };
        }

        defer (mach_port_deallocate(mach_task_self(), pset));
        defer (mach_port_deallocate(mach_task_self(), psets[i]));

        // Get tasks from a processor set.
        task_array_t tasks;
        mach_msg_type_number_t taskCount;
        kr = processor_set_tasks(pset, &tasks, &taskCount);

        if (kr != KERN_SUCCESS)
        {
            throw std::runtime_error { "failed to get tasks from processor set" + std::to_string(kr) };
        }

        defer(mach_vm_deallocate(mach_task_self(), reinterpret_cast<mach_vm_address_t>(tasks), taskCount * sizeof(*tasks)));

        for (mach_msg_type_number_t j = 0; j < taskCount; j++)
        {
            const auto& task { tasks[j] };
            defer(mach_port_deallocate(mach_task_self(), task));
            int pid;
            pid_for_task(task, &pid);

            // Check if we already know this pid and create a new ProcessInfo if not.
            auto it = processesMap.find(pid);

            if (it == processesMap.end())
            {
                // Create new process info struct
                auto kinfo {infoForPid(pid)};
                auto insertion { processesMap.emplace(pid, DarwinProcessInfo{kinfo}) };
                it = insertion.first;
            }

            auto& currentProcess { it->second };

            // If the process is in a zombie state, then it has no threads so we don't need to iterate over them.
            if (currentProcess.state != STATE_ZOMBIE)
            {
                thread_act_array_t threads;
                mach_msg_type_number_t threadCount;
                kr = task_threads(task, &threads, &threadCount);

                if (kr != KERN_SUCCESS)
                {
                    throw std::runtime_error{"Failed to get threads of a task: " + std::to_string(kr)};
                }

                // Go through all threads, translating the thread state to a unified process state and take the minimum state value.
                int state = INT_MAX;

                for (mach_msg_type_number_t k = 0; k < threadCount; k++)
                {
                    thread_basic_info_data_t info;
                    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
                    kr = thread_info(threads[k], THREAD_BASIC_INFO, reinterpret_cast<thread_info_t>(&info), &count);

                    if (kr != KERN_SUCCESS)
                    {
                        throw std::runtime_error{"Failed to get thread info: " + std::to_string(kr)};
                    }

                    defer(mach_port_deallocate(mach_task_self(), threads[k]));
                    state = std::min(state, toProcessState(info.run_state, info.sleep_time));
                }

                currentProcess.state = state != INT_MAX ? state : STATE_UNKNOWN;
            }


            auto json = currentProcess.toJson();
            callback(json);
        }

    }

}

void SysInfo::getPackages(std::function<void(nlohmann::json&)> callback) const
{
    for (const auto& packageDirectory : s_mapPackagesDirectories)
    {
        const auto pkgDirectory { packageDirectory.first };

        if (Utils::existsDir(pkgDirectory))
        {
            getPackagesFromPath(pkgDirectory, packageDirectory.second, callback);
        }
    }
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}
