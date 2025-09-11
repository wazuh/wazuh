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
#include <fstream>
#include <iostream>
#include <regex>
#include <sys/utsname.h>
#include "packages/modernPackageDataRetriever.hpp"
#include "sharedDefs.h"
#include "stringHelper.h"
#include <file_io_utils.hpp>
#include <filesystem_wrapper.hpp>
#include "cmdHelper.h"
#include "osinfo/sysOsParsers.h"
#include "sysInfo.hpp"
#include "readproc.h"
#include "networkUnixHelper.h"
#include "networkHelper.h"
#include "network/networkLinuxWrapper.h"
#include "network/networkFamilyDataAFactory.h"
#include "ports/portLinuxWrapper.h"
#include "ports/portImpl.h"
#include "packages/berkeleyRpmDbHelper.h"
#include "packages/packageLinuxDataRetriever.h"
#include "linuxInfoHelper.h"
#include "groups_linux.hpp"
#include "user_groups_linux.hpp"
#include "logged_in_users_linux.hpp"
#include "shadow_linux.hpp"
#include "sudoers_unix.hpp"
#include "users_linux.hpp"
#include "systemd_units_linux.hpp"
#include "chrome.hpp"
#include "firefox.hpp"

using ProcessInfo = std::unordered_map<int64_t, std::pair<int32_t, std::string>>;

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

        while (file.good())
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
    jsProcessInfo["pid"]        = std::to_string(process->tid);
    jsProcessInfo["name"]       = process->cmd;
    jsProcessInfo["state"]      = &process->state;
    jsProcessInfo["parent_pid"] = process->ppid;
    jsProcessInfo["utime"]      = process->utime;
    jsProcessInfo["stime"]      = process->stime;
    std::string commandLine;
    std::string commandLineArgs;
    unsigned int commandLineCount = 0;

    if (process->cmdline && process->cmdline[0])
    {
        commandLine = process->cmdline[0];

        for (int idx = 1; process->cmdline[idx]; ++idx)
        {
            const auto cmdlineArgSize { sizeof(process->cmdline[idx]) };

            if (strnlen(process->cmdline[idx], cmdlineArgSize) != 0)
            {
                commandLineArgs += process->cmdline[idx];

                if (process->cmdline[idx + 1])
                {
                    commandLineArgs += " ";
                }

                commandLineCount++;
            }
        }
    }

    jsProcessInfo["command_line"] = commandLine;
    jsProcessInfo["args"]         = commandLineArgs;
    jsProcessInfo["args_count"]   = commandLineCount;
    jsProcessInfo["start"]        = Utils::timeTick2unixTime(process->start_time);
    return jsProcessInfo;
}

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
        serial = UNKNOWN_VALUE;
    }

    return serial;
}

static std::string getCpuName()
{
    std::string retVal { UNKNOWN_VALUE };
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_CPU_DIR, ":", systemInfo);
    const auto& it { systemInfo.find("model name") };

    if (it != systemInfo.end())
    {
        retVal = it->second;
    }

    return retVal;
}

static int getCpuCores()
{
    int retVal { 0 };
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_CPU_DIR, ":", systemInfo);
    const auto& it { systemInfo.find("processor") };

    if (it != systemInfo.end())
    {
        retVal = std::stoi(it->second) + 1;
    }

    return retVal;
}

static int getCpuMHz()
{
    int retVal { 0 };
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_CPU_DIR, ":", systemInfo);

    const auto& it { systemInfo.find("cpu MHz") };

    if (it != systemInfo.end())
    {
        retVal = std::stoi(it->second) + 1;
    }
    else
    {
        int cpuFreq { 0 };

        const file_system::FileSystemWrapper fileSystemWrapper;
        const auto cpusInfo {fileSystemWrapper.list_directory(WM_SYS_CPU_FREC_DIR)};

        constexpr auto CPU_FREQ_DIRNAME_PATTERN {"cpu[0-9]+"};
        const std::regex cpuDirectoryRegex {CPU_FREQ_DIRNAME_PATTERN};

        for (const auto& cpu : cpusInfo)
        {
            if (std::regex_match(cpu.string(), cpuDirectoryRegex))
            {
                std::fstream file{WM_SYS_CPU_FREC_DIR + cpu.string() + "/cpufreq/cpuinfo_max_freq", std::ios_base::in};

                if (file.is_open())
                {
                    std::string frequency;
                    std::getline(file, frequency);

                    try
                    {
                        cpuFreq = std::stoi(frequency);  // Frequency on KHz

                        if (cpuFreq > retVal)
                        {
                            retVal = cpuFreq;
                        }
                    }
                    catch (...)
                    {
                    }
                }
            }
        }

        retVal /= 1000;  // Convert frequency from KHz to MHz
    }

    return retVal;
}

static void getMemory(nlohmann::json& info)
{
    std::map<std::string, std::string> systemInfo;
    getSystemInfo(WM_SYS_MEM_DIR, ":", systemInfo);

    auto memTotal{ 1ull };
    auto memFree{ 0ull };

    const auto& itTotal { systemInfo.find("MemTotal") };

    if (itTotal != systemInfo.end())
    {
        memTotal = std::stoull(itTotal->second);
    }

    const auto& itAvailable { systemInfo.find("MemAvailable") };
    const auto& itFree { systemInfo.find("MemFree") };

    if (itAvailable != systemInfo.end())
    {
        memFree = std::stoull(itAvailable->second);
    }
    else if (itFree != systemInfo.end())
    {
        memFree = std::stoull(itFree->second);
    }

    const auto ramTotal { memTotal == 0 ? 1 : memTotal };
    info["memory_total"] = ramTotal;
    info["memory_free"] = memFree;
    info["memory_used"] = 100 - (100 * memFree / ramTotal);
}

nlohmann::json SysInfo::getHardware() const
{
    nlohmann::json hardware;
    hardware["serial_number"] = getSerialNumber();
    hardware["cpu_name"] = getCpuName();
    hardware["cpu_cores"] = getCpuCores();
    hardware["cpu_speed"] = double(getCpuMHz());
    getMemory(hardware);
    return hardware;
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json packages;
    getPackages([&packages](nlohmann::json & data)
    {
        packages.push_back(data);
    });
    return packages;
}

static bool getOsInfoFromFiles(nlohmann::json& info)
{
    bool ret{false};
    const std::vector<std::string> UNIX_RELEASE_FILES{"/etc/os-release", "/usr/lib/os-release"};
    constexpr auto CENTOS_RELEASE_FILE{"/etc/centos-release"};
    static const std::vector<std::pair<std::string, std::string>> PLATFORMS_RELEASE_FILES
    {
        {"centos",      CENTOS_RELEASE_FILE     },
        {"fedora",      "/etc/fedora-release"   },
        {"rhel",        "/etc/redhat-release"   },
        {"gentoo",      "/etc/gentoo-release"   },
        {"suse",        "/etc/SuSE-release"     },
        {"arch",        "/etc/arch-release"     },
        {"debian",      "/etc/debian_version"   },
        {"slackware",   "/etc/slackware-version"},
        {"ubuntu",      "/etc/lsb-release"      },
        {"alpine",      "/etc/alpine-release"   },
    };
    const auto parseFnc
    {
        [&info](const std::string & fileName, const std::string & platform)
        {
            std::fstream file{fileName, std::ios_base::in};

            if (file.is_open())
            {
                const auto spParser{FactorySysOsParser::create(platform)};
                return spParser->parseFile(file, info);
            }

            return false;
        }
    };

    for (const auto& unixReleaseFile : UNIX_RELEASE_FILES)
    {
        ret |= parseFnc(unixReleaseFile, "unix");
    }

    if (ret)
    {
        ret |= parseFnc(CENTOS_RELEASE_FILE, "centos");
    }
    else
    {
        for (const auto& platform : PLATFORMS_RELEASE_FILES)
        {
            if (parseFnc(platform.second, platform.first))
            {
                ret = true;
                break;
            }
        }
    }

    return ret;
}

nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts {};

    if (!getOsInfoFromFiles(ret))
    {
        ret["os_name"] = "Linux";
        ret["os_platform"] = "linux";
        ret["os_version"] = UNKNOWN_VALUE;
    }

    if (uname(&uts) >= 0)
    {
        ret["os_kernel_name"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["os_kernel_version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["os_kernel_release"] = uts.release;
    }

    return ret;
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

nlohmann::json SysInfo::getNetworks() const
{
    nlohmann::json networks;

    std::unique_ptr<ifaddrs, Utils::IfAddressSmartDeleter> interfacesAddress;
    std::map<std::string, std::vector<ifaddrs*>> networkInterfaces;
    Utils::NetworkUnixHelper::getNetworks(interfacesAddress, networkInterfaces);

    for (const auto& interface : networkInterfaces)
    {
        nlohmann::json ifaddr {};

        for (auto addr : interface.second)
        {
            const auto networkInterfacePtr { FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(std::make_shared<NetworkLinuxInterface>(addr)) };

            if (networkInterfacePtr)
            {
                networkInterfacePtr->buildNetworkData(ifaddr);
            }
        }

        networks["iface"].push_back(ifaddr);
    }

    return networks;
}


ProcessInfo portProcessInfo(const std::string& procPath, const std::deque<int64_t>& inodes)
{
    ProcessInfo ret;
    auto getProcessName = [](const std::string & filePath) -> std::string
    {
        // Get stat file content.
        std::string processInfo { UNKNOWN_VALUE };
        const file_io::FileIOUtils ioUtils;
        const std::string statContent {ioUtils.getFileContent(filePath)};

        const auto openParenthesisPos {statContent.find("(")};
        const auto closeParenthesisPos {statContent.find(")")};

        if (openParenthesisPos != std::string::npos && closeParenthesisPos != std::string::npos)
        {
            processInfo = statContent.substr(openParenthesisPos + 1, closeParenthesisPos - openParenthesisPos - 1);
        }

        return processInfo;
    };

    auto findInode = [](const std::string & filePath) -> int64_t
    {
        constexpr size_t MAX_LENGTH {256};
        char buffer[MAX_LENGTH] = "";

        if (-1 == readlink(filePath.c_str(), buffer, MAX_LENGTH - 1))
        {
            throw std::system_error(errno, std::system_category(), "readlink");
        }

        // ret format is "socket:[<num>]".
        const std::string bufferStr {buffer};
        const auto openBracketPos {bufferStr.find("[")};
        const auto closeBracketPos {bufferStr.find("]")};
        const auto match {bufferStr.substr(openBracketPos + 1, closeBracketPos - openBracketPos - 1)};

        return std::stoll(match);
    };

    const file_system::FileSystemWrapper fs;

    if (fs.is_directory(procPath))
    {
        auto procFiles = fs.list_directory(procPath);

        // Iterate proc directory.
        for (const auto& procFile : procFiles)
        {
            // Only directories that represent a PID are inspected.
            const std::string procFilePath {procPath / procFile};

            if (Utils::isNumber(procFile) && fs.is_directory(procFilePath))
            {
                // Only fd directory is inspected.
                const std::string pidFilePath {procFilePath + "/fd"};

                if (fs.is_directory(pidFilePath))
                {
                    auto fdFiles = fs.list_directory(pidFilePath);

                    // Iterate fd directory.
                    for (const auto& fdFile : fdFiles)
                    {
                        // Only sysmlinks that represent a socket are read.
                        const std::string fdFilePath {pidFilePath / fdFile};

                        if (!Utils::startsWith(fdFile, ".") && fs.is_socket(fdFilePath))
                        {
                            try
                            {
                                int64_t inode {findInode(fdFilePath)};

                                if (std::any_of(inodes.cbegin(), inodes.cend(), [&](const auto it)
                            {
                                return it == inode;
                            }))
                                {
                                    std::string statPath {procFilePath + "/" + "stat"};
                                    std::string processName = getProcessName(statPath);
                                    int32_t pid { std::stoi(procFile) };

                                    ret.emplace(std::make_pair(inode, std::make_pair(pid, processName)));
                                }
                            }
                            catch (const std::exception& e)
                            {
                                std::cerr << "Error: " << e.what() << std::endl;
                            }
                        }
                    }
                }
            }
        }
    }

    return ret;
}

nlohmann::json SysInfo::getPorts() const
{
    nlohmann::json ports;
    std::deque<int64_t> inodes;

    for (const auto& portType : PORTS_TYPE)
    {
        const file_io::FileIOUtils ioUtils;
        const auto fileContent {ioUtils.getFileContent(WM_SYS_NET_DIR + portType.second)};
        auto rows { Utils::split(fileContent, '\n') };
        auto fileBody { false };

        for (auto& row : rows)
        {
            nlohmann::json port {};

            try
            {
                if (fileBody)
                {
                    row = Utils::trim(row);
                    Utils::replaceAll(row, "\t", " ");
                    row = Utils::trimRepeated(row, ' ');
                    std::make_unique<PortImpl>(std::make_shared<LinuxPortWrapper>(portType.first, row))->buildPortData(port);
                    inodes.push_back(port.at("file_inode"));
                    ports.push_back(std::move(port));
                }

                fileBody = true;
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error while parsing port: " << e.what() << std::endl;
            }
        }
    }


    if (!inodes.empty())
    {
        ProcessInfo ret = portProcessInfo(WM_SYS_PROC_DIR, inodes);

        for (auto& port : ports)
        {
            try
            {
                auto portInode = port.at("file_inode");

                if (ret.find(portInode) != ret.end())
                {
                    std::pair<int32_t, std::string> processInfoPair = ret.at(portInode);
                    port["process_pid"] = processInfoPair.first;
                    port["process_name"] = processInfoPair.second;
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error while parsing process_pid and process_name from ports: " << e.what() << std::endl;
            }
        }
    }

    return ports;
}

void SysInfo::getProcessesInfo(std::function<void(nlohmann::json&)> callback) const
{

    const SysInfoProcessesTable spProcTable
    {
        openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLARG | PROC_FILLGRP | PROC_FILLUSR | PROC_FILLCOM | PROC_FILLENV)
    };

    SysInfoProcess spProcInfo { readproc(spProcTable.get(), nullptr) };

    while (nullptr != spProcInfo)
    {
        // Get process information object and push it to the caller
        auto processInfo = getProcessInfo(spProcInfo);
        callback(processInfo);
        spProcInfo.reset(readproc(spProcTable.get(), nullptr));
    }
}

void SysInfo::getPackages(std::function<void(nlohmann::json&)> callback) const
{
    FactoryPackagesCreator<LINUX_TYPE>::getPackages(callback);
    std::map<std::string, std::set<std::string>> searchPaths =
    {
        {"PYPI", UNIX_PYPI_DEFAULT_BASE_DIRS},
        {"NPM", UNIX_NPM_DEFAULT_BASE_DIRS}
    };

    std::unordered_set<std::string> excludePaths;

    FactoryPackagesCreator<LINUX_TYPE>::getPythonPackages(excludePaths);

    ModernFactoryPackagesCreator<HAS_STDFILESYSTEM>::getPackages(searchPaths, callback, excludePaths);
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}

nlohmann::json SysInfo::getGroups() const
{
    nlohmann::json result;
    GroupsProvider groupsProvider;
    UserGroupsProvider userGroupsProvider;

    auto collectedGroups = groupsProvider.collect({});

    for (auto& group : collectedGroups)
    {
        nlohmann::json groupItem {};

        groupItem["group_id"] = group["gid"];
        groupItem["group_name"] = group["groupname"];
        groupItem["group_description"] = UNKNOWN_VALUE;
        groupItem["group_id_signed"] = group["gid_signed"];
        groupItem["group_uuid"] = UNKNOWN_VALUE;
        groupItem["group_is_hidden"] = 0;

        std::set<gid_t> gids {static_cast<gid_t>(group["gid"].get<int>())};
        auto collectedUsersGroups = userGroupsProvider.getUserNamesByGid(gids);

        if (collectedUsersGroups.empty())
        {
            groupItem["group_users"] = UNKNOWN_VALUE;
        }
        else
        {
            std::string usersConcatenated;

            for (const auto& user : collectedUsersGroups)
            {
                if (!usersConcatenated.empty())
                {
                    usersConcatenated += secondaryArraySeparator;
                }

                usersConcatenated += user.get<std::string>();
            }

            groupItem["group_users"] = usersConcatenated;
        }

        result.push_back(std::move(groupItem));

    }

    return result;
}

nlohmann::json SysInfo::getUsers() const
{
    nlohmann::json result;

    UsersProvider usersProvider;
    auto collectedUsers = usersProvider.collect();

    LoggedInUsersProvider loggedInUserProvider;
    auto collectedLoggedInUser = loggedInUserProvider.collect();

    ShadowProvider shadowProvide;
    auto collectedShadow = shadowProvide.collect();

    UserGroupsProvider userGroupsProvider;

    for (auto& user : collectedUsers)
    {
        nlohmann::json userItem {};

        std::string username = user["username"].get<std::string>();

        userItem["user_id"] = user["uid"];
        userItem["user_full_name"] = user["description"];
        userItem["user_home"] = user["directory"];
        userItem["user_is_remote"] = user["include_remote"];
        userItem["user_name"] = username;
        userItem["user_shell"] = user["shell"];
        userItem["user_uid_signed"] = user["uid_signed"];
        userItem["user_group_id_signed"] = user["gid_signed"];
        userItem["user_group_id"] = user["gid"];

        std::set<uid_t> uid {static_cast<uid_t>(user["uid"].get<int>())};
        auto collectedUsersGroups = userGroupsProvider.getGroupNamesByUid(uid);

        if (collectedUsersGroups.empty())
        {
            userItem["user_groups"] = UNKNOWN_VALUE;
        }
        else
        {
            std::string accumGroups;

            for (const auto& group : collectedUsersGroups)
            {
                if (!accumGroups.empty())
                {
                    accumGroups += secondaryArraySeparator;
                }

                accumGroups += group.get<std::string>();
            }

            userItem["user_groups"] = accumGroups;
        }

        // Only in windows
        userItem["user_type"] = UNKNOWN_VALUE;

        // Macos or windows
        userItem["user_uuid"] = UNKNOWN_VALUE;

        // Macos
        userItem["user_is_hidden"] = 0;
        userItem["user_created"] = 0;
        userItem["user_auth_failed_count"] = 0;
        userItem["user_auth_failed_timestamp"] = 0;

        auto matched = false;
        auto lastLogin = 0;

        userItem["host_ip"] = UNKNOWN_VALUE;

        //TODO: Avoid this iteration, move logic to LoggedInUsersProvider
        for (auto& item : collectedLoggedInUser)
        {
            // By default, user is not logged in.
            userItem["login_status"] = 0;

            // tty,host,time and pid can take more than one value due to different logins.
            if (item["user"] == username)
            {
                matched = true;
                userItem["login_status"] = 1;

                auto newDate = item["time"].get<int32_t>();

                if (newDate > lastLogin)
                {
                    lastLogin = newDate;
                    userItem["user_last_login"] = newDate;
                    userItem["login_tty"] = item["tty"].get<std::string>();
                    userItem["login_type"] = item["type"].get<std::string>();
                    userItem["process_pid"] = item["pid"].get<int32_t>();
                }

                const auto& hostStr = item["host"].get_ref<const std::string&>();

                if (!hostStr.empty())
                {
                    userItem["host_ip"] = userItem["host_ip"].get<std::string>() == UNKNOWN_VALUE
                                          ? hostStr
                                          : (userItem["host_ip"].get<std::string>() + primaryArraySeparator + hostStr);
                }
            }
        }

        if (!matched)
        {
            userItem["login_status"] = 0;
            userItem["login_tty"] = UNKNOWN_VALUE;
            userItem["login_type"] = UNKNOWN_VALUE;
            userItem["process_pid"] = 0;
            userItem["user_last_login"] = 0;
        }

        matched = false;

        for (auto& singleShadow : collectedShadow)
        {
            // If matches user_name, fill the rest of the fields
            if (singleShadow["username"] == username)
            {
                matched = true;
                userItem["user_password_expiration_date"] = singleShadow["expire"];
                userItem["user_password_hash_algorithm"] = singleShadow["hash_alg"];
                userItem["user_password_inactive_days"] = singleShadow["inactive"];
                userItem["user_password_last_change"] = singleShadow["last_change"];
                userItem["user_password_max_days_between_changes"] = singleShadow["max"];
                userItem["user_password_min_days_between_changes"] = singleShadow["min"];
                userItem["user_password_status"] = singleShadow["password_status"];
                userItem["user_password_warning_days_before_expiration"] = singleShadow["warning"];
            }
        }

        if (!matched)
        {
            userItem["user_password_expiration_date"] = 0;
            userItem["user_password_hash_algorithm"] = UNKNOWN_VALUE;
            userItem["user_password_inactive_days"] = 0;
            userItem["user_password_last_change"] = 0;
            userItem["user_password_max_days_between_changes"] = 0;
            userItem["user_password_min_days_between_changes"] = 0;
            userItem["user_password_status"] = UNKNOWN_VALUE;
            userItem["user_password_warning_days_before_expiration"] = 0;
        }


        SudoersProvider sudoersProvider;
        auto collectedSudoers = sudoersProvider.collect();

        // By default, user is not sudoer.
        userItem["user_roles"] = UNKNOWN_VALUE;

        for (auto& singleSudoer : collectedSudoers)
        {
            // Searching in content of header
            auto header = singleSudoer["header"].get<std::string>();

            if (header.find(username) != std::string::npos)
            {
                //TODO: user_roles_sudo_sudo_rule_details has more detailed information.
                userItem["user_roles"] = "sudo";

            }
        }

        result.push_back(std::move(userItem));
    }

    return result;
}

nlohmann::json SysInfo::getServices() const
{
    nlohmann::json result = nlohmann::json::array();

    SystemdUnitsProvider servicesProvider;
    auto collectedServices = servicesProvider.collect();

    for (auto& svc : collectedServices)
    {
        nlohmann::json serviceItem{};

        // ECS mapping based on the provided table
        serviceItem["service_id"]                            = (svc.contains("id") && !svc["id"].get<std::string>().empty()) ? svc["id"] : UNKNOWN_VALUE;
        serviceItem["service_name"]                          = UNKNOWN_VALUE;
        serviceItem["service_description"]                   = svc.value("description",       UNKNOWN_VALUE);
        serviceItem["service_type"]                          = UNKNOWN_VALUE;
        serviceItem["service_state"]                         = svc.value("active_state",      UNKNOWN_VALUE);
        serviceItem["service_sub_state"]                     = svc.value("sub_state",         UNKNOWN_VALUE);
        serviceItem["service_enabled"]                       = svc.value("unit_file_state",   UNKNOWN_VALUE);
        serviceItem["service_start_type"]                    = UNKNOWN_VALUE;
        serviceItem["service_restart"]                       = UNKNOWN_VALUE;
        serviceItem["service_frequency"]                     = 0;
        serviceItem["service_starts_on_mount"]               = 0;
        serviceItem["service_starts_on_path_modified"]       = UNKNOWN_VALUE;
        serviceItem["service_starts_on_not_empty_directory"] = UNKNOWN_VALUE;
        serviceItem["service_inetd_compatibility"]           = 0;
        serviceItem["process_pid"]                           = 0;
        serviceItem["process_executable"]                    = svc.value("fragment_path",     UNKNOWN_VALUE);
        serviceItem["process_args"]                          = UNKNOWN_VALUE;
        serviceItem["process_user_name"]                     = svc.value("user",              UNKNOWN_VALUE);
        serviceItem["process_group_name"]                    = UNKNOWN_VALUE;
        serviceItem["process_working_directory"]             = UNKNOWN_VALUE;
        serviceItem["process_root_directory"]                = UNKNOWN_VALUE;
        serviceItem["file_path"]                             = (svc.contains("source_path") && !svc["source_path"].get<std::string>().empty()) ? svc["source_path"] : UNKNOWN_VALUE;
        serviceItem["service_address"]                       = UNKNOWN_VALUE;
        serviceItem["log_file_path"]                         = UNKNOWN_VALUE;
        serviceItem["error_log_file_path"]                   = UNKNOWN_VALUE;
        serviceItem["service_exit_code"]                     = 0;
        serviceItem["service_win32_exit_code"]               = 0;
        serviceItem["service_following"]                     = svc.value("following",         UNKNOWN_VALUE);
        serviceItem["service_object_path"]                   = svc.value("object_path",       UNKNOWN_VALUE);
        serviceItem["service_target_ephemeral_id"]           = svc.value("job_id",        0);
        serviceItem["service_target_type"]                   = svc.value("job_type",          UNKNOWN_VALUE);
        serviceItem["service_target_address"]                = svc.value("job_path",          UNKNOWN_VALUE);

        result.push_back(std::move(serviceItem));
    }

    return result;
}

nlohmann::json SysInfo::getBrowserExtensions() const
{
    nlohmann::json result = nlohmann::json::array();

    try
    {
        // Collect Chrome extensions
        chrome::ChromeExtensionsProvider chromeProvider;
        auto collectedChromeExtensions = chromeProvider.collect();

        for (auto& ext : collectedChromeExtensions)
        {
            nlohmann::json extensionItem{};

            // Convert string fields to int
            auto stringToInt = [&ext](const std::string & fieldName) -> int
            {
                if (ext.contains(fieldName))
                {
                    try
                    {
                        auto valueStr = ext[fieldName].get<std::string>();
                        return valueStr.empty() ? 0 : std::stoi(valueStr);
                    }
                    catch (const std::exception&)
                    {
                        return 0;
                    }
                }

                return 0;
            };

            extensionItem["browser_name"]              = (ext.contains("browser_type") && !ext["browser_type"].get<std::string>().empty()) ? ext["browser_type"] : UNKNOWN_VALUE;
            extensionItem["user_id"]                   = (ext.contains("uid") && !ext["uid"].get<std::string>().empty()) ? ext["uid"] : UNKNOWN_VALUE;
            extensionItem["package_name"]              = (ext.contains("name") && !ext["name"].get<std::string>().empty()) ? ext["name"] : UNKNOWN_VALUE;
            extensionItem["package_id"]                = ext.value("identifier",          UNKNOWN_VALUE);
            extensionItem["package_version"]           = (ext.contains("version") && !ext["version"].get<std::string>().empty()) ? ext["version"] : UNKNOWN_VALUE;
            extensionItem["package_description"]       = ext.value("description",         UNKNOWN_VALUE);
            extensionItem["package_vendor"]            = ext.value("author",              UNKNOWN_VALUE);
            extensionItem["package_build_version"]     = UNKNOWN_VALUE;
            extensionItem["package_path"]              = ext.value("path",                UNKNOWN_VALUE);
            extensionItem["browser_profile_name"]      = (ext.contains("profile") && !ext["profile"].get<std::string>().empty()) ? ext["profile"] : UNKNOWN_VALUE;
            extensionItem["browser_profile_path"]      = ext.value("profile_path",        UNKNOWN_VALUE);
            extensionItem["package_reference"]         = ext.value("update_url",          UNKNOWN_VALUE);
            extensionItem["package_permissions"]       = ext.value("permissions",         UNKNOWN_VALUE);
            extensionItem["package_type"]              = UNKNOWN_VALUE;

            if (ext.contains("state") && !ext["state"].get<std::string>().empty())
            {
                try
                {
                    int stateValue = std::stoi(ext["state"].get<std::string>());
                    extensionItem["package_enabled"] = (stateValue == 1) ? 1 : 0;
                }
                catch (const std::exception&)
                {
                    extensionItem["package_enabled"] = -1;
                }
            }
            else
            {
                extensionItem["package_enabled"] = -1;
            }

            extensionItem["package_visible"]           = 0;
            extensionItem["package_autoupdate"]        = 0;
            extensionItem["package_persistent"]        = stringToInt("persistent");
            extensionItem["package_from_webstore"]     = stringToInt("from_webstore");
            extensionItem["browser_profile_referenced"] = stringToInt("referenced");
            extensionItem["package_installed"]         = ext.value("install_timestamp",  UNKNOWN_VALUE);
            extensionItem["file_hash_sha256"]          = ext.value("manifest_hash",      UNKNOWN_VALUE);

            result.push_back(std::move(extensionItem));
        }

        // Collect Firefox extensions
        FirefoxAddonsProvider firefoxProvider;
        auto collectedFirefoxExtensions = firefoxProvider.collect();

        for (auto& ext : collectedFirefoxExtensions)
        {
            nlohmann::json extensionItem{};

            extensionItem["browser_name"]              = "firefox";
            extensionItem["user_id"]                   = (ext.contains("uid") && !ext["uid"].get<std::string>().empty()) ? ext["uid"] : UNKNOWN_VALUE;
            extensionItem["package_name"]              = (ext.contains("name") && !ext["name"].get<std::string>().empty()) ? ext["name"] : UNKNOWN_VALUE;
            extensionItem["package_id"]                = ext.value("identifier",          UNKNOWN_VALUE);
            extensionItem["package_version"]           = (ext.contains("version") && !ext["version"].get<std::string>().empty()) ? ext["version"] : UNKNOWN_VALUE;
            extensionItem["package_description"]       = ext.value("description",         UNKNOWN_VALUE);
            extensionItem["package_vendor"]            = ext.value("creator",             UNKNOWN_VALUE);
            extensionItem["package_build_version"]     = UNKNOWN_VALUE;
            extensionItem["package_path"]              = ext.value("path",                UNKNOWN_VALUE);
            extensionItem["browser_profile_name"]      = UNKNOWN_VALUE;
            extensionItem["browser_profile_path"]      = UNKNOWN_VALUE;
            extensionItem["package_reference"]         = ext.value("source_url",          UNKNOWN_VALUE);
            extensionItem["package_permissions"]       = UNKNOWN_VALUE;
            extensionItem["package_type"]              = ext.value("type",                UNKNOWN_VALUE);
            extensionItem["package_enabled"] = ext["disabled"].get<bool>() ? 0 : 1;
            extensionItem["package_visible"] = ext["visible"].get<bool>() ? 1 : 0;
            extensionItem["package_autoupdate"]        = (ext.contains("autoupdate") && ext["autoupdate"].get<bool>()) ? 1 : 0;
            extensionItem["package_persistent"]        = 0;
            extensionItem["package_from_webstore"]     = 0;
            extensionItem["browser_profile_referenced"] = 0;
            extensionItem["package_installed"]         = UNKNOWN_VALUE;
            extensionItem["file_hash_sha256"]          = UNKNOWN_VALUE;

            result.push_back(std::move(extensionItem));
        }
    }
    catch (const std::exception& e)
    {
        // Log error but don't fail completely
    }

    return result;
}
