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
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include <filesystem_wrapper.hpp>
#include "osinfo/sysOsParsers.h"
#include <libproc.h>
#include <pwd.h>
#include <grp.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include "ports/portBSDWrapper.h"
#include "ports/portImpl.h"
#include "packages/packageFamilyDataAFactory.h"
#include "packages/packageMac.h"
#include "hardware/factoryHardwareFamilyCreator.h"
#include "hardware/hardwareWrapperImplMac.h"
#include "osPrimitivesImplMac.h"
#include "sqliteWrapperTemp.h"
#include "packages/modernPackageDataRetriever.hpp"
#include "groups_darwin.hpp"
#include "user_groups_darwin.hpp"
#include "logged_in_users_darwin.hpp"
#include "sudoers_unix.hpp"
#include "users_darwin.hpp"
#include "launchd_darwin.hpp"
#include "chrome.hpp"
#include "safari_darwin.hpp"
#include "firefox.hpp"

const std::string MAC_APPS_PATH{"/Applications"};
const std::string MAC_UTILITIES_PATH{"/Applications/Utilities"};
const std::string MACPORTS_DB_NAME {"registry.db"};
const std::string MACPORTS_QUERY {"SELECT name, version, date, location, archs FROM ports WHERE state = 'installed';"};
constexpr auto MAC_ROSETTA_DEFAULT_ARCH {"arm64"};

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
    { "/private/var/db/receipts", RCP},
    { "/Library/Apple/System/Library/Receipts", RCP},
    { "/usr/local/Cellar", BREW},
    { "/opt/local/var/macports/registry", MACPORTS}
};

static nlohmann::json getProcessInfo(const ProcessTaskInfo& taskInfo, const pid_t pid)
{
    nlohmann::json jsProcessInfo{};
    jsProcessInfo["pid"]        = std::to_string(pid);
    jsProcessInfo["name"]       = taskInfo.pbsd.pbi_name;
    jsProcessInfo["state"]      = UNKNOWN_VALUE;
    jsProcessInfo["parent_pid"] = taskInfo.pbsd.pbi_ppid;
    jsProcessInfo["start"]      = taskInfo.pbsd.pbi_start_tvsec;
    return jsProcessInfo;
}

nlohmann::json SysInfo::getHardware() const
{
    nlohmann::json hardware;
    FactoryHardwareFamilyCreator<OSPlatformType::BSDBASED>::create(std::make_shared<OSHardwareWrapperMac<OsPrimitivesMac>>())->buildHardwareData(hardware);
    return hardware;
}

static void getPackagesFromPath(const std::string& pkgDirectory, const int pkgType, std::function<void(nlohmann::json&)> callback)
{
    const file_system::FileSystemWrapper fs;

    if (MACPORTS == pkgType)
    {
        if (fs.is_regular_file(pkgDirectory + "/" + MACPORTS_DB_NAME))
        {
            try
            {
                std::shared_ptr<SQLite::IConnection> sqliteConnection = std::make_shared<SQLite::Connection>(pkgDirectory + "/" + MACPORTS_DB_NAME);

                SQLite::Statement stmt
                {
                    sqliteConnection,
                    MACPORTS_QUERY
                };

                std::pair<SQLite::IStatement&, const int&> pkgContext {std::make_pair(std::ref(stmt), std::cref(pkgType))};

                while (SQLITE_ROW == stmt.step())
                {
                    try
                    {
                        nlohmann::json jsPackage;
                        FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(pkgContext)->buildPackageData(jsPackage);

                        if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                        {
                            // Only return valid content packages
                            callback(jsPackage);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        std::cerr << e.what() << std::endl;
                    }
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << e.what() << std::endl;
            }
        }
    }
    else
    {
        const auto packages { fs.list_directory(pkgDirectory) };

        for (const auto& package : packages)
        {
            if ((PKG == pkgType && Utils::endsWith(package, ".app")) ||
                    (RCP == pkgType && Utils::endsWith(package, ".plist")))
            {
                try
                {
                    nlohmann::json jsPackage;
                    FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(std::make_pair(PackageContext{pkgDirectory, package, ""}, pkgType))->buildPackageData(jsPackage);

                    if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                    {
                        // Only return valid content packages
                        callback(jsPackage);
                    }
                }
                catch (const std::exception& e)
                {
                    std::cerr << e.what() << std::endl;
                }
            }
            else if (BREW == pkgType)
            {
                if (!Utils::startsWith(package, "."))
                {
                    const auto packageVersions { fs.list_directory(pkgDirectory / package) };

                    for (const auto& version : packageVersions)
                    {
                        if (!Utils::startsWith(version, "."))
                        {
                            try
                            {
                                nlohmann::json jsPackage;
                                FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(std::make_pair(PackageContext{pkgDirectory, package, version}, pkgType))->buildPackageData(jsPackage);

                                if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                                {
                                    // Only return valid content packages
                                    callback(jsPackage);
                                }
                            }
                            catch (const std::exception& e)
                            {
                                std::cerr << e.what() << std::endl;
                            }
                        }
                    }
                }
            }

            // else: invalid package
        }
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

static bool isRunningOnRosetta()
{

    /* Rosetta is a translation process that allows users to run
     *  apps that contain x86_64 instructions on Apple silicon.
     * The sysctl.proc_translated indicates if current process is being translated
     *   from x86_64 to arm64 (1) or not (0).
     * If sysctl.proc_translated flag cannot be found, the current process is
     *  nativally running on x86_64.
     * Ref: https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment
    */
    constexpr auto PROCESS_TRANSLATED {1};
    auto retVal {false};
    auto isTranslated{0};
    auto len{sizeof(isTranslated)};
    const auto result{sysctlbyname("sysctl.proc_translated", &isTranslated, &len, NULL, 0)};

    if (result)
    {
        if (errno != ENOENT)
        {
            throw std::system_error
            {
                result,
                std::system_category(),
                "Error reading rosetta status."
            };
        }
    }
    else
    {
        retVal = PROCESS_TRANSLATED == isTranslated;
    }

    return retVal;
}

nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts {};
    MacOsParser parser;
    parser.parseSwVersion(Utils::exec("sw_vers"), ret);
    parser.parseUname(Utils::exec("uname -r"), ret);

    if (!parser.parseSystemProfiler(Utils::exec("system_profiler SPSoftwareDataType"), ret))
    {
        ret["os_name"] = "macOS";
    }

    if (uname(&uts) >= 0)
    {
        ret["os_kernel_name"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["os_kernel_version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["os_kernel_release"] = uts.release;
    }

    if (isRunningOnRosetta())
    {
        ret["architecture"] = MAC_ROSETTA_DEFAULT_ARCH;
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
    int32_t maxProc{};
    size_t len { sizeof(maxProc) };
    const auto ret { sysctlbyname("kern.maxproc", &maxProc, &len, NULL, 0) };

    if (ret)
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

    for (int index = 0; index < processesCount; ++index)
    {
        ProcessTaskInfo taskInfo{};
        const auto pid { spPids.get()[index] };
        const auto sizeTask
        {
            proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &taskInfo, PROC_PIDTASKALLINFO_SIZE)
        };

        if (PROC_PIDTASKALLINFO_SIZE == sizeTask)
        {
            auto processInfo = getProcessInfo(taskInfo, pid);
            callback(processInfo);
        }
    }
}

void SysInfo::getPackages(std::function<void(nlohmann::json&)> callback) const
{
    const file_system::FileSystemWrapper fs;

    for (const auto& packageDirectory : s_mapPackagesDirectories)
    {
        const auto pkgDirectory { packageDirectory.first };

        if (fs.is_directory(pkgDirectory))
        {
            getPackagesFromPath(pkgDirectory, packageDirectory.second, callback);
        }
    }

    // Add all the unix default paths
    std::set<std::string> pypyMacOSPaths =
    {
        UNIX_PYPI_DEFAULT_BASE_DIRS.begin(),
        UNIX_PYPI_DEFAULT_BASE_DIRS.end()
    };

    // Add macOS specific paths
    pypyMacOSPaths.emplace("/Library/Python/*/*-packages");
    pypyMacOSPaths.emplace("/Users/*/Library/Python/*/lib/python/*-packages");
    pypyMacOSPaths.emplace("/Users/*/.pyenv/versions/*/lib/python*/*-packages");
    pypyMacOSPaths.emplace("/private/var/root/.pyenv/versions/*/lib/python*/*-packages");
    pypyMacOSPaths.emplace(
        "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*/lib/python*/*-packages");
    pypyMacOSPaths.emplace("/System/Library/Frameworks/Python.framework/*-packages");
    pypyMacOSPaths.emplace("/opt/homebrew/lib/python*/*-packages");

    static const std::map<std::string, std::set<std::string>> searchPaths =
    {
        {"PYPI", pypyMacOSPaths},
        {"NPM", UNIX_NPM_DEFAULT_BASE_DIRS}
    };
    ModernFactoryPackagesCreator<HAS_STDFILESYSTEM>::getPackages(searchPaths, callback);
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

    // Collect all the GIDs
    std::set<gid_t> allGids;

    for (auto& group : collectedGroups)
    {
        allGids.insert(static_cast<gid_t>(group["gid"].get<int>()));
    }

    // Single call to getUserNamesByGid with all GIDs
    auto allUsersGroups = userGroupsProvider.getUserNamesByGid(allGids);

    // Process each group
    for (auto& group : collectedGroups)
    {
        nlohmann::json groupItem {};
        gid_t currentGid = static_cast<gid_t>(group["gid"].get<int>());

        groupItem["group_id"] = group["gid"];
        groupItem["group_name"] = group["groupname"];
        groupItem["group_description"] = group["comment"];
        groupItem["group_id_signed"] = group["gid_signed"];
        groupItem["group_uuid"] = UNKNOWN_VALUE;
        groupItem["group_is_hidden"] = group["is_hidden"];

        // Obtain the users for this specific GID
        auto gidStr = std::to_string(currentGid);
        nlohmann::json collectedUsersGroups = allUsersGroups.contains(gidStr) ?
                                              allUsersGroups[gidStr] : nlohmann::json::array();

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

    SudoersProvider sudoersProvider;
    auto collectedSudoers = sudoersProvider.collect();

    UserGroupsProvider userGroupsProvider;

    for (auto& user : collectedUsers)
    {
        nlohmann::json userItem {};

        std::string username = user["username"].get<std::string>();

        userItem["user_id"] = user["uid"];
        userItem["user_full_name"] = user["description"];
        userItem["user_home"] = user["directory"];
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

        // Macos
        userItem["user_password_last_change"] = user["password_last_set_time"];
        userItem["user_is_hidden"] = user["is_hidden"];
        userItem["user_created"] = user["creation_time"];
        userItem["user_auth_failed_count"] = user["failed_login_count"];
        userItem["user_auth_failed_timestamp"] = user["failed_login_timestamp"];
        // Macos or windows
        userItem["user_uuid"] = user["uuid"];

        // Only in windows
        userItem["user_type"] = UNKNOWN_VALUE;

        // Only in Linux
        userItem["user_is_remote"] = 0;

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

        userItem["user_password_expiration_date"] = 0;
        userItem["user_password_hash_algorithm"] = UNKNOWN_VALUE;
        userItem["user_password_inactive_days"] = 0;
        userItem["user_password_max_days_between_changes"] = 0;
        userItem["user_password_min_days_between_changes"] = 0;
        userItem["user_password_status"] = UNKNOWN_VALUE;
        userItem["user_password_warning_days_before_expiration"] = 0;

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

    LaunchdProvider servicesProvider{nullptr};
    auto collectedServices = servicesProvider.collect();

    for (auto& svc : collectedServices)
    {
        nlohmann::json serviceItem{};

        // Convert string fields to int
        auto stringToInt = [&svc](const std::string & fieldName) -> int
        {
            if (svc.contains(fieldName))
            {
                try
                {
                    auto valueStr = svc[fieldName].get<std::string>();
                    return valueStr.empty() ? 0 : std::stoi(valueStr);
                }
                catch (const std::exception&)
                {
                    return 0;
                }
            }

            return 0;
        };

        // ECS mapping based on the provided table
        serviceItem["service_id"]           = (svc.contains("label") && !svc["label"].get<std::string>().empty()) ? svc["label"] : UNKNOWN_VALUE;
        serviceItem["service_name"]         = svc.value("name",         UNKNOWN_VALUE);
        serviceItem["service_description"]  = UNKNOWN_VALUE;
        serviceItem["service_type"]         = svc.value("process_type", UNKNOWN_VALUE);
        serviceItem["service_state"]        = UNKNOWN_VALUE;
        serviceItem["service_sub_state"]    = UNKNOWN_VALUE;

        if (svc.contains("disabled"))
        {
            auto disabledValue = svc["disabled"].get<std::string>();

            if (disabledValue == "0")
            {
                serviceItem["service_enabled"] = "1";
            }
            else if (disabledValue == "1")
            {
                serviceItem["service_enabled"] = "0";
            }
            else
            {
                serviceItem["service_enabled"] = UNKNOWN_VALUE;
            }
        }
        else
        {
            serviceItem["service_enabled"] = UNKNOWN_VALUE;
        }

        serviceItem["service_start_type"]                    = svc.value("run_at_load",         UNKNOWN_VALUE);
        serviceItem["service_restart"]                       = svc.value("keep_alive",          UNKNOWN_VALUE);
        serviceItem["service_frequency"]                     = stringToInt("start_interval");
        serviceItem["service_starts_on_mount"]               = stringToInt("start_on_mount");
        serviceItem["service_starts_on_path_modified"]       = svc.value("watch_paths",         UNKNOWN_VALUE);
        serviceItem["service_starts_on_not_empty_directory"] = svc.value("queue_directories",   UNKNOWN_VALUE);
        serviceItem["service_inetd_compatibility"]           = stringToInt("inetd_compatibility");
        serviceItem["process_pid"]                           = 0;
        serviceItem["process_executable"]                    = svc.value("program",             UNKNOWN_VALUE);
        serviceItem["process_args"]                          = svc.value("program_arguments",   UNKNOWN_VALUE);
        serviceItem["process_user_name"]                     = svc.value("username",            UNKNOWN_VALUE);
        serviceItem["process_group_name"]                    = svc.value("groupname",           UNKNOWN_VALUE);
        serviceItem["process_working_directory"]             = svc.value("working_directory",   UNKNOWN_VALUE);
        serviceItem["process_root_directory"]                = svc.value("root_directory",      UNKNOWN_VALUE);
        serviceItem["file_path"]                             = (svc.contains("path") && !svc["path"].get<std::string>().empty()) ? svc["path"] : UNKNOWN_VALUE;
        serviceItem["service_address"]                       = UNKNOWN_VALUE;
        serviceItem["log_file_path"]                         = svc.value("stdout_path",         UNKNOWN_VALUE);
        serviceItem["error_log_file_path"]                   = svc.value("stderr_path",         UNKNOWN_VALUE);
        serviceItem["service_exit_code"]                     = 0;
        serviceItem["service_win32_exit_code"]               = 0;
        serviceItem["service_following"]                     = UNKNOWN_VALUE;
        serviceItem["service_object_path"]                   = UNKNOWN_VALUE;
        serviceItem["service_target_ephemeral_id"]           = 0;
        serviceItem["service_target_type"]                   = UNKNOWN_VALUE;
        serviceItem["service_target_address"]                = UNKNOWN_VALUE;

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

        // Collect Safari extensions
        SafariExtensionsProvider safariProvider;
        auto collectedSafariExtensions = safariProvider.collect();

        for (auto& ext : collectedSafariExtensions)
        {
            nlohmann::json extensionItem{};

            extensionItem["browser_name"]              = "safari";
            extensionItem["user_id"]                   = (ext.contains("uid") && !ext["uid"].get<std::string>().empty()) ? ext["uid"] : UNKNOWN_VALUE;
            extensionItem["package_name"]              = (ext.contains("name") && !ext["name"].get<std::string>().empty()) ? ext["name"] : UNKNOWN_VALUE;
            extensionItem["package_id"]                = ext.value("identifier",          UNKNOWN_VALUE);
            extensionItem["package_version"]           = (ext.contains("version") && !ext["version"].get<std::string>().empty()) ? ext["version"] : UNKNOWN_VALUE;
            extensionItem["package_description"]       = ext.value("description",         UNKNOWN_VALUE);
            extensionItem["package_vendor"]            = ext.value("copyright",           UNKNOWN_VALUE);
            extensionItem["package_build_version"]     = ext.value("bundle_version",      UNKNOWN_VALUE);
            extensionItem["package_path"]              = ext.value("path",                UNKNOWN_VALUE);
            extensionItem["browser_profile_name"]      = UNKNOWN_VALUE;
            extensionItem["browser_profile_path"]      = UNKNOWN_VALUE;
            extensionItem["package_reference"]         = UNKNOWN_VALUE;
            extensionItem["package_permissions"]       = UNKNOWN_VALUE;
            extensionItem["package_type"]              = UNKNOWN_VALUE;
            extensionItem["package_enabled"]           = 1;
            extensionItem["package_visible"]            = 0;
            extensionItem["package_autoupdate"]        = 0;
            extensionItem["package_persistent"]        = 0;
            extensionItem["package_from_webstore"]     = 0;
            extensionItem["browser_profile_referenced"] = 0;
            extensionItem["package_installed"]         = UNKNOWN_VALUE;
            extensionItem["file_hash_sha256"]          = UNKNOWN_VALUE;

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
            extensionItem["package_enabled"]           = ext["disabled"].get<bool>() ? 0 : 1;
            extensionItem["package_visible"]            = ext["visible"].get<bool>() ? 1 : 0;
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
