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
#include "filesystemHelper.h"
#include "filesystemHelperMac.h"
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
#include "packages/pkgWrapper.h"
#include "hardware/factoryHardwareFamilyCreator.h"
#include "hardware/hardwareWrapperImplMac.h"
#include "osPrimitivesImplMac.h"
#include "sqliteWrapperTemp.h"

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
    { "/Library", PKG },
    { "/System/Applications", PKG },
    { "/System/Library", PKG },
    { "/Users", PKG },
    { "/Library/Apple/System/Library/Receipts", RCP },
    { "/private/var/db/receipts", RCP },
    { "/usr/local/Cellar", BREW },
    { "/opt/local/var/macports/registry", MACPORTS}
};

static nlohmann::json getProcessInfo(const ProcessTaskInfo& taskInfo, const pid_t pid)
{
    nlohmann::json jsProcessInfo{};
    jsProcessInfo["pid"]        = std::to_string(pid);
    jsProcessInfo["name"]       = taskInfo.pbsd.pbi_name;

    jsProcessInfo["state"]      = UNKNOWN_VALUE;
    jsProcessInfo["ppid"]       = taskInfo.pbsd.pbi_ppid;

    const auto eUser { getpwuid(taskInfo.pbsd.pbi_uid) };

    if (eUser)
    {
        jsProcessInfo["euser"]  = eUser->pw_name;
    }

    const auto rUser { getpwuid(taskInfo.pbsd.pbi_ruid) };

    if (rUser)
    {
        jsProcessInfo["ruser"]  = rUser->pw_name;
    }

    const auto rGroup { getgrgid(taskInfo.pbsd.pbi_rgid) };

    if (rGroup)
    {
        jsProcessInfo["rgroup"] = rGroup->gr_name;
    }

    jsProcessInfo["priority"]   = taskInfo.ptinfo.pti_priority;
    jsProcessInfo["nice"]       = taskInfo.pbsd.pbi_nice;
    jsProcessInfo["vm_size"]    = taskInfo.ptinfo.pti_virtual_size / KByte;
    jsProcessInfo["start_time"] = taskInfo.pbsd.pbi_start_tvsec;
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
    switch (pkgType)
    {
        case PKG:
            {
                std::function<void(const std::string&)> pkgAnalizeDirectory;

                pkgAnalizeDirectory =
                    [&](const std::string & directory)
                {
                    const auto subDirectories { Utils::enumerateDirTypeDir(directory) };

                    for (const auto& subDirectory : subDirectories)
                    {
                        if ((subDirectory == ".") || (subDirectory == ".."))
                        {
                            continue;
                        }

                        if (Utils::endsWith(subDirectory, ".app") || Utils::endsWith(subDirectory, ".service"))
                        {
                            std::string pathInfoPlist { directory + "/" + subDirectory + "/" + PKGWrapper::INFO_PLIST_PATH };

                            try
                            {
                                nlohmann::json jsPackage;
                                FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(std::make_pair(PackageContext{directory, subDirectory, ""}, PKG))->buildPackageData(jsPackage);

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

                        std::string pathSubDirectory { directory + "/" + subDirectory };
                        pkgAnalizeDirectory(pathSubDirectory);
                    }
                };

                pkgAnalizeDirectory(pkgDirectory);
                break;
            }

        case RCP:
            {
                static auto isInPKGDirectory
                {
                    [](const std::string & plistDirectory)
                    {
                        for (const auto& packagesDirectory : s_mapPackagesDirectories)
                        {
                            if (packagesDirectory.second == RCP && Utils::startsWith(plistDirectory, packagesDirectory.first))
                            {
                                return false;
                            }
                        }

                        for (const auto& packagesDirectory : s_mapPackagesDirectories)
                        {
                            if (packagesDirectory.second == PKG && Utils::startsWith(plistDirectory, packagesDirectory.first))
                            {
                                return true;
                            }
                        }

                        return false;
                    }
                };

                const auto files { Utils::enumerateDirTypeRegular(pkgDirectory) };

                for (const auto& file : files)
                {
                    if (Utils::endsWith(file, ".plist"))
                    {
                        std::string package { Utils::substrOnFirstOccurrence(file, ".plist") };

                        try
                        {
                            nlohmann::json jsPackage;
                            FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(std::make_pair(PackageContext{pkgDirectory, package, ""}, RCP))->buildPackageData(jsPackage);

                            if (!jsPackage.at("name").get_ref<const std::string&>().empty() &&
                                    !jsPackage.at("location").get_ref<const std::string&>().empty() &&
                                    !isInPKGDirectory(jsPackage.at("location").get_ref<const std::string&>())
                               )
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

                break;
            }

        case BREW:
            {
                const auto packages { Utils::enumerateDir(pkgDirectory) };

                for (const auto& package : packages)
                {
                    if (!Utils::startsWith(package, "."))
                    {
                        const auto packageVersions { Utils::enumerateDir(pkgDirectory + "/" + package) };

                        for (const auto& version : packageVersions)
                        {
                            if (!Utils::startsWith(version, "."))
                            {
                                nlohmann::json jsPackage;
                                FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(std::make_pair(PackageContext{pkgDirectory, package, version}, pkgType))->buildPackageData(jsPackage);

                                if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                                {
                                    // Only return valid content packages
                                    callback(jsPackage);
                                }
                            }
                        }
                    }
                }

                break;
            }

        case MACPORTS:
            {
                if (Utils::existsRegular(pkgDirectory + "/" + MACPORTS_DB_NAME))
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

                break;
            }

        default:
            throw std::runtime_error
            {
                "Unsupported pkgType argument"
            };
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
        ret["sysname"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["release"] = uts.release;
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
