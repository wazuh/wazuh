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

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <memory>
#include <list>
#include <set>
#include <system_error>
#include <versionhelpers.h>
#include "sysinfoapi.h"
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "registryHelper.h"
#include "defs.h"
#include "debug_op.h"

constexpr auto BASEBOARD_INFORMATION_TYPE{2};
constexpr auto CENTRAL_PROCESSOR_REGISTRY{"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"};
const std::string UNINSTALL_REGISTRY{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"};
constexpr auto WIN_REG_HOTFIX{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"};
constexpr auto VISTA_REG_HOTFIX{"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix"};
constexpr auto SYSTEM_IDLE_PROCESS_NAME{"System Idle Process"};
constexpr auto SYSTEM_PROCESS_NAME{"System"};

struct CharDeleter
{
    void operator()(char* buffer)
    {
        free(buffer);
    }
};

static bool isVistaOrLater()
{
    static const bool ret
    {
        IsWindowsVistaOrGreater()
    };
    return ret;
}

class SysInfoProcess final
{
public:
    SysInfoProcess(const DWORD pId)
        : m_pId{ pId },
          m_hProcess{ OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_pId) },
          m_kernelModeTime{},
          m_userModeTime{}
    {
        if (m_hProcess)
        {
            setProcessTimes();
            setProcessMemInfo();
        }
        // else: Unable to open current process
    }

    ~SysInfoProcess()
    {
        CloseHandle(m_hProcess);
    }

    std::string cmd()
    {
        std::string ret { "unknown" };
        std::string path;
        const auto spReadBuff { std::make_unique<char[]>(OS_MAXSTR) };
        // Get full Windows kernel path for the process
        if (spReadBuff && GetProcessImageFileName(m_hProcess, spReadBuff.get(), OS_MAXSTR))
        {
            // Convert Windows kernel path to a valid Win32 filepath
            // E.g.: "\Device\HarddiskVolume1\Windows\system32\notepad.exe" -> "C:\Windows\system32\notepad.exe"
            ntPath2Win32Path(spReadBuff.get(), ret);
        }
        // else: Unable to retrieve executable path from current process.
        return ret;
    }

    ULONGLONG kernelModeTime() const
    {
        return m_kernelModeTime.QuadPart;
    }

    ULONGLONG userModeTime() const
    {
        return m_userModeTime.QuadPart;
    }

    DWORD pageFileUsage() const
    {
        return m_pageFileUsage;
    }

    DWORD virtualSize() const
    {
        return m_virtualSize;
    }

    DWORD sessionId() const
    {
        DWORD ret{};
        if (!ProcessIdToSessionId(m_pId, &ret))
        {
            // Unable to retrieve session ID from current process.
        }
        return ret;
    }

private:
    using SystemDrivesMap  = std::map<std::string, std::string>;

    void setProcessTimes()
    {
        constexpr auto s_toSecondsValue { 10000000ULL };
        FILETIME lpCreationTime{};
        FILETIME lpExitTime{};
        FILETIME lpKernelTime{};
        FILETIME lpUserTime{};
        if (GetProcessTimes(m_hProcess, &lpCreationTime, &lpExitTime, &lpKernelTime, &lpUserTime))
        {
            // Copy the kernel mode filetime high and low parts and convert it to seconds
            m_kernelModeTime.LowPart = lpKernelTime.dwLowDateTime;
            m_kernelModeTime.HighPart = lpKernelTime.dwHighDateTime;
            m_kernelModeTime.QuadPart /= s_toSecondsValue;

            // Copy the user mode filetime high and low parts and convert it to seconds
            m_userModeTime.LowPart = lpUserTime.dwLowDateTime;
            m_userModeTime.HighPart = lpUserTime.dwHighDateTime;
            m_userModeTime.QuadPart /= s_toSecondsValue;
        }
        // else: Unable to retrieve kernel mode and user mode times from current process.
    }

    void setProcessMemInfo()
    {
        PROCESS_MEMORY_COUNTERS pMemCounters{};
        // Get page file usage and virtual size
        // Reference: https://stackoverflow.com/a/1986486
        if (GetProcessMemoryInfo(m_hProcess, &pMemCounters, sizeof(pMemCounters)))
        {
            m_pageFileUsage = pMemCounters.PagefileUsage;
            m_virtualSize   = pMemCounters.WorkingSetSize + pMemCounters.PagefileUsage;
        }
        // else: Unable to retrieve page file usage from current process
    }

    static SystemDrivesMap getNtWin32DrivesMap()
    {
        SystemDrivesMap ret;

        // Get the total amount of available logical drives
        // The input size must not include the NULL terminator
        auto spLogicalDrives { std::make_unique<char[]>(OS_MAXSTR) };
        auto res { GetLogicalDriveStrings(OS_MAXSTR - 1, spLogicalDrives.get()) };
        if (res <= 0 || res > OS_MAXSTR)
        {
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to parse logical drive strings."
            };
        }

        const auto logicalDrives { Utils::splitNullTerminatedStrings(spLogicalDrives.get()) };
        for(const auto& logicalDrive : logicalDrives)
        {
            const auto spDosDevice { std::make_unique<char[]>(OS_MAXSTR) };
            res = QueryDosDevice(logicalDrive.c_str(), spDosDevice.get(), OS_MAXSTR);
            if (res)
            {
                // Make the NT Path <-> DOS Path mapping
                ret[spDosDevice.get()] = logicalDrive;
            }
        }
        return ret;
    }

    bool fillOutput(const SystemDrivesMap& drivesMap, const std::string& ntPath, std::string& outbuf)
    {
        bool ret { false };
        const auto it
        {
            std::find_if(drivesMap.begin(), drivesMap.end(),
                [&ntPath](const auto& key) -> bool
                {
                    return Utils::startsWith(ntPath, key.first);
                })
        };

        if (it != drivesMap.end())
        {
            outbuf = it->second + ntPath.substr(it->first.size()+1);
            ret = true;
        }

        return ret;
    }

    void ntPath2Win32Path(const std::string& ntPath, std::string& outbuf)
    {
        static SystemDrivesMap s_drivesMap { getNtWin32DrivesMap() };
        if (!fillOutput(s_drivesMap, ntPath, outbuf))
        {
            s_drivesMap = getNtWin32DrivesMap();
            if(!fillOutput(s_drivesMap, ntPath, outbuf))
            {
                // If after re-fill the drives map DOS drive is not found, NTPath path will
                // be returned.
                outbuf = ntPath;
            }
        }
    }

    const DWORD     m_pId;
    HANDLE          m_hProcess;
    ULARGE_INTEGER  m_kernelModeTime;
    ULARGE_INTEGER  m_userModeTime;
    DWORD           m_pageFileUsage;
    DWORD           m_virtualSize;
};

typedef struct RawSMBIOSData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Length;
    BYTE    SMBIOSTableData[];
} RawSMBIOSData, *PRawSMBIOSData;

typedef struct SMBIOSStructureHeader
{
    BYTE Type;
    BYTE FormattedAreaLength;
    WORD Handle;
} SMBIOSStructureHeader;

typedef struct SMBIOSBasboardInfoStructure
{
    BYTE Type;
    BYTE FormattedAreaLength;
    WORD Handle;
    BYTE Manufacturer;
    BYTE Product;
    BYTE Version;
    BYTE SerialNumber;
} SMBIOSBasboardInfoStructure;

/* Reference: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.6.0.pdf */
static std::string parseRawSmbios(const BYTE* rawData, const DWORD rawDataSize)
{
    std::string serialNumber;
    DWORD offset{0};
    while (offset < rawDataSize && serialNumber.empty())
    {
        SMBIOSStructureHeader header{};
        memcpy(&header, rawData + offset, sizeof(SMBIOSStructureHeader));
        if (BASEBOARD_INFORMATION_TYPE == header.Type)
        {
            SMBIOSBasboardInfoStructure info{};
            memcpy(&info, rawData + offset, sizeof(SMBIOSBasboardInfoStructure));
            offset += info.FormattedAreaLength;
            for (BYTE i = 1; i < info.SerialNumber; ++i)
            {
                const char* tmp{reinterpret_cast<const char*>(rawData + offset)};
                const auto len{ strlen(tmp) };
                offset += len + sizeof(char);
            }
            serialNumber = reinterpret_cast<const char*>(rawData + offset);
        }
        else
        {
            offset += header.FormattedAreaLength;
            bool end{false};
            while(!end)
            {
                const char* tmp{reinterpret_cast<const char*>(rawData + offset)};
                const auto len{strlen(tmp)};
                offset += len + sizeof(char);
                end = !len;
            }
        }
    }
    return serialNumber;
}

static bool isSystemProcess(const DWORD pid)
{
    return pid == 0 || pid == 4;
}

static std::string processName(const PROCESSENTRY32& processEntry)
{
    std::string ret;
    const DWORD pId { processEntry.th32ProcessID };
    if (isSystemProcess(pId))
    {
        ret = (pId == 0) ? SYSTEM_IDLE_PROCESS_NAME : SYSTEM_PROCESS_NAME;
    }
    else
    {
        ret = processEntry.szExeFile;
    }
    return ret;
}

typedef UINT (WINAPI *GetSystemFirmwareTable_t)(DWORD, DWORD, PVOID, DWORD);
static GetSystemFirmwareTable_t getSystemFirmwareTableFunctionAddress()
{
    GetSystemFirmwareTable_t ret{nullptr};
    auto hKernel32{LoadLibrary("kernel32.dll")};
    if (hKernel32)
    {
        ret = reinterpret_cast<GetSystemFirmwareTable_t>(GetProcAddress(hKernel32, "GetSystemFirmwareTable"));
        FreeLibrary(hKernel32);
    }
    return ret;
}

static nlohmann::json getProcessInfo(const PROCESSENTRY32& processEntry)
{
    nlohmann::json jsProcessInfo{};
    const DWORD pId { processEntry.th32ProcessID };
    SysInfoProcess process(pId);

    // Current process information
    jsProcessInfo["name"]       = processName(processEntry);
    jsProcessInfo["cmd"]        = (isSystemProcess(pId)) ? "none" : process.cmd();
    jsProcessInfo["stime"]      = process.kernelModeTime();
    jsProcessInfo["size"]       = process.pageFileUsage();
    jsProcessInfo["ppid"]       = processEntry.th32ParentProcessID;
    jsProcessInfo["priority"]   = processEntry.pcPriClassBase;
    jsProcessInfo["pid"]        = pId;
    jsProcessInfo["session"]    = process.sessionId();
    jsProcessInfo["nlwp"]       = processEntry.cntThreads;
    jsProcessInfo["utime"]      = process.userModeTime();
    jsProcessInfo["vm_size"]    = process.virtualSize();
    return jsProcessInfo;
}

static void getPackagesFromReg(const HKEY key, const std::string& subKey, nlohmann::json& data, const REGSAM access = 0)
{
    try
    {
        Utils::Registry root{key, subKey, access | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
        const auto packages{root.enumerate()};
        for (const auto& package : packages)
        {
            std::string value;
            nlohmann::json packageJson;
            Utils::Registry packageReg{key, subKey + "\\" + package, access | KEY_READ};
            if (packageReg.string("DisplayName", value))
            {
                packageJson["name"] = value;
            }
            if (packageReg.string("DisplayVersion", value))
            {
                packageJson["version"] = value;
            }
            if (packageReg.string("Publisher", value))
            {
                packageJson["vendor"] = value;
            }
            if (packageReg.string("InstallDate", value))
            {
                packageJson["install_time"] = value;
            }
            if (packageReg.string("InstallLocation", value))
            {
                packageJson["location"] = value;
            }
            if (!packageJson.empty())
            {
                if (access & KEY_WOW64_32KEY)
                {
                    packageJson["architecture"] = "i686";
                }
                else if (access & KEY_WOW64_64KEY)
                {
                    packageJson["architecture"] = "x86_64";
                }
                else
                {
                    packageJson["architecture"] = "unknown";
                }
                data.push_back(packageJson);
            }
        }
    }
    catch(...)
    {
    }
}

static void getHotFixFromReg(const HKEY key, const std::string& subKey, nlohmann::json& data)
{
    try
    {
        std::set<std::string> hotfixes;
        Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
        const auto packages{root.enumerate()};
        for (const auto& package : packages)
        {
            if (Utils::startsWith(package, "Package_"))
            {
                std::string value;
                Utils::Registry packageReg{key, subKey + "\\" + package, KEY_WOW64_64KEY | KEY_READ};
                if (packageReg.string("InstallLocation", value))
                {
                    value = Utils::toUpperCase(value);
                    const auto start{value.find("KB")};
                    if (start != std::string::npos)
                    {
                        value = value.substr(start);
                        const auto end{value.find("-")};
                        value = value.substr(0, end);
                        hotfixes.insert(value);
                    }
                }
            }
        }
        for (const auto& hotfix : hotfixes)
        {
            data.push_back({{"hotfix", hotfix}});
        }
    }
    catch(...)
    {
    }
}

static void getHotFixFromRegNT(const HKEY key, const std::string& subKey, nlohmann::json& data)
{
    static const std::string KB_PREFIX{"KB"};
    static const auto KB_PREFIX_SIZE{KB_PREFIX.size()};
    try
    {
        std::set<std::string> hotfixes;
        Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
        const auto packages{root.enumerate()};
        for (const auto& package : packages)
        {
            auto value{Utils::toUpperCase(package)};
            if (Utils::startsWith(value, KB_PREFIX))
            {
                value = value.substr(KB_PREFIX_SIZE);
                value = Utils::trim(value.substr(0, value.find_first_not_of("1234567890")));
                hotfixes.insert(KB_PREFIX + value);
            }
        }
        for (const auto& hotfix : hotfixes)
        {
            data.push_back({{"hotfix", hotfix}});
        }
    }
    catch(...)
    {
    }
}

std::string SysInfo::getSerialNumber() const
{
    std::string ret;
    if (isVistaOrLater())
    {
        static auto pfnGetSystemFirmwareTable{getSystemFirmwareTableFunctionAddress()};
        if (pfnGetSystemFirmwareTable)
        {
            const auto size {pfnGetSystemFirmwareTable('RSMB', 0, nullptr, 0)};
            if (size)
            {
                const auto spBuff{std::make_unique<unsigned char[]>(size)};
                if (spBuff)
                {
                    /* Get raw SMBIOS firmware table */
                    if (pfnGetSystemFirmwareTable('RSMB', 0, spBuff.get(), size) == size)
                    {
                        PRawSMBIOSData smbios{reinterpret_cast<PRawSMBIOSData>(spBuff.get())};
                        /* Parse SMBIOS structures */
                        ret = parseRawSmbios(smbios->SMBIOSTableData, size);
                    }
                }
            }
        }
    }
    else
    {
        const auto rawData{Utils::exec("wmic baseboard get SerialNumber")};
        const auto pos{rawData.find("\r\n")};
        if (pos != std::string::npos)
        {
            ret = Utils::trim(rawData.substr(pos), " \t\r\n");
        }
        else
        {
            ret = "unknown";
        }
    }
    return ret;
}

std::string SysInfo::getCpuName() const
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY);
    return reg.string("ProcessorNameString");
}

int SysInfo::getCpuMHz() const
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY);
    return reg.dword("~MHz");
}

int SysInfo::getCpuCores() const
{
    SYSTEM_INFO siSysInfo{};
    GetSystemInfo(&siSysInfo);
    return siSysInfo.dwNumberOfProcessors;
}

void SysInfo::getMemory(nlohmann::json& info) const
{
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex))
    {
        info["ram_total"] = statex.ullTotalPhys/KByte;
        info["ram_free"] = statex.ullAvailPhys/KByte;
        info["ram_usage"] = statex.dwMemoryLoad;
    }
    else
    {
        throw std::system_error
        {
            static_cast<int>(GetLastError()),
            std::system_category(),
            "Error calling GlobalMemoryStatusEx"
        };
    }
}

nlohmann::json SysInfo::getProcessesInfo() const
{
    nlohmann::json jsProcessesList{};
    PROCESSENTRY32 processEntry{};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    // Create a snapshot of all current processes
    const auto processesSnapshot { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if (INVALID_HANDLE_VALUE != processesSnapshot)
    {
        if (Process32First(processesSnapshot, &processEntry))
        {
            do
            {
                jsProcessesList.push_back(getProcessInfo(processEntry));
            } while (Process32Next(processesSnapshot, &processEntry));
        }
        else
        {
            CloseHandle(processesSnapshot);
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to retrieve process information from the snapshot."
            };
        }
        CloseHandle(processesSnapshot);

    }
    else
    {
        throw std::system_error
        {
            static_cast<int>(GetLastError()),
            std::system_category(),
            "Unable to create process snapshot."
        };      
    }
    return jsProcessesList;
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json ret;
    getPackagesFromReg(HKEY_LOCAL_MACHINE, UNINSTALL_REGISTRY, ret, KEY_WOW64_64KEY);
    getPackagesFromReg(HKEY_LOCAL_MACHINE, UNINSTALL_REGISTRY, ret, KEY_WOW64_32KEY);
    for (const auto& user : Utils::Registry{HKEY_USERS, "", KEY_READ | KEY_ENUMERATE_SUB_KEYS}.enumerate())
    {
        getPackagesFromReg(HKEY_USERS, user + "\\" + UNINSTALL_REGISTRY, ret);
    }
    getHotFixFromReg(HKEY_LOCAL_MACHINE, WIN_REG_HOTFIX, ret);
    getHotFixFromRegNT(HKEY_LOCAL_MACHINE, VISTA_REG_HOTFIX, ret);
    return ret;
}
