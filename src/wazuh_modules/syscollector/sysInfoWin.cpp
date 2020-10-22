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
        : m_pId(pId),
          m_kernelModeTime{},
          m_userModeTime{}
    {
        m_spProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_pId);
        if (m_spProcess)
        {
            setProcessTimes();
            setProcessMemInfo();
        }
        else
        {
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to open process with PID %lu" + m_pId
            };
        }
    }

    ~SysInfoProcess()
    {
        CloseHandle(m_spProcess);
    }

    std::string cmd()
    {
        std::string ret { "unknown" };
        char readBuffer[OS_MAXSTR] = {};
        //std::unique_ptr<char*, CharDeleter> path { nullptr };
        char* path { nullptr };
        // Get full Windows kernel path for the process
        if (GetProcessImageFileName(m_spProcess, readBuffer, OS_MAXSTR))
        {
            // Convert Windows kernel path to a valid Win32 filepath
            // E.g.: "\Device\HarddiskVolume1\Windows\system32\notepad.exe" -> "C:\Windows\system32\notepad.exe"
            // This requires hotfix KB931305 in order to work under XP/Server 2003, so the conversion will be skipped if we're not running under Vista or greater
            if (!isVistaOrLater() || !ntPath2Win32Path(readBuffer, &path))
            {
                // If there were any errors, the readBuffer array will remain intact
                // In that case, let's just use the Windows kernel path. It's better than nothing
                ret = path;
            }
        }
        else
        {
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to retrieve executable path from process with PID %lu" + m_pId
            };
        }
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
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to retrieve session ID from process with PID %lu" + m_pId
            };
        }
        return ret;
    }

private:
    void setProcessTimes()
    {
        FILETIME lpCreationTime{};
        FILETIME lpExitTime{};
        FILETIME lpKernelTime{};
        FILETIME lpUserTime{};
        if (GetProcessTimes(m_spProcess, &lpCreationTime, &lpExitTime, &lpKernelTime, &lpUserTime))
        {
            // Copy the kernel mode filetime high and low parts and convert it to seconds
            m_kernelModeTime.LowPart = lpKernelTime.dwLowDateTime;
            m_kernelModeTime.HighPart = lpKernelTime.dwHighDateTime;
            m_kernelModeTime.QuadPart /= 10000000ULL;

            // Copy the user mode filetime high and low parts and convert it to seconds
            m_userModeTime.LowPart = lpUserTime.dwLowDateTime;
            m_userModeTime.HighPart = lpUserTime.dwHighDateTime;
            m_userModeTime.QuadPart /= 10000000ULL;
        }
        else
        {
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to retrieve kernel mode and user mode times from process with PID %lu" + m_pId
            };          
        }
    }

    void setProcessMemInfo()
    {
        PROCESS_MEMORY_COUNTERS pMemCounters;
        // Get page file usage and virtual size
        // Reference: https://stackoverflow.com/a/1986486
        if (GetProcessMemoryInfo(m_spProcess, &pMemCounters, sizeof(pMemCounters)))
        {
            m_pageFileUsage = pMemCounters.PagefileUsage;
            m_virtualSize   = pMemCounters.WorkingSetSize + pMemCounters.PagefileUsage;
        }
        else
        {
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to retrieve page file usage from process with PID %lu" + m_pId
            };
        }
    }

    int ntPath2Win32Path(char* ntpath, char** outbuf)
    {
        int success { 0 };

        if (nullptr != ntpath)
        {
            char logicalDrives[OS_MAXSTR] = {0};
            // Get the total amount of available logical drives
            // The input size must not include the NULL terminator
            DWORD res { GetLogicalDriveStrings(OS_MAXSTR - 1, logicalDrives) };
            if (res <= 0 || res > OS_MAXSTR)
            {
                throw std::system_error
                {
                    static_cast<int>(GetLastError()),
                    std::system_category(),
                    "Unable to parse logical drive strings"
                };
                return success;
            }

            char bufferRead[OS_MAXSTR] = {0};
            constexpr auto MAX_MS_DOS_DRIVE_CHARS { 3 };
            char msdosDrive[MAX_MS_DOS_DRIVE_CHARS] = { '\0', ':', '\0' };

            // Performs a loop of the retrieved drive list
            char* singleDrive { logicalDrives };
            while(*singleDrive && !success)
            {
                // Get the MS-DOS drive letter
                *msdosDrive = *singleDrive;

                // Retrieve the Windows kernel path for this drive
                res = QueryDosDevice(msdosDrive, bufferRead, OS_MAXSTR);
                if (res)
                {
                    // Check if this is the drive we're looking for
                    const auto bufferReadLen { strlen(bufferRead) };
                    if (!strncmp(ntpath, bufferRead, bufferReadLen))
                    {
                        // Calculate new string length (making sure there's space left for the NULL terminator)
                        const auto len { strlen(ntpath) - bufferReadLen + MAX_MS_DOS_DRIVE_CHARS };

                        // Allocate memory
                        *outbuf = reinterpret_cast<char*>(std::malloc(len));
                        if (*outbuf)
                        {
                            // Copy the new filepath
                            snprintf(*outbuf, len, "%s%s", msdosDrive, ntpath + bufferReadLen);
                            success = 1;
                        }
                    }
                }
                else
                {
                    throw std::system_error
                    {
                        static_cast<int>(res),
                        std::system_category(),
                        "Unable to retrieve Windows kernel path for drive '%s\\'" + std::string(msdosDrive)
                    };
                }

                // Get the next drive
                singleDrive += strlen(singleDrive) + 1;
            }

            if (!success)
            {
                throw std::system_error
                {
                    static_cast<int>(GetLastError()),
                    std::system_category(),
                    "Unable to find a matching Windows kernel drive path for '%s'" + std::string(ntpath)
                };
            }
        }

        return success;
    }

    const DWORD     m_pId;
    HANDLE          m_spProcess;
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

static std::string processName(PROCESSENTRY32 processEntry,
                               std::string& execPath)
{
    std::string ret;
    const DWORD pId { processEntry.th32ProcessID };
    if (pId == 0 || pId == 4)
    {
        ret = (pId == 0) ? SYSTEM_IDLE_PROCESS_NAME : SYSTEM_PROCESS_NAME;
        execPath = "none";
    }
    else
    {
        ret = processEntry.szExeFile;
    }
    return ret;
}

static nlohmann::json getProcessInfo(const PROCESSENTRY32& processEntry)
{
    nlohmann::json jsProcessInfo{};
    const DWORD pId { processEntry.th32ProcessID };
    SysInfoProcess process(pId);
    std::string execName;

    // Current process information
    jsProcessInfo["name"]       = processName(processEntry, execName);
    jsProcessInfo["cmd"]        = (execName.compare("none") == 0) ? execName : process.cmd();
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

std::string SysInfo::getSerialNumber() const
{
    std::string ret;
    if (isVistaOrLater())
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
    else
    {
        const auto size {GetSystemFirmwareTable('RSMB', 0, nullptr, 0)};
        if (size)
        {
            const auto spBuff{std::make_unique<unsigned char[]>(size)};
            if (spBuff)
            {
                /* Get raw SMBIOS firmware table */
                if (GetSystemFirmwareTable('RSMB', 0, spBuff.get(), size) == size)
                {
                    PRawSMBIOSData smbios{reinterpret_cast<PRawSMBIOSData>(spBuff.get())};
                    /* Parse SMBIOS structures */
                    ret = parseRawSmbios(smbios->SMBIOSTableData, size);
                }
            }
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

nlohmann::json SysInfo::getPackages() const
{
    return {};
}

nlohmann::json SysInfo::getProcessesInfo() const
{
    nlohmann::json jsProcessesList{};
    PROCESSENTRY32 processEntry {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    // Create a snapshot of all current processes
    const auto spProcessSnapshot { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if (INVALID_HANDLE_VALUE != spProcessSnapshot)
    {
        if (Process32First(spProcessSnapshot, &processEntry))
        {
            do
            {
                jsProcessesList += getProcessInfo(processEntry);
            } while (Process32Next(spProcessSnapshot, &processEntry));
        }
        else
        {
            throw std::system_error
            {
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Unable to retrieve process information from the snapshot"
            };
        }
        CloseHandle(spProcessSnapshot);
    }
    else
    {
        throw std::system_error
        {
            static_cast<int>(GetLastError()),
            std::system_category(),
            "Unable to create process snapshot"
        };      
    }
    return jsProcessesList;
}
