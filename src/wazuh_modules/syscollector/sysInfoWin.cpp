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
#include <memory>
#include <list>
#include <system_error>
#include "cmdHelper.h"
#include "stringHelper.h"
#include "registryHelper.h"
#include "sysinfoapi.h"
#include <versionhelpers.h>

constexpr auto BASEBOARD_INFORMATION_TYPE{2};
constexpr auto CENTRAL_PROCESSOR_REGISTRY{"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"};
const std::string UNINSTALL_REGISTRY{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"};

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

static bool isVistaOrLater()
{
    static const bool ret
    {
        IsWindowsVistaOrGreater()
    };
    return ret;
}

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

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json ret;
    getPackagesFromReg(HKEY_LOCAL_MACHINE, UNINSTALL_REGISTRY, ret, KEY_WOW64_64KEY);
    getPackagesFromReg(HKEY_LOCAL_MACHINE, UNINSTALL_REGISTRY, ret, KEY_WOW64_32KEY);
    for (const auto& user : Utils::Registry{HKEY_USERS, "", KEY_READ | KEY_ENUMERATE_SUB_KEYS}.enumerate())
    {
        getPackagesFromReg(HKEY_USERS, user + "\\" + UNINSTALL_REGISTRY, ret);
    }
    return ret;
}
