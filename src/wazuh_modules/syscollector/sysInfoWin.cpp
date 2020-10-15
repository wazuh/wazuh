/*
 * Wazuh RSYNC
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
        if (header.Type == BASEBOARD_INFORMATION_TYPE)
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

static std::string getSerialNumberVista()
{
    std::string ret;
    const auto size {GetSystemFirmwareTable('RSMB', 0, nullptr, 0)};
    if (size)
    {
        std::unique_ptr<unsigned char> buff{new unsigned char[size]};
        if (buff)
        {
            /* Get raw SMBIOS firmware table */
            if (GetSystemFirmwareTable('RSMB', 0, buff.get(), size) == size)
            {
                PRawSMBIOSData smbios{reinterpret_cast<PRawSMBIOSData>(buff.get())};
                /* Parse SMBIOS structures */
                ret = parseRawSmbios(smbios->SMBIOSTableData, size);
            }
        }
    }
    return ret;
}

static std::string getSerialNumber()
{
    const auto rawData{Utils::exec("wmic baseboard get SerialNumber")};
    return Utils::trim(rawData.substr(rawData.find("\r\n")), " \t\r\n");
}

void setSystemInfo(nlohmann::json& info)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
    info["cpu_name"] = reg.string("ProcessorNameString");
    info["cpu_MHz"] = reg.dword("~MHz");

    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);
    info["cpu_cores"] = siSysInfo.dwNumberOfProcessors;

    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex))
    {
        info["ram_total"] = statex.ullTotalPhys/1024;
        info["ram_free"] = statex.ullAvailPhys/1024;
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

nlohmann::json SysInfo::hardware()
{
    nlohmann::json ret;
    ret["board_serial"] = isVistaOrLater() ? getSerialNumberVista() : getSerialNumber();
    setSystemInfo(ret);
    return ret;
}