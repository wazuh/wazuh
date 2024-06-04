/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * November 1, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#ifndef _NETWORK_WINDOWS_HELPER_H
#define _NETWORK_WINDOWS_HELPER_H

#include <map>
#include <memory>
#include <vector>
#include <array>
#include <system_error>
#include <winsock2.h>
#include <windows.h>
#include <time.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <versionhelpers.h>
#include "mem_op.h"
#include "stringHelper.h"
#include "encodingWindowsHelper.h"
#include "timeHelper.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wreturn-type"
#pragma GCC diagnostic ignored "-Wcast-function-type"

constexpr auto WORKING_ADAPTERS_INFO_BUFFER_SIZE
{
    15000
};
constexpr auto MAX_ADAPTERS_INFO_TRIES
{
    3
};

constexpr auto WINDOWS_UNIX_EPOCH_DIFF_SECONDS
{
    11644473600ULL
};

constexpr int BASEBOARD_INFORMATION_TYPE
{
    2
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

typedef struct SMBIOSBaseboardInfoStructure
{
    BYTE Type;
    BYTE FormattedAreaLength;
    WORD Handle;
    BYTE Manufacturer;
    BYTE Product;
    BYTE Version;
    BYTE SerialNumber;
} SMBIOSBaseboardInfoStructure;
constexpr auto REFERENCE_YEAR
{
    1900
};

//140512 represents 14:05:12.
constexpr auto HOURMINSEC_VALUE_SIZE
{
    6
};

constexpr auto INSTALLDATE_REGISTRY_VALUE_SIZE
{
    8
};


namespace Utils
{
    struct IPAddressSmartDeleter
    {
        void operator()(IP_ADAPTER_INFO* address)
        {
            win_free(address);
            address = nullptr;
        }
        void operator()(IP_ADAPTER_ADDRESSES* address)
        {
            win_free(address);
            address = nullptr;
        }
    };

    typedef UINT (WINAPI* GetSystemFirmwareTable_t)(DWORD, DWORD, PVOID, DWORD);
    static GetSystemFirmwareTable_t getSystemFirmwareTableFunctionAddress()
    {
        GetSystemFirmwareTable_t ret{nullptr};
        auto hKernel32 { GetModuleHandle(TEXT("kernel32.dll")) };

        if (hKernel32)
        {
            ret = reinterpret_cast<GetSystemFirmwareTable_t>(GetProcAddress(hKernel32, "GetSystemFirmwareTable"));
        }

        return ret;
    }

    typedef NETIOAPI_API (WINAPI* ConvertLengthToIpv4Mask_t)(ULONG, PULONG);
    static ConvertLengthToIpv4Mask_t getConvertLengthToIpv4MaskFunctionAddress()
    {
        ConvertLengthToIpv4Mask_t ret{nullptr};
        auto hIphlpapi { GetModuleHandle(TEXT("Iphlpapi.dll")) };

        if (hIphlpapi)
        {
            ret = reinterpret_cast<ConvertLengthToIpv4Mask_t>(GetProcAddress(hIphlpapi, "ConvertLengthToIpv4Mask"));
        }

        return ret;
    }

    typedef NETIOAPI_API (WINAPI* GetIfEntry2_t)(PMIB_IF_ROW2);
    static GetIfEntry2_t getIfEntry2FunctionAddress()
    {
        GetIfEntry2_t ret{nullptr};
        auto hIphlpapi { GetModuleHandle(TEXT("Iphlpapi.dll")) };

        if (hIphlpapi)
        {
            ret = reinterpret_cast<GetIfEntry2_t>(GetProcAddress(hIphlpapi, "GetIfEntry2"));
        }

        return ret;
    }

    typedef INT (WINAPI* inet_pton_t)(INT, PCSTR, PVOID);
    static inet_pton_t getInetPtonFunctionAddress()
    {
        inet_pton_t ret{nullptr};
        auto hWs232 { GetModuleHandle(TEXT("ws2_32.dll")) };

        if (hWs232)
        {
            ret = reinterpret_cast<inet_pton_t>(GetProcAddress(hWs232, "inet_pton"));
        }

        return ret;
    }

    typedef PCSTR (WINAPI* inet_ntop_t)(INT, PVOID, PSTR, size_t);
    static inet_ntop_t getInetNtopFunctionAddress()
    {
        inet_ntop_t ret{nullptr};
        auto hWs232 { GetModuleHandle(TEXT("ws2_32.dll")) };

        if (hWs232)
        {
            ret = reinterpret_cast<inet_ntop_t>(GetProcAddress(hWs232, "inet_ntop"));
        }

        return ret;
    }

    static bool isVistaOrLater()
    {
        static const bool ret
        {
            IsWindowsVistaOrGreater()
        };
        return ret;
    }

    // https://en.wikipedia.org/wiki/ISO_8601#Calendar_dates
    // https://en.wikipedia.org/wiki/ISO_8601#Combined_date_and_time_representations
    static std::string normalizeTimestamp(const std::string& dateISO8601CalendarDateFormat, const std::string& dateISO8601CombinedFormat)
    {
        std::string normalizedTimestamp;

        if (dateISO8601CalendarDateFormat.size() != INSTALLDATE_REGISTRY_VALUE_SIZE)
        {
            throw std::runtime_error("Invalid dateISO8601CalendarDateFormat size.");
        }

        if (!isNumber(dateISO8601CalendarDateFormat))
        {
            throw std::runtime_error("Invalid dateISO8601CalendarDateFormat format.");
        }

        const auto pos = dateISO8601CombinedFormat.find(' ');

        if (pos != std::string::npos)
        {
            // Substracts "YYYY/MM/DD" from "YYYY/MM/DD hh:mm:ss" string.
            auto dateTrimmed = dateISO8601CombinedFormat.substr(0, pos);
            // Substracts "hh:mm:ss" from "YYYY/MM/DD hh:mm:ss" string.
            auto timeTrimmed = dateISO8601CombinedFormat.substr(pos + 1);

            // Converts "YYYY/MM/DD" string to "YYYYMMDD".
            Utils::replaceAll(dateTrimmed, "/", "");
            // Converts "hh:mm:ss" string to "hhmmss".
            Utils::replaceAll(timeTrimmed, ":", "");

            if (dateTrimmed.size() == INSTALLDATE_REGISTRY_VALUE_SIZE
                    || timeTrimmed.size() == HOURMINSEC_VALUE_SIZE)
            {
                if (dateTrimmed.compare(dateISO8601CalendarDateFormat) == 0)
                {
                    normalizedTimestamp = dateISO8601CombinedFormat;
                }
                else
                {
                    tm local_time_s {};

                    // Parsing YYYYMMDD date format string.
                    local_time_s.tm_year = std::stoi(dateISO8601CalendarDateFormat.substr(0, 4)) - REFERENCE_YEAR;
                    local_time_s.tm_mon = std::stoi(dateISO8601CalendarDateFormat.substr(4, 2)) - 1;
                    local_time_s.tm_mday = std::stoi(dateISO8601CalendarDateFormat.substr(6, 2));
                    local_time_s.tm_hour = 0;
                    local_time_s.tm_min = 0;
                    local_time_s.tm_sec = 0;
                    time_t local_time = mktime(&local_time_s);

                    normalizedTimestamp = Utils::getTimestamp(local_time, false);
                }
            }
            else
            {
                throw std::runtime_error("Invalid dateISO8601CombinedFormat format.");
            }
        }
        else
        {
            throw std::runtime_error("Invalid dateISO8601CombinedFormat date/time separator.");
        }

        return normalizedTimestamp;
    }

    /* Reference: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.6.0.pdf */
    static std::string getSerialNumberFromSmbios(const BYTE* rawData, const DWORD rawDataSize)
    {
        std::string serialNumber;
        DWORD offset{0};

        if (nullptr != rawData)
        {
            std::unique_ptr<BYTE[]> tmpBuffer { std::make_unique<BYTE[]>(rawDataSize + 1) };
            memcpy(tmpBuffer.get(), rawData, rawDataSize);

            while (offset < rawDataSize && serialNumber.empty())
            {
                if (offset + sizeof(SMBIOSStructureHeader) >= rawDataSize)
                {
                    break;
                }

                SMBIOSStructureHeader header{};
                memcpy(&header, tmpBuffer.get() + offset, sizeof(SMBIOSStructureHeader));

                if (offset + header.FormattedAreaLength >= rawDataSize || offset + sizeof(SMBIOSBaseboardInfoStructure) >= rawDataSize)
                {
                    break;
                }

                if (BASEBOARD_INFORMATION_TYPE == header.Type)
                {
                    SMBIOSBaseboardInfoStructure info{};
                    memcpy(&info, tmpBuffer.get() + offset, sizeof(SMBIOSBaseboardInfoStructure));
                    offset += info.FormattedAreaLength;

                    for (BYTE i = 1; i < info.SerialNumber; ++i)
                    {
                        const char* tmp{reinterpret_cast<const char*>(tmpBuffer.get() + offset)};

                        if (offset < rawDataSize)
                        {
                            const auto len{ nullptr != tmp ? strlen(tmp) : 0 };
                            offset += len + sizeof(char);
                        }
                    }

                    if (offset < rawDataSize)
                    {
                        serialNumber = reinterpret_cast<const char*>(tmpBuffer.get() + offset);
                    }
                }
                else
                {
                    offset += header.FormattedAreaLength;

                    // Search for the end of the unformatted structure (\0\0)
                    while (offset + 1 < rawDataSize)
                    {
                        if (!(*(tmpBuffer.get() + offset)) && !(*(tmpBuffer.get() + offset + 1)))
                        {
                            offset += 2;
                            break;
                        }

                        offset++;
                    }
                }
            }
        }

        return serialNumber;
    }

    static std::string buildTimestamp(const ULONGLONG time)
    {
        // Format of value is 18-digit LDAP/FILETIME timestamps.
        // 18-digit LDAP/FILETIME timestamps -> Epoch/Unix time
        // (value/10000000ULL) - 11644473600ULL
        const time_t epochTime { static_cast<long int> ((time / 10000000ULL) - WINDOWS_UNIX_EPOCH_DIFF_SECONDS) };
        char formatString[20] = {0};

        tm utc_time;
        gmtime_s(&utc_time, &epochTime);

        std::strftime(formatString, sizeof(formatString), "%Y/%m/%d %H:%M:%S", &utc_time);
        return formatString;
    }

    class NetworkWindowsHelper final
    {
            static DWORD getAdapterAddresses(PIP_ADAPTER_ADDRESSES& ipAdapterAddresses)
            {
                // Set the flags to pass to GetAdaptersAddresses()
                // When the GAA_FLAG_INCLUDE_PREFIX flag is set, IP address prefixes are returned for both IPv6 and IPv4 addresses.
                const auto adapterAddressesFlags
                {
                    isVistaOrLater() ? (GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS)
                    : 0
                };

                ULONG bufferLen { WORKING_ADAPTERS_INFO_BUFFER_SIZE };
                DWORD dwRetVal  { 0 };
                auto attempts   { 0 };
                bool adapterAddressesFound { false };

                do
                {
                    ipAdapterAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(win_alloc(bufferLen));

                    if (!ipAdapterAddresses)
                    {
                        throw std::system_error
                        {
                            static_cast<int>(GetLastError()),
                            std::system_category(),
                            "Unable to allocate memory for PIP_ADAPTER_ADDRESSES struct."
                        };
                    }

                    // Two calls of GetAdaptersAddresses are needed. One for getting the size needed (bufferLen variable),
                    // and the second one for getting the actual data we want.
                    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, adapterAddressesFlags, nullptr, ipAdapterAddresses, &bufferLen);

                    if (ERROR_BUFFER_OVERFLOW == dwRetVal)
                    {
                        win_free(ipAdapterAddresses);
                        ipAdapterAddresses = nullptr;
                    }
                    else
                    {
                        adapterAddressesFound = true;
                    }

                    ++attempts;
                }
                while (!adapterAddressesFound && attempts < MAX_ADAPTERS_INFO_TRIES);

                return dwRetVal;
            }

            static DWORD getAdapterInfoXP(PIP_ADAPTER_INFO& ipAdapterInfo)
            {
                // Windows XP additional IPv4 interfaces data

                ULONG bufferLen { WORKING_ADAPTERS_INFO_BUFFER_SIZE };
                DWORD dwRetVal  { 0 };
                auto attempts   { 0 };
                bool adapterInfoFound { false };

                while (!adapterInfoFound && attempts < MAX_ADAPTERS_INFO_TRIES)
                {
                    ipAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(win_alloc(bufferLen));

                    if (!ipAdapterInfo)
                    {
                        throw std::system_error
                        {
                            static_cast<int>(GetLastError()),
                            std::system_category(),
                            "Unable to allocate memory for IP_ADAPTER_INFO struct."
                        };
                    }

                    dwRetVal = GetAdaptersInfo(ipAdapterInfo, &bufferLen);

                    if (ERROR_BUFFER_OVERFLOW == dwRetVal)
                    {
                        win_free(ipAdapterInfo);
                        ipAdapterInfo = nullptr;
                    }
                    else
                    {
                        adapterInfoFound = true;
                    }

                    ++attempts;
                }

                return dwRetVal;
            }

        public:

            enum NetworkFamilyTypes
            {
                UNDEF,
                IPV4,
                IPV6,
                COMMON_DATA
            };

            static std::string getAdapterNameStr(const std::wstring& adapterName)
            {
                return Utils::EncodingWindowsHelper::wstringToStringUTF8(adapterName);
            }

            static void getAdapters(std::unique_ptr<IP_ADAPTER_ADDRESSES, IPAddressSmartDeleter>& interfacesAddress)
            {
                PIP_ADAPTER_ADDRESSES ipAdapterAddresses { nullptr };
                const DWORD dwRetVal { getAdapterAddresses(ipAdapterAddresses) };

                if (NO_ERROR == dwRetVal)
                {
                    interfacesAddress.reset(ipAdapterAddresses);
                }
                else
                {
                    throw std::system_error
                    {
                        static_cast<int>(dwRetVal),
                        std::system_category(),
                        "Error reading network adapter addresses"
                    };
                }
            }

            static void getAdapterInfo(std::unique_ptr<IP_ADAPTER_INFO, IPAddressSmartDeleter>& adapterInfo)
            {
                PIP_ADAPTER_INFO ipAdapterInfo { nullptr };
                const DWORD dwRetVal { getAdapterInfoXP(ipAdapterInfo) };

                if (NO_ERROR == dwRetVal)
                {
                    adapterInfo.reset(ipAdapterInfo);
                }
                else
                {
                    throw std::system_error
                    {
                        static_cast<int>(dwRetVal),
                        std::system_category(),
                        "Error reading network adapter info"
                    };
                }
            }

            static std::string IAddressToString(const int family, in_addr address)
            {
                std::string retVal;
                auto plainAddress { std::make_unique<char[]>(NI_MAXHOST) };

                if (isVistaOrLater())
                {
                    static auto pfnInetNtop { getInetNtopFunctionAddress() };

                    if (pfnInetNtop)
                    {
                        if (pfnInetNtop(family, &address, plainAddress.get(), NI_MAXHOST))
                        {
                            retVal = plainAddress.get();
                        }
                    }
                }
                else
                {
                    // Windows XP
                    plainAddress.reset(inet_ntoa(address));

                    if (plainAddress)
                    {
                        retVal = plainAddress.get();
                    }
                }

                return retVal;
            }

            static std::string IAddressToString(const int family, in6_addr address)
            {
                std::string retVal;
                auto plainAddress { std::make_unique<char[]>(NI_MAXHOST) };

                if (isVistaOrLater())
                {
                    static auto pfnInetNtop { getInetNtopFunctionAddress() };

                    if (pfnInetNtop)
                    {
                        if (pfnInetNtop(family, &address, plainAddress.get(), NI_MAXHOST))
                        {
                            retVal = plainAddress.get();
                        }
                    }
                }

                // IPv6 in Windows XP is not supported
                return retVal;
            }

            static std::string broadcastAddress(const std::string& ipAddress, const std::string& netmask)
            {
                struct in_addr host {};
                struct in_addr mask {};
                struct in_addr broadcast {};

                std::string broadcastAddr;

                static auto pfnInetPton { getInetPtonFunctionAddress() };

                if (pfnInetPton)
                {
                    if (pfnInetPton(AF_INET, ipAddress.c_str(), &host) == 1 && pfnInetPton(AF_INET, netmask.c_str(), &mask) == 1)
                    {
                        broadcast.s_addr = host.s_addr | ~mask.s_addr;
                        broadcastAddr = IAddressToString(AF_INET, broadcast);
                    }
                }

                return broadcastAddr;
            }

            static std::string getIpV6Address(const uint8_t* addrParam)
            {
                std::string retVal;

                if (addrParam)
                {
                    constexpr auto IPV6_BUFFER_ADDRESS_SIZE { 16 };
                    std::array<char, IPV6_BUFFER_ADDRESS_SIZE> buffer;
                    memcpy(buffer.data(), addrParam, IPV6_BUFFER_ADDRESS_SIZE);

                    std::array<char, IPV6_BUFFER_ADDRESS_SIZE> addrComparator;
                    addrComparator.fill(0);

                    if (std::equal(buffer.begin(), buffer.end(), addrComparator.begin()))
                    {
                        retVal = "::";
                    }
                    else
                    {
                        addrComparator.at(IPV6_BUFFER_ADDRESS_SIZE - 1) = 0x1;

                        if (std::equal(buffer.begin(), buffer.end(), addrComparator.begin()))
                        {
                            retVal = "::1";
                        }
                        else
                        {
                            std::stringstream ss;
                            bool separator { false };
                            ss << std::hex << std::setfill('0');

                            for (const auto& value : buffer)
                            {
                                ss << std::setw(2) << (static_cast<unsigned>(value) & 0xFF);

                                if (separator)
                                {
                                    ss << ":";
                                }

                                separator = !separator;
                            }

                            retVal = ss.str();
                            Utils::replaceAll(retVal, "0000", "");
                            Utils::replaceAll(retVal, ":::", "::");
                            retVal = retVal.substr(0, retVal.size() - 1);
                        }
                    }
                }

                return retVal;
            }

            static std::string ipv6Netmask(const uint8_t maskLength)
            {
                static const auto MAX_BITS_LENGTH { 128 };
                std::string netmask;

                if (maskLength < MAX_BITS_LENGTH)
                {
                    // For a unicast IPv6 address, any value greater than 128 is an illegal value

                    // Each chunks of addresses has four letters "f" following by a ":"
                    // If "maskLength" is not multiple of 4, we need to fill the current
                    // "chunk" depending of the amount of letters needed. That's why
                    // the need of the following map.
                    static std::map<int, std::string> NET_MASK_FILLER_CHARS_MAP =
                    {
                        { 1, "8"},
                        { 2, "c"},
                        { 3, "e"}
                    };
                    static const int BITS_PER_CHUNK     { 4 };
                    static const int NETMASK_TOTAL_BITS { 32 };

                    netmask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"; // 128 bits address
                    const int value          { maskLength / BITS_PER_CHUNK };
                    const int remainingValue { maskLength % BITS_PER_CHUNK };
                    const int totalSum       { value + remainingValue };
                    const int refillData     { totalSum % BITS_PER_CHUNK };
                    const int separators     { value / BITS_PER_CHUNK };
                    const int remainingSeparators     { value % BITS_PER_CHUNK };
                    const int finalNumberOfSeparators { remainingSeparators == 0 ? separators - 1 : separators };

                    // Add the needed ":" separators
                    netmask = netmask.substr(0, value + finalNumberOfSeparators);

                    if (remainingValue)
                    {
                        // If the maskLength is not multiple of 4, let's refill with the corresponding
                        // character
                        const auto it { NET_MASK_FILLER_CHARS_MAP.find(remainingValue) };

                        if (NET_MASK_FILLER_CHARS_MAP.end() != it)
                        {
                            netmask += it->second;
                        }
                    }
                    else
                    {
                        netmask += std::string(refillData, '0'); // Refill data with 0's if applies
                    }

                    if (totalSum < (NETMASK_TOTAL_BITS - BITS_PER_CHUNK))
                    {
                        // Append "::" to fill the complete 128 bits address (IPv6 representation)
                        netmask += "::";
                    }
                }

                return netmask;
            }
    };
}

#pragma GCC diagnostic pop

#endif // _NETWORK_WINDOWS_HELPER_H

#endif //WIN32
