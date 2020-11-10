/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 24, 2020.
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
#include <system_error>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <versionhelpers.h>
#include "mem_op.h"
#include "stringHelper.h"
	
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wreturn-type"
#pragma GCC diagnostic ignored "-Wcast-function-type"

constexpr auto WORKING_ADAPTERS_INFO_BUFFER_SIZE {15000};
constexpr auto MAX_ADAPTERS_INFO_TRIES {3};

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

    typedef NETIOAPI_API (WINAPI *ConvertLengthToIpv4Mask_t)(ULONG, PULONG);
    static ConvertLengthToIpv4Mask_t getConvertLengthToIpv4MaskFunctionAddress()
    {
        ConvertLengthToIpv4Mask_t ret{nullptr};
        auto hIphlpapi{LoadLibrary("Iphlpapi.dll")};
        if (hIphlpapi)
        {
            ret = reinterpret_cast<ConvertLengthToIpv4Mask_t>(GetProcAddress(hIphlpapi, "ConvertLengthToIpv4Mask"));
            FreeLibrary(hIphlpapi);
        }
        return ret;
    }

    typedef NETIOAPI_API (WINAPI *GetIfEntry2_t)(PMIB_IF_ROW2);
    static GetIfEntry2_t getIfEntry2FunctionAddress()
    {
        GetIfEntry2_t ret{nullptr};
        auto hIphlpapi{LoadLibrary("Iphlpapi.dll")};
        if (hIphlpapi)
        {
            ret = reinterpret_cast<GetIfEntry2_t>(GetProcAddress(hIphlpapi, "GetIfEntry2"));
            FreeLibrary(hIphlpapi);
        }
        return ret;
    }  

    typedef INT (WINAPI *inet_pton_t)(INT, PCSTR, PVOID);
    static inet_pton_t getInetPtonFunctionAddress()
    {
        inet_pton_t ret{nullptr};
        auto hWs232{LoadLibrary("ws2_32.dll")};
        if (hWs232)
        {
            ret = reinterpret_cast<inet_pton_t>(GetProcAddress(hWs232, "inet_pton"));
            FreeLibrary(hWs232);
        }
        return ret;
    }

    typedef PCSTR (WINAPI *inet_ntop_t)(INT, PVOID, PSTR, size_t);
    static inet_ntop_t getInetNtopFunctionAddress()
    {
        inet_ntop_t ret{nullptr};
        auto hWs232{LoadLibrary("ws2_32.dll")};
        if (hWs232)
        {
            ret = reinterpret_cast<inet_ntop_t>(GetProcAddress(hWs232, "inet_ntop"));
            FreeLibrary(hWs232);
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
            } while (!adapterAddressesFound && attempts < MAX_ADAPTERS_INFO_TRIES);
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

        static std::string getAdapterNameStr(const PWCHAR& adapterName)
        {
            std::string retVal{ "unknown" };
            const std::wstring wfriendlyName(adapterName);
            if (!wfriendlyName.empty())
            {
                retVal.assign(wfriendlyName.begin(), wfriendlyName.end());
            }
            return retVal;
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
            // inet_ntoa with in6_addr for Windows XP is not supported
            return retVal;
        }        

        static std::string broadcastAddress(const std::string& ipAddress, const std::string& netmask)
        {
            struct in_addr host {};
            struct in_addr mask {};
            struct in_addr broadcast {};

            std::string broadcastAddr { "unknown" };

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
                const auto IPV6_BUFFER_ADDRESS_SIZE { 16 };
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
                    addrComparator.at(IPV6_BUFFER_ADDRESS_SIZE-1) = 0x1;
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
                        Utils::replaceAll(retVal,"0000", "");
                        Utils::replaceAll(retVal,":::", "::");
                        retVal = retVal.substr(0, retVal.size() - 1);
                    }
                }
            }
            return retVal;
        }        
    };
}

#pragma GCC diagnostic pop

#endif // _NETWORK_WINDOWS_HELPER_H

#endif //WIN32