/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_UNIX_HELPER_H
#define _NETWORK_UNIX_HELPER_H

#include "stringHelper.h"
#include <ifaddrs.h>
#include <map>
#include <memory>
#include <net/if.h>
#include <string>
#include <system_error>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    struct IfAddressSmartDeleter
    {
        void operator()(ifaddrs* address)
        {
            freeifaddrs(address);
        }
    };

    class NetworkUnixHelper final
    {
    public:
        static void getNetworks(std::unique_ptr<ifaddrs, IfAddressSmartDeleter>& interfacesAddress,
                                std::map<std::string, std::vector<ifaddrs*>>& networkInterfaces)
        {
            struct ifaddrs* ifaddr {nullptr};
            const auto ret {getifaddrs(&ifaddr)};

            if (ret != -1)
            {
                interfacesAddress.reset(ifaddr);

                for (auto ifa = ifaddr; ifa; ifa = ifa->ifa_next)
                {
                    if (!(ifa->ifa_flags & IFF_LOOPBACK) && ifa->ifa_name)
                    {
                        networkInterfaces[substrOnFirstOccurrence(ifa->ifa_name, ":")].push_back(ifa);
                    }
                }
            }
            else
            {
                throw std::system_error {ret, std::system_category(), "Error reading networks"};
            }
        }
    };
} // namespace Utils

#pragma GCC diagnostic pop

#endif // _NETWORK_UNIX_HELPER_H
