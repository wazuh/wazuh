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

#ifndef _NETWORK_HELPER_H
#define _NETWORK_HELPER_H

#include "makeUnique.h"
#include <arpa/inet.h>
#include <memory>
#include <netdb.h>
#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    class NetworkHelper final
    {
    public:
        static std::string getNetworkTypeStringCode(const int value,
                                                    const std::map<std::pair<int, int>, std::string>& interfaceTypeData)
        {
            std::string retVal;

            const auto it {std::find_if(interfaceTypeData.begin(),
                                        interfaceTypeData.end(),
                                        [value](const std::pair<std::pair<int, int>, std::string>& paramValue) {
                                            return paramValue.first.first >= value && paramValue.first.second <= value;
                                        })};

            if (interfaceTypeData.end() != it)
            {
                retVal = it->second;
            }

            return retVal;
        }

        template<class T>
        static std::string IAddressToBinary(const int family, const T address)
        {
            std::string retVal;
            const auto broadcastAddrPlain {std::make_unique<char[]>(NI_MAXHOST)};

            if (inet_ntop(family, address, broadcastAddrPlain.get(), NI_MAXHOST))
            {
                retVal = broadcastAddrPlain.get();
            }

            return retVal;
        }

        static std::string getBroadcast(const std::string& ipAddress, const std::string& netmask)
        {
            struct in_addr host;
            struct in_addr mask;
            struct in_addr broadcast;

            std::string broadcastAddr;

            if (inet_pton(AF_INET, ipAddress.c_str(), &host) == 1 && inet_pton(AF_INET, netmask.c_str(), &mask) == 1)
            {

                broadcast.s_addr = host.s_addr | ~mask.s_addr;
                broadcastAddr = IAddressToBinary(AF_INET, &broadcast);
            }

            return broadcastAddr;
        }
    };
} // namespace Utils

#pragma GCC diagnostic pop

#endif // _NETWORK_HELPER_H