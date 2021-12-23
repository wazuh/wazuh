/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_LINUX_WRAPPER_H
#define _NETWORK_LINUX_WRAPPER_H

#include <vector>
#include <sys/sockio.h>
#include <arpa/inet.h>

#include "inetworkWrapper.h"
#include "UtilsWrapperUnix.hpp"
#include "sharedDefs.h"

class NetworkSolarisInterface final : public INetworkInterfaceWrapper
{
    struct lifconf* m_networkInterfaces;
    int m_indexInterface;
    int m_fileDescriptor;

    public:
        explicit NetworkSolarisInterface(int fs, int index, struct lifconf* interfaces)
        : m_networkInterfaces {interfaces}
        , m_indexInterface {index}
        , m_fileDescriptor {fs}
        {
        }

        std::string name() const override
        {
            return "";
        }

        std::string adapter() const override
        {
            return "";
        }

        int family() const override
        {
            return m_networkInterfaces->lifc_family;
        }

        std::string address() const override
        {
            constexpr auto IPSIZE {16};
            auto addressInterface { std::vector<char>(IPSIZE) };
            struct lifreq *interfaceReq = m_networkInterfaces->lifc_req + m_indexInterface;

            if (-1 != UtilsWrapperUnix::createIoctl(m_fileDescriptor, SIOCGLIFFLAGS, reinterpret_cast<char *>(interfaceReq)))
            {
                // Get address of interfaces are UP and aren't Loopback
                if ( !(IFF_UP & interfaceReq->lifr_flags) && !(IFF_LOOPBACK & interfaceReq->lifr_flags) )
                {
                    if (-1 != UtilsWrapperUnix::createIoctl(m_fileDescriptor, SIOCGLIFADDR, reinterpret_cast<char *>(interfaceReq)))
                    {
                        struct sockaddr_in* data = reinterpret_cast<struct sockaddr_in *>(&interfaceReq->lifr_addr);
                        inet_ntop(AF_INET, &data, addressInterface.data(), addressInterface.size());
                    }
                }
            }

            const std::string address(addressInterface.begin(), addressInterface.end());
            return address;
        }

        std::string netmask() const override
        {
            return "";
        }

        std::string broadcast() const override
        {
            std::string retVal { UNKNOWN_VALUE };
            return retVal;
        }

        std::string addressV6() const override
        {
            constexpr auto IPSIZE {46};
            auto addressInterface { std::vector<char>(IPSIZE) };
            struct lifreq *interfaceReq = m_networkInterfaces->lifc_req + m_indexInterface;

            if (-1 != UtilsWrapperUnix::createIoctl(m_fileDescriptor, SIOCGLIFFLAGS, reinterpret_cast<char *>(interfaceReq)))
            {
                // Get address of interfaces are UP and aren't Loopback
                if ( !(IFF_UP & interfaceReq->lifr_flags) && !(IFF_LOOPBACK & interfaceReq->lifr_flags) )
                {
                    #ifdef SIOCGLIFADDR
                    if (-1 != UtilsWrapperUnix::createIoctl(m_fileDescriptor, SIOCGLIFADDR, reinterpret_cast<char *>(interfaceReq)))
                    {
                        struct sockaddr_in6* data = reinterpret_cast<struct sockaddr_in6 *>(&interfaceReq->lifr_addr);
                        inet_ntop(AF_INET6, &data, addressInterface.data(), addressInterface.size());
                    }
                    #else
                    if (-1 != UtilsWrapperUnix::createIoctl(m_fileDescriptor, SIOCGIFV6ADDR, reinterpret_cast<char *>(interfaceReq)))
                    {
                        struct sockaddr_in6* data = reinterpret_cast<struct sockaddr_in6 *>(&interfaceReq->lifr_addr);
                        inet_ntop(AF_INET6, &data, addressInterface.data(), addressInterface.size());
                    }
                    #endif
                }
            }

            const std::string address(addressInterface.begin(), addressInterface.end());
            return address;
        }

        std::string netmaskV6() const override
        {
            return "";
        }

        std::string broadcastV6() const override
        {
            return "";
        }

        std::string gateway() const override
        {
            return "";
        }

        std::string metrics() const override
        {
            return "";
        }

        std::string metricsV6() const override
        {
            return "";
        }

        std::string dhcp() const override
        {
            std::string retVal { "unknown" };
            return retVal;
        }

        uint32_t mtu() const override
        {
            uint32_t retVal { 0 };
            return retVal;
        }

        LinkStats stats() const override
        {
            return LinkStats();
        }

        std::string type() const override
        {
            std::string type { UNKNOWN_VALUE };
            return type;
        }

        std::string state() const override
        {
            std::string state { UNKNOWN_VALUE };
            return state;
        }

        std::string MAC() const override
        {
            std::string mac { UNKNOWN_VALUE };
            return mac;
        }
};

#endif // _NETWORK_LINUX_WRAPPER_H
