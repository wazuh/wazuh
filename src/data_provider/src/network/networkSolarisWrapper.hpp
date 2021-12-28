/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_SOLARIS_WRAPPER_H
#define _NETWORK_SOLARIS_WRAPPER_H

#include <vector>
#include <algorithm>
#include <sys/sockio.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#include "inetworkWrapper.h"
#include "UtilsWrapperUnix.hpp"
#include "sharedDefs.h"
#include "networkHelper.h"
#include "cmdHelper.h"
#include "stringHelper.h"

enum ROUTING_FIELDS {
    ROUTING_DESTINATION,
    ROUTING_GATEWAY,
    ROUTING_FLAGS,
    ROUTING_REF,
    ROUTING_USE,
    ROUTING_IFACE_NAME,
    ROUTING_SIZE_FIELDS
};

enum MAC_FIELDS {
    MAC_FIELD_NAME,
    MAC_ADDRESS,
    MAC_SIZE_FIELDS
};

class NetworkSolarisInterface final : public INetworkInterfaceWrapper
{
    lifreq* m_networkInterface;
    const int m_fileDescriptor;
    const sa_family_t m_family;
    const uint64_t m_interfaceFlags;

    public:
        explicit NetworkSolarisInterface(const sa_family_t family, int fd, std::pair<lifreq*, uint64_t> interface)
        : m_networkInterface {interface.first}
        , m_fileDescriptor {fd}
        , m_family {family}
        , m_interfaceFlags {interface.second}
        {
        }

        std::string name() const override
        {
            return m_networkInterface->lifr_name ? m_networkInterface->lifr_name : "";
        }

        std::string adapter() const override
        {
            return "";
        }

        int family() const override
        {
            return m_family;
        }

        std::string address() const override
        {
            std::string address;

            if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFADDR, reinterpret_cast<char *>(m_networkInterface)))
            {
                struct sockaddr_in* data = reinterpret_cast<struct sockaddr_in *>(&m_networkInterface->lifr_addr);
                address = Utils::NetworkHelper::IAddressToBinary(this->family(), &data->sin_addr);
            }
            return address;
        }

        std::string netmask() const override
        {
            std::string address;

            if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFNETMASK, reinterpret_cast<char *>(m_networkInterface)))
            {
                struct sockaddr_in* data = reinterpret_cast<struct sockaddr_in *>(&m_networkInterface->lifr_addr);
                address = Utils::NetworkHelper::IAddressToBinary(this->family(), &data->sin_addr);
            }
            return address;
        }

        std::string broadcast() const override
        {
            std::string retVal { UNKNOWN_VALUE };
            if (m_interfaceFlags & IFF_BROADCAST)
            {
                if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFBRDADDR, reinterpret_cast<char *>(m_networkInterface)))
                {
                    struct sockaddr_in* data = reinterpret_cast<struct sockaddr_in *>(&m_networkInterface->lifr_broadaddr);
                    retVal = Utils::NetworkHelper::IAddressToBinary(this->family(), &data->sin_addr);
                }
            }
            return retVal;
        }

        std::string addressV6() const override
        {
            std::string address;
            if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFADDR, reinterpret_cast<char *>(m_networkInterface)))
            {
                struct sockaddr_in6* data = reinterpret_cast<struct sockaddr_in6 *>(&m_networkInterface->lifr_addr);
                address = Utils::NetworkHelper::IAddressToBinary(this->family(), &data->sin6_addr);
            }
            return address;
        }

        std::string netmaskV6() const override
        {
            std::string address;
            if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFNETMASK, reinterpret_cast<char *>(m_networkInterface)))
            {
                struct sockaddr_in6* data = reinterpret_cast<struct sockaddr_in6 *>(&m_networkInterface->lifr_addr);
                address = Utils::NetworkHelper::IAddressToBinary(this->family(), &data->sin6_addr);
            }
            return address;
        }

        std::string broadcastV6() const override
        {
            std::string retVal;
            if (m_interfaceFlags & IFF_BROADCAST)
            {
                if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFBRDADDR , reinterpret_cast<char *>(m_networkInterface)))
                {
                    struct sockaddr_in6* data = reinterpret_cast<struct sockaddr_in6 *>(&m_networkInterface->lifr_addr);
                    retVal = Utils::NetworkHelper::IAddressToBinary(this->family(), &data->sin6_addr);
                }
            }
            return retVal;
        }

        std::string gateway() const override
        {
            std::string retVal;
            const auto buffer { Utils::exec("netstat -rn") };
            if (!buffer.empty())
            {
                const auto lines { Utils::split(buffer, '\n') };
                for (auto line : lines)
                {
                    Utils::replaceAll(line, "  ", " ");
                    const auto fields { Utils::split(line, ' ') };
                    if (fields.size() == ROUTING_SIZE_FIELDS && fields.front().compare("default") == 0)
                    {
                        if (fields[ROUTING_IFACE_NAME].compare(this->name()) == 0)
                        {
                            retVal = fields[ROUTING_GATEWAY];
                        }
                        break;
                    }
                }
            }
            return retVal;
        }

        std::string metrics() const override
        {
            std::string metric;
            if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFMETRIC, reinterpret_cast<char *>(m_networkInterface)))
            {
                metric = std::to_string(m_networkInterface->lifr_metric);
            }
            return metric;
        }

        std::string metricsV6() const override
        {
            std::string metric;
            if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFMETRIC, reinterpret_cast<char *>(m_networkInterface)))
            {
                metric = std::to_string(m_networkInterface->lifr_metric);
            }
            return metric;
        }

        std::string dhcp() const override
        {
            return m_interfaceFlags & IFF_DHCPRUNNING ? "enabled" : "disabled";
        }

        uint32_t mtu() const override
        {
            uint32_t retVal { 0 };
            if (-1 != UtilsWrapperUnix::ioctl(m_fileDescriptor, SIOCGLIFMTU, reinterpret_cast<char *>(m_networkInterface)))
            {
                retVal = m_networkInterface->lifr_mtu;
            }
            return retVal;
        }

        LinkStats stats() const override
        {
            auto buffer { Utils::exec("dlstat -a " + this->name(), 256) };
	        LinkStats statistic { 0, 0, 0, 0, 0, 0, 0, 0 };

            if (!buffer.empty())
            {
                auto lines { Utils::split(buffer, '\n') };

		        lines.erase(lines.begin());
		        lines.erase(lines.begin());
		        lines.erase(lines.end());

                try
                {
                    size_t valueSize = 0;
                    constexpr auto RX_PACKET_INDEX { 0 };
                    constexpr auto RX_BYTES_INDEX  { 1 };
                    constexpr auto TX_PACKET_INDEX { 2 };
                    constexpr auto TX_BYTES_INDEX  { 3 };
                    constexpr auto RX_DROPS_INDEX  { 4 };
                    constexpr auto TX_DROPS_INDEX  { 6 };
                    auto value { std::stoi(Utils::split(lines.at(RX_PACKET_INDEX), ' ').back(), &valueSize) };

                    if (Utils::split(lines.at(RX_PACKET_INDEX), ' ').back().size() == valueSize)
                    {
                        statistic.rxPackets = static_cast<unsigned int>(value);
                    }

                    value = std::stoi(Utils::split(lines.at(RX_BYTES_INDEX), ' ').back(), &valueSize);

                    if (Utils::split(lines.at(RX_BYTES_INDEX), ' ').back().size() == valueSize)
                    {
                        statistic.rxBytes = static_cast<unsigned int>(value);
                    }

                    value = std::stoi(Utils::split(lines.at(TX_PACKET_INDEX), ' ').back(), &valueSize);

                    if (Utils::split(lines.at(TX_PACKET_INDEX), ' ').back().size() == valueSize)
                    {
                        statistic.txPackets = static_cast<unsigned int>(value);
                    }

                    value = std::stoi(Utils::split(lines.at(TX_BYTES_INDEX), ' ').back(), &valueSize);

                    if (Utils::split(lines.at(TX_BYTES_INDEX), ' ').back().size() == valueSize)
                    {
                        statistic.txBytes = static_cast<unsigned int>(value);
                    }

                    value = std::stoi(Utils::split(lines.at(RX_DROPS_INDEX), ' ').back(), &valueSize);

                    if (Utils::split(lines.at(RX_DROPS_INDEX), ' ').back().size() == valueSize)
                    {
                        statistic.rxDropped = static_cast<unsigned int>(value);
                    }

                    value = std::stoi(Utils::split(lines.at(TX_DROPS_INDEX), ' ').back(), &valueSize);

                    if (Utils::split(lines.at(TX_DROPS_INDEX), ' ').back().size() == valueSize)
                    {
                        statistic.txDropped = static_cast<unsigned int>(value);
                    }
                }
                catch(...)
                {
                }
            }

            return statistic;
        }

        std::string type() const override
        {
            const auto buffer { Utils::exec("dladm show-phys " + this->name(), 256) };
            constexpr auto INDEX_TYPE_INTERFACE { 1 };
            std::string type { "" };

            if (!buffer.empty())
            {
                auto lines { Utils::split(buffer, '\n') };
                lines.erase(lines.begin ());

                try
                {
                    for (auto line : lines)
                    {
                        Utils::replaceAll(line, "\t", "");
                        auto fields { Utils::split(line, ' ') };
                        fields.erase(std::remove_if(fields.begin(), fields.end(), [](const std::string& s) { return s.empty(); }), fields.end());

                        type = fields.at(INDEX_TYPE_INTERFACE);
                    }
                }
                catch(...)
                {
                }
            }

            return type;
        }

        std::string state() const override
        {
            return m_interfaceFlags & IFF_UP ? "up" : "down";
        }

        std::string MAC() const override
        {
            std::string mac { UNKNOWN_VALUE };
            const auto buffer { Utils::exec("ifconfig " + this->name()) };
            if (!buffer.empty())
            {
                const auto lines { Utils::split(buffer, '\n') };
                for (auto line : lines)
                {
                    Utils::replaceAll(line, "\t", "");
                    const auto fields { Utils::split(line, ' ') };
                    if (fields.size() == MAC_SIZE_FIELDS && fields.front().compare("ether") == 0)
                    {
                        mac = fields[MAC_ADDRESS];
                        break;
                    }
                }
            }
            return mac;
        }
};

#endif // _NETWORK_SOLARIS_WRAPPER_H
