/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_LINUX_WRAPPER_H
#define _NETWORK_LINUX_WRAPPER_H

#include <algorithm>
#include <cctype>
#include <ifaddrs.h>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <optional>
#include <net/if_arp.h>
#include <sys/socket.h>
#include "inetworkWrapper.h"
#include "networkHelper.h"
#include <file_io_utils.hpp>
#include "networkLinuxAddressResolver.h"
#include "stringHelper.h"
#include "sharedDefs.h"

#ifndef ARPHRD_TUNNEL
#define ARPHRD_TUNNEL   768     /* IPIP tunnel.  */
#endif
#ifndef ARPHRD_TUNNEL6
#define ARPHRD_TUNNEL6  769     /* IPIP6 tunnel.  */
#endif
#ifndef ARPHRD_FRAD
#define ARPHRD_FRAD 770             /* Frame Relay Access Device.  */
#endif
#ifndef ARPHRD_SKIP
#define ARPHRD_SKIP 771     /* SKIP vif.  */
#endif
#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 772     /* Loopback device.  */
#endif
#ifndef ARPHRD_LOCALTLK
#define ARPHRD_LOCALTLK 773     /* Localtalk device.  */
#endif
#ifndef ARPHRD_FDDI
#define ARPHRD_FDDI 774     /* Fiber Distributed Data Interface. */
#endif
#ifndef ARPHRD_BIF
#define ARPHRD_BIF  775             /* AP1000 BIF.  */
#endif
#ifndef ARPHRD_SIT
#define ARPHRD_SIT  776     /* sit0 device - IPv6-in-IPv4.  */
#endif
#ifndef ARPHRD_IPDDP
#define ARPHRD_IPDDP    777     /* IP-in-DDP tunnel.  */
#endif
#ifndef ARPHRD_IPGRE
#define ARPHRD_IPGRE    778     /* GRE over IP.  */
#endif
#ifndef ARPHRD_PIMREG
#define ARPHRD_PIMREG   779     /* PIMSM register interface.  */
#endif
#ifndef ARPHRD_HIPPI
#define ARPHRD_HIPPI    780     /* High Performance Parallel I'face. */
#endif
#ifndef ARPHRD_ASH
#define ARPHRD_ASH  781     /* (Nexus Electronics) Ash.  */
#endif
#ifndef ARPHRD_ECONET
#define ARPHRD_ECONET   782     /* Acorn Econet.  */
#endif
#ifndef ARPHRD_IRDA
#define ARPHRD_IRDA 783     /* Linux-IrDA.  */
#endif
#ifndef ARPHRD_FCPP
#define ARPHRD_FCPP 784     /* Point to point fibrechanel.  */
#endif
#ifndef ARPHRD_FCAL
#define ARPHRD_FCAL 785     /* Fibrechanel arbitrated loop.  */
#endif
#ifndef ARPHRD_FCPL
#define ARPHRD_FCPL 786     /* Fibrechanel public loop.  */
#endif
#ifndef ARPHRD_FCFABRIC
#define ARPHRD_FCFABRIC 787     /* Fibrechanel fabric.  */
#endif
#ifndef ARPHRD_IEEE802_TR
#define ARPHRD_IEEE802_TR 800       /* Magic type ident for TR.  */
#endif
#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801        /* IEEE 802.11.  */
#endif
#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802  /* IEEE 802.11 + Prism2 header.  */
#endif
#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803   /* IEEE 802.11 + radiotap header.  */
#endif
#ifndef ARPHRD_IEEE802154
#define ARPHRD_IEEE802154 804       /* IEEE 802.15.4 header.  */
#endif
#ifndef ARPHRD_IEEE802154_PHY
#define ARPHRD_IEEE802154_PHY 805 /* IEEE 802.15.4 PHY header.  */
#endif

static const std::map<std::pair<int, int>, std::string> NETWORK_INTERFACE_TYPE =
{
    { std::make_pair(ARPHRD_ETHER, ARPHRD_ETHER),               "ethernet"          },
    { std::make_pair(ARPHRD_PRONET, ARPHRD_PRONET),             "token ring"        },
    { std::make_pair(ARPHRD_PPP, ARPHRD_PPP),                   "point-to-point"    },
    { std::make_pair(ARPHRD_ATM, ARPHRD_ATM),                   "ATM"               },
    { std::make_pair(ARPHRD_IEEE1394, ARPHRD_IEEE1394),         "firewire"          },
    { std::make_pair(ARPHRD_LOOPBACK, ARPHRD_LOOPBACK),         "loopback"          },
    { std::make_pair(ARPHRD_TUNNEL, ARPHRD_IRDA),               "tunnel"            },
    { std::make_pair(ARPHRD_FCPP, ARPHRD_FCFABRIC),             "fibrechannel"      },
    { std::make_pair(ARPHRD_IEEE802_TR, ARPHRD_IEEE802154_PHY), "wireless"          },
};

static const std::map<std::string, uint32_t> DHCP_STATUS =
{
    { "dhcp",                   1           },
    { "yes",                    1           },
    { "static",                 0           },
    { "none",                   0           },
    { "no",                     0           },
    { "manual",                 0           },
    { "bootp",                  1           },
    // SUSE (wicked) BOOTPROTO values that start a DHCPv4 client
    { "dhcp4",                  1           },
    { "dhcp+autoip",            1           },
    // Boolean spellings that ifcfg-rh accepts for DHCPV6C
    { "1",                      1           },
    { "true",                   1           },
    { "y",                      1           },
    { "t",                      1           },
    { "0",                      0           },
    { "false",                  0           },
    { "n",                      0           },
    { "f",                      0           },
};

namespace GatewayFileFields
{
    enum
    {
        Iface,
        Destination,
        Gateway,
        Flags,
        RefCnt,
        Use,
        Metric,
        Mask,
        MTU,
        Window,
        IRTT,
        Size
    };
}

namespace GatewayV6FileFields
{
    enum
    {
        Destination,
        DestinationPrefix,
        Source,
        SourcePrefix,
        NextHop,
        Metric,
        RefCnt,
        Use,
        Flags,
        Iface,
        Size
    };
}

namespace DebianInterfaceConfig
{
    enum Config
    {
        Type,
        Name,
        Family,
        Method,
        Size
    };
}

namespace RHInterfaceConfig
{
    enum Config
    {
        Key,
        Value,
        Size
    };
}

namespace NetDevFileFields
{
    enum
    {
        Iface,
        RxBytes,
        RxPackets,
        RxErrors,
        RxDropped,
        RxFifo,
        RxFrame,
        RxCompressed,
        RxMulticast,
        TxBytes,
        TxPackets,
        TxErrors,
        TxDropped,
        TxFifo,
        TxColls,
        TxCarrier,
        TxCompressed,
        FieldsQuantity
    };
}

class NetworkLinuxInterface final : public INetworkInterfaceWrapper
{
        ifaddrs* m_interfaceAddress;
        std::string m_interfaceName;
        std::string m_gateway;
        std::string m_metrics;
        std::shared_ptr<const IPv4AddressFlags> m_addressFlags;

        // Prefix length of an IPv4 entry, counted from its netmask; 0 without one.
        unsigned int prefixLength() const
        {
            const auto netmask { reinterpret_cast<const sockaddr_in*>(m_interfaceAddress->ifa_netmask) };
            return netmask ? static_cast<unsigned int>(__builtin_popcount(ntohl(netmask->sin_addr.s_addr))) : 0;
        }

        static std::string getNameInfo(const sockaddr* inputData, const socklen_t socketLen)
        {
            auto retVal { std::make_unique<char[]>(NI_MAXHOST) };

            if (inputData)
            {
                const auto result { getnameinfo(inputData,
                                                socketLen,
                                                retVal.get(), NI_MAXHOST,
                                                NULL, 0, NI_NUMERICHOST) };

                if (result != 0)
                {
                    throw std::runtime_error
                    {
                        "Cannot get socket address information, Code: " + result
                    };
                }
            }

            return retVal.get();
        }

        static uint32_t getDebianDHCPStatus(const std::string& family, const std::vector<std::string>& fields)
        {
            uint32_t retVal { 1 };

            if (fields.at(DebianInterfaceConfig::Family).compare(family) == 0)
            {
                const auto method { fields.at(DebianInterfaceConfig::Method) };

                const auto it { DHCP_STATUS.find(method) };

                if (DHCP_STATUS.end() != it)
                {
                    retVal = it->second;
                }
            }

            return retVal;
        }

    public:
        // interfaceName is the link holding the entry; for IPv4 entries ifa_name is the address label.
        NetworkLinuxInterface(ifaddrs* addrs, const std::string& interfaceName, std::shared_ptr<const IPv4AddressFlags> addressFlags = nullptr)
            : m_interfaceAddress{ addrs }
            , m_interfaceName{ interfaceName }
            , m_gateway{UNKNOWN_VALUE}
            , m_addressFlags{ std::move(addressFlags) }
        {
            if (!addrs)
            {
                throw std::runtime_error { "Nullptr instances of network interface" };
            }
            else
            {
                const file_io::FileIOUtils ioUtils;
                auto fileData { ioUtils.getFileContent(std::string(WM_SYS_NET_DIR) + "route") };
                const auto ifName { this->name() };

                if (!fileData.empty())
                {
                    auto lines { Utils::split(fileData, '\n') };

                    for (auto& line : lines)
                    {
                        line = Utils::rightTrim(line);
                        Utils::replaceAll(line, "\t", " ");
                        line = Utils::trimRepeated(line, ' ');
                        const auto fields { Utils::split(line, ' ') };

                        if (GatewayFileFields::Size == fields.size() &&
                                fields.at(GatewayFileFields::Iface).compare(ifName) == 0)
                        {
                            auto address { static_cast<uint32_t>(std::stol(fields.at(GatewayFileFields::Gateway), 0, 16)) };
                            m_metrics = fields.at(GatewayFileFields::Metric);

                            if (address)
                            {
                                m_gateway = Utils::NetworkHelper::IAddressToBinary(AF_INET, reinterpret_cast<in_addr*>(&address));
                                break;
                            }
                        }
                    }
                }
            }
        }

        std::string name() const override
        {
            return m_interfaceName;
        }

        std::string adapter() const override
        {
            return "";
        }

        int family() const override
        {
            return m_interfaceAddress->ifa_addr ? m_interfaceAddress->ifa_addr->sa_family : AF_PACKET;
        }

        std::string address() const override
        {
            return m_interfaceAddress->ifa_addr ? getNameInfo(m_interfaceAddress->ifa_addr, sizeof(struct sockaddr_in)) : "";
        }

        std::string netmask() const override
        {
            return m_interfaceAddress->ifa_netmask ? getNameInfo(m_interfaceAddress->ifa_netmask, sizeof(struct sockaddr_in)) : "";
        }

        std::string broadcast() const override
        {
            std::string retVal { UNKNOWN_VALUE };

            if (m_interfaceAddress->ifa_ifu.ifu_broadaddr)
            {
                retVal = getNameInfo(m_interfaceAddress->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr_in));
            }
            else
            {
                const auto netmask { this->netmask() };
                const auto address { this->address() };

                if (address.size() && netmask.size())
                {
                    const auto broadcast { Utils::NetworkHelper::getBroadcast(address, netmask) };
                    retVal =  broadcast.empty() ? UNKNOWN_VALUE : broadcast;
                }
            }

            return retVal;
        }

        std::string addressV6() const override
        {
            return m_interfaceAddress->ifa_addr ? Utils::splitIndex(getNameInfo(m_interfaceAddress->ifa_addr, sizeof(struct sockaddr_in6)), '%', 0) : "";
        }

        std::string netmaskV6() const override
        {
            return m_interfaceAddress->ifa_netmask ? getNameInfo(m_interfaceAddress->ifa_netmask, sizeof(struct sockaddr_in6)) : "";
        }

        std::string broadcastV6() const override
        {
            return m_interfaceAddress->ifa_ifu.ifu_broadaddr ? getNameInfo(m_interfaceAddress->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr_in6)) : "";
        }

        std::string gateway() const override
        {
            return m_gateway;
        }

        std::string gatewayV6() const override
        {
            const file_io::FileIOUtils ioUtils;
            return parseGatewayV6(ioUtils.getFileContent(std::string(WM_SYS_NET_DIR) + "ipv6_route"), this->name());
        }

        // Next hop of the ::/0 route of ifName in /proc/net/ipv6_route format
        static std::string parseGatewayV6(const std::string& routeTable, const std::string& ifName)
        {
            constexpr auto IPV6_HEX_LENGTH { 32 };
            constexpr auto RTF_UP_GATEWAY { 0x0003 };
            const std::string ANY_ADDRESS(IPV6_HEX_LENGTH, '0');
            const auto isHex
            {
                [](const std::string & value)
                {
                    return !value.empty() && std::all_of(value.begin(), value.end(), [](const unsigned char c)
                    {
                        return std::isxdigit(c) != 0;
                    });
                }
            };
            std::string retVal { UNKNOWN_VALUE };

            for (auto& line : Utils::split(routeTable, '\n'))
            {
                Utils::replaceAll(line, "\t", " ");
                line = Utils::trimRepeated(Utils::trim(line), ' ');
                const auto fields { Utils::split(line, ' ') };

                if (GatewayV6FileFields::Size == fields.size() &&
                        fields.at(GatewayV6FileFields::Iface).compare(ifName) == 0 &&
                        fields.at(GatewayV6FileFields::Destination).compare(ANY_ADDRESS) == 0 &&
                        fields.at(GatewayV6FileFields::DestinationPrefix).compare("00") == 0 &&
                        fields.at(GatewayV6FileFields::SourcePrefix).compare("00") == 0 &&
                        fields.at(GatewayV6FileFields::NextHop).size() == IPV6_HEX_LENGTH &&
                        fields.at(GatewayV6FileFields::NextHop).compare(ANY_ADDRESS) != 0 &&
                        isHex(fields.at(GatewayV6FileFields::NextHop)) &&
                        fields.at(GatewayV6FileFields::Flags).size() <= 8 &&
                        isHex(fields.at(GatewayV6FileFields::Flags)) &&
                        (std::stoul(fields.at(GatewayV6FileFields::Flags), nullptr, 16) & RTF_UP_GATEWAY) == RTF_UP_GATEWAY)
                {
                    const auto& nextHop { fields.at(GatewayV6FileFields::NextHop) };
                    in6_addr address {};

                    for (size_t i = 0; i < sizeof(address.s6_addr); ++i)
                    {
                        address.s6_addr[i] = static_cast<uint8_t>(std::stoul(nextHop.substr(i * 2, 2), nullptr, 16));
                    }

                    retVal = Utils::NetworkHelper::IAddressToBinary(AF_INET6, &address);
                    break;
                }
            }

            return retVal;
        }

        // Value of an ifcfg entry without surrounding whitespace and one pair of matching quotes
        static std::string stripQuotes(const std::string& value)
        {
            auto retVal { Utils::trim(value, " \t\r") };

            if (retVal.size() >= 2 && (retVal.front() == '"' || retVal.front() == '\'') && retVal.back() == retVal.front())
            {
                retVal = retVal.substr(1, retVal.size() - 2);
            }

            return retVal;
        }

        // Values are compared case-insensitively, as NetworkManager's ifcfg-rh plugin does. A value
        // outside the table says nothing (std::nullopt), so the runtime check can still answer.
        static std::optional<uint32_t> getRedHatDHCPStatus(const std::vector<std::string>& fields)
        {
            std::optional<uint32_t> retVal;
            const auto value { Utils::toLowerCase(stripQuotes(fields.at(RHInterfaceConfig::Value))) };

            const auto it { DHCP_STATUS.find(value) };

            if (DHCP_STATUS.end() != it)
            {
                retVal = it->second;
            }

            return retVal;
        }

        // The configuration files win. Without an answer from them, an address that is not permanent
        // was installed with a lifetime, which is what a DHCP client does. A permanent address, or no
        // flags, says nothing either way, which is reported as disabled.
        static uint32_t resolveDhcp(const std::optional<uint32_t>& fileResult, const bool flagsKnown, const uint32_t flags)
        {
            if (fileResult.has_value())
            {
                return fileResult.value();
            }

            return (flagsKnown && !(flags & IFA_F_PERMANENT)) ? 1 : 0;
        }

        std::string metrics() const override
        {
            return m_metrics;
        }

        std::string metricsV6() const override
        {
            return "";
        }

        uint32_t dhcp() const override
        {
            const file_io::FileIOUtils ioUtils;
            auto fileData { ioUtils.getFileContent(WM_SYS_IF_FILE) };
            std::optional<uint32_t> retVal;
            const auto family { this->family() };
            const auto ifName { this->name() };

            if (!fileData.empty())
            {
                const auto lines { Utils::split(fileData, '\n') };

                for (const auto& line : lines)
                {
                    const auto fields { Utils::split(line, ' ') };

                    if (DebianInterfaceConfig::Size == fields.size())
                    {
                        if (fields.at(DebianInterfaceConfig::Type).compare("iface") == 0 &&
                                fields.at(DebianInterfaceConfig::Name).compare(ifName) == 0)
                        {
                            if (AF_INET == family)
                            {
                                retVal = getDebianDHCPStatus("inet", fields);
                                break;
                            }
                            else if (AF_INET6 == family)
                            {
                                retVal = getDebianDHCPStatus("inet6", fields);
                                break;
                            }
                        }
                    }
                }
            }
            else
            {
                const auto fileName { "ifcfg-" + ifName };
                fileData = ioUtils.getFileContent(WM_SYS_IF_DIR_RH + fileName);
                fileData = fileData.empty() ? ioUtils.getFileContent(WM_SYS_IF_DIR_SUSE + fileName) : fileData;

                if (!fileData.empty())
                {
                    const auto lines { Utils::split(fileData, '\n') };

                    for (const auto& line : lines)
                    {
                        const auto fields { Utils::split(line, '=') };

                        if (fields.size() == RHInterfaceConfig::Size)
                        {
                            if (AF_INET == family)
                            {
                                if (fields.at(RHInterfaceConfig::Key).compare("BOOTPROTO") == 0)
                                {
                                    retVal = getRedHatDHCPStatus(fields);
                                    break;
                                }
                            }
                            else if (AF_INET6 == family)
                            {
                                if (fields.at(RHInterfaceConfig::Key).compare("DHCPV6C") == 0)
                                {
                                    retVal = getRedHatDHCPStatus(fields);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Netplan, NetworkManager keyfiles and similar leave no file for the checks above
            auto flagsKnown { false };
            uint32_t flags { 0 };

            if (AF_INET == family && m_addressFlags)
            {
                const auto it { m_addressFlags->find(IPv4AddressKey { ifName, this->address(), prefixLength() }) };

                if (m_addressFlags->end() != it)
                {
                    flagsKnown = true;
                    flags = it->second;
                }
            }

            return resolveDhcp(retVal, flagsKnown, flags);
        }

        uint32_t mtu() const override
        {
            uint32_t retVal { 0 };
            const file_io::FileIOUtils ioUtils;
            const auto mtuFileContent {ioUtils.getFileContent(std::string(WM_SYS_IFDATA_DIR) + this->name() + "/mtu")};

            if (!mtuFileContent.empty())
            {
                retVal =  std::stol(Utils::splitIndex(mtuFileContent, '\n', 0));
            }

            return retVal;
        }

        LinkStats stats() const override
        {
            LinkStats retVal {};

            try
            {
                const file_io::FileIOUtils ioUtils;
                const auto devData {ioUtils.getFileContent(std::string(WM_SYS_NET_DIR) + "dev")};

                if (!devData.empty())
                {
                    auto lines { Utils::split(devData, '\n') };
                    lines.erase(lines.begin());
                    lines.erase(lines.begin());

                    for (auto& line : lines)
                    {
                        line = Utils::trim(line);
                        Utils::replaceAll(line, "\t", " ");
                        line = Utils::trimRepeated(line, ' ');
                        Utils::replaceAll(line, ": ", " ");
                        const auto fields { Utils::split(line, ' ') };

                        if (NetDevFileFields::FieldsQuantity == fields.size())
                        {
                            if (fields.at(NetDevFileFields::Iface).compare(this->name()) == 0)
                            {
                                retVal.rxBytes = std::stoul(fields.at(NetDevFileFields::RxBytes));
                                retVal.txBytes = std::stoul(fields.at(NetDevFileFields::TxBytes));
                                retVal.rxPackets = std::stoul(fields.at(NetDevFileFields::RxPackets));
                                retVal.txPackets = std::stoul(fields.at(NetDevFileFields::TxPackets));
                                retVal.rxErrors = std::stoul(fields.at(NetDevFileFields::RxErrors));
                                retVal.txErrors = std::stoul(fields.at(NetDevFileFields::TxErrors));
                                retVal.rxDropped = std::stoul(fields.at(NetDevFileFields::RxDropped));
                                retVal.txDropped = std::stoul(fields.at(NetDevFileFields::TxDropped));
                                break;
                            }
                        }
                    }
                }
            }
            catch (...)
            {
            }

            return retVal;
        }

        std::string type() const override
        {
            const file_io::FileIOUtils ioUtils;
            const auto networkTypeCode {ioUtils.getFileContent(std::string(WM_SYS_IFDATA_DIR) + this->name() + "/type")};
            std::string type { UNKNOWN_VALUE };

            if (!networkTypeCode.empty())
            {
                type = Utils::NetworkHelper::getNetworkTypeStringCode(std::stoi(networkTypeCode), NETWORK_INTERFACE_TYPE);
            }

            return type;
        }

        std::string state() const override
        {
            const file_io::FileIOUtils ioUtils;
            const std::string operationalState
            {
                ioUtils.getFileContent(std::string(WM_SYS_IFDATA_DIR) + this->name() + "/operstate")};

            std::string state { UNKNOWN_VALUE };

            if (!operationalState.empty())
            {
                state = Utils::splitIndex(operationalState, '\n', 0);

                // Drivers that do not implement carrier detection, loopback among them, report
                // "unknown" instead of an operational state; resolve those from the administrative
                // flag. Every remaining value means the interface is not carrying traffic.
                if ("up" != state && "down" != state)
                {
                    state = ("unknown" == state && (m_interfaceAddress->ifa_flags & IFF_UP)) ? "up" : "down";
                }
            }

            return state;
        }

        std::string MAC() const override
        {
            const file_io::FileIOUtils ioUtils;
            const std::string macContent
            {
                ioUtils.getFileContent(std::string(WM_SYS_IFDATA_DIR) + this->name() + "/address")};

            std::string mac { UNKNOWN_VALUE };

            if (!macContent.empty())
            {
                mac = Utils::splitIndex(macContent, '\n', 0);
            }

            return mac;
        }
};

#endif // _NETWORK_LINUX_WRAPPER_H
