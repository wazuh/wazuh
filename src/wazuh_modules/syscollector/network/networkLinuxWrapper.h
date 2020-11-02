#ifndef _NETWORK_LINUX_WRAPPER_H
#define _NETWORK_LINUX_WRAPPER_H

#include <net/if_arp.h>
#include "inetworkWrapper.h"
#include "networkHelper.h"
#include "filesystemHelper.h"
#include "stringHelper.h"
#include "sharedDefs.h"

static const std::map<std::pair<int, int>, std::string> NETWORK_INTERFACE_TYPE =
{
    { std::make_pair(ARPHRD_ETHER, ARPHRD_ETHER),               "ethernet"          },
    { std::make_pair(ARPHRD_PRONET, ARPHRD_PRONET),             "token ring"        },
    { std::make_pair(ARPHRD_PPP, ARPHRD_PPP),                   "point-to-point"    },
    { std::make_pair(ARPHRD_ATM, ARPHRD_ATM),                   "ATM"               },
    { std::make_pair(ARPHRD_IEEE1394, ARPHRD_IEEE1394),         "firewire"          },
    { std::make_pair(ARPHRD_TUNNEL, ARPHRD_IRDA),               "tunnel"            },
    { std::make_pair(ARPHRD_FCPP, ARPHRD_FCFABRIC),             "fibrechannel"      },
    { std::make_pair(ARPHRD_IEEE802_TR, ARPHRD_IEEE802154_PHY), "wireless"          },
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

class NetworkLinuxInterface final : public INetworkInterfaceWrapper
{
    ifaddrs* m_interfaceAddress;
    static std::string getNameInfo(const sockaddr* inputData, const socklen_t socketLen)
    {
        auto retVal { std::make_unique<char[]>(NI_MAXHOST) };
        if (inputData)
        {
            const auto result = getnameinfo(inputData,
                socketLen,
                retVal.get(), NI_MAXHOST,
                NULL, 0, NI_NUMERICHOST);
            
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
 
    static std::string getRedHatDHCPStatus(const std::vector<std::string>& fields)
    {
        std::string retVal { "unknown" };
        const auto value { fields.at(RHInterfaceConfig::Value) };
        
        if (value.compare("static") == 0 || value.compare("none") == 0 || value.compare("no") == 0)
        {
            retVal = "disabled";
        }
        else if (value.compare("dhcp") == 0 || value.compare("yes") == 0)
        {
            retVal = "enabled";
        }
        else if (value.compare("bootp") == 0)
        {
            retVal = "BOOTP";
        }

        return retVal;
    }

    static std::string getDebianDHCPStatus(const std::string& family, const std::vector<std::string>& fields)
    {
        std::string retVal { "enabled" };
        if (fields.at(DebianInterfaceConfig::Family).compare(family) == 0)
        {
            const auto method { fields.at(DebianInterfaceConfig::Method) };
            if (method.compare("static") == 0 || method.compare("manual") == 0)
            {
                retVal = "disabled";
            }
            else if (method.compare("dhcp") == 0)
            {
                retVal = "enabled";
            }
        }
        return retVal;
    }
    public:
    explicit NetworkLinuxInterface(ifaddrs* addrs)
    : m_interfaceAddress(addrs)
    { 
        if (!addrs)
        {
            throw std::runtime_error { "Nullptr instances of network interface" };
        }
    }

    std::string name() override
    {
        return m_interfaceAddress->ifa_name ? m_interfaceAddress->ifa_name : "";
    }

    int family() override
    {
        return m_interfaceAddress->ifa_addr ? m_interfaceAddress->ifa_addr->sa_family : AF_UNSPEC;
    }

    std::string address() override
    {
        return m_interfaceAddress->ifa_addr ? getNameInfo(m_interfaceAddress->ifa_addr, sizeof(struct sockaddr_in)) : "";
    }
    
    std::string netmask() override
    {
        return m_interfaceAddress->ifa_netmask ? getNameInfo(m_interfaceAddress->ifa_netmask, sizeof(struct sockaddr_in)) : "";
    }

    std::string broadcast() override
    {
        std::string retVal;
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
                retVal = Utils::NetworkHelper::getBroadcast(address, netmask);
            }
        }
        return retVal;
    }

    std::string addressV6() override
    {
        return m_interfaceAddress->ifa_addr ? Utils::splitIndex(getNameInfo(m_interfaceAddress->ifa_addr, sizeof(struct sockaddr_in6)), '%', 0) : "";
    }
    std::string netmaskV6() override
    {
        return m_interfaceAddress->ifa_netmask ? getNameInfo(m_interfaceAddress->ifa_netmask, sizeof(struct sockaddr_in6)) : "";
    }
    std::string broadcastV6() override
    {
        return m_interfaceAddress->ifa_ifu.ifu_broadaddr ? getNameInfo(m_interfaceAddress->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr_in6)) : "";
    }
    std::string gateway() override
    {
        std::string retVal { "unknown" };
        auto fileData { Utils::getFileContent(std::string(WM_SYS_NET_DIR) + "route") };
        const auto ifName { this->name() };
        if (!fileData.empty())
        {
            auto lines { Utils::split(fileData, '\n') };
            for (auto& line : lines)
            {
                line = Utils::rightTrim(line);
                Utils::replaceAll(line, "\t", " ");
                Utils::replaceAll(line, "  ", " ");
                const auto fields { Utils::split(line, ' ') };

                if (GatewayFileFields::Size == fields.size())
                {
                    if (fields.at(GatewayFileFields::Iface).compare(ifName) == 0)
                    {
                        const auto address { static_cast<uint32_t>(std::stoi(fields.at(GatewayFileFields::Gateway), 0, 16)) };
                        if (address)
                        {
                            retVal = std::string(inet_ntoa({ address })) + "|" + fields.at(GatewayFileFields::Metric);
                        }
                    }
                }
            }
        }
        return retVal;
    }

    std::string dhcp() override
    {
        auto fileData { Utils::getFileContent(WM_SYS_IF_FILE) };
        std::string retVal { "unknown" };
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
                        }
                        else if (AF_INET6 == family)
                        {
                            retVal = getDebianDHCPStatus("inet6", fields);
                        }
                    }
                }
            }
        }
        else
        {
            const auto fileName { "ifcfg-" + ifName };
            fileData = Utils::getFileContent(WM_SYS_IF_DIR_RH + fileName);
            fileData = fileData.empty() ? Utils::getFileContent(WM_SYS_IF_DIR_SUSE + fileName) : fileData;

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
                            }
                        }
                        else if (AF_INET6 == family)
                        {
                            if (fields.at(RHInterfaceConfig::Key).compare("DHCPV6C") == 0)
                            {
                                retVal = getRedHatDHCPStatus(fields);
                            }
                        }
                    }
                }
            }
        }
        return retVal;
    }
    std::string mtu() override
    {
        std::string retVal;
        const auto name { this->name() };
        if (!name.empty())
        {
            const auto mtuFileContent { Utils::getFileContent(std::string(WM_SYS_IFDATA_DIR) + name + "/mtu") };
            retVal = Utils::splitIndex(mtuFileContent, '\n', 0);
        }
        return retVal;
    }

    LinkStats stats() override
    {
        return m_interfaceAddress->ifa_data ? *reinterpret_cast<LinkStats *>(m_interfaceAddress->ifa_data) : LinkStats();
    }
    
    std::string type() override
    {
        const auto networkTypeCode { Utils::getFileContent(std::string(WM_SYS_IFDATA_DIR) + this->name() + "/type") };
        return Utils::NetworkHelper::getNetworkTypeStringCode(std::stoi(networkTypeCode), NETWORK_INTERFACE_TYPE);
    }
    std::string state() override
    {
        const auto operationalState { Utils::getFileContent(std::string(WM_SYS_IFDATA_DIR) + this->name() + "/operstate") };
        return Utils::splitIndex(operationalState, '\n', 0);
    }
    std::string MAC() override
    {
        const auto mac { Utils::getFileContent(std::string(WM_SYS_IFDATA_DIR) + this->name() + "/address")};
        return Utils::splitIndex(mac, '\n', 0);
    }
};

#endif // _NETWORK_LINUX_WRAPPER_H