/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * November 5, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_WINDOWS_WRAPPER_H
#define _NETWORK_WINDOWS_WRAPPER_H

#include <sstream>
#include <iomanip>
#include <ifdef.h>
#include <iptypes.h>
#include <netioapi.h>
#include "windowsHelper.h"
#include "inetworkWrapper.h"
#include "makeUnique.h"
#include "sharedDefs.h"

static const std::map<int, std::string> NETWORK_INTERFACE_TYPES =
{
    { IF_TYPE_ETHERNET_CSMACD, "ethernet"       },
    { IF_TYPE_ISO88025_TOKENRING, "token ring"     },
    { IF_TYPE_PPP, "point-to-point" },
    { IF_TYPE_ATM, "ATM"            },
    { IF_TYPE_IEEE80211, "wireless"       },
    { IF_TYPE_TUNNEL, "tunnel"         },
    { IF_TYPE_IEEE1394, "firewire"       },
};

static const std::map<IF_OPER_STATUS, std::string> NETWORK_OPERATIONAL_STATUS =
{
    { IfOperStatusUp, "up"             },
    { IfOperStatusDown, "down"           },
    { IfOperStatusTesting, "testing"        },          // In testing mode
    { IfOperStatusUnknown, "unknown"        },
    { IfOperStatusDormant, "dormant"        },          // In a pending state, waiting for some external event
    { IfOperStatusNotPresent, "notpresent"     },       // Interface down because of any component is not present (hardware typically)
    { IfOperStatusLowerLayerDown, "lowerlayerdown" },   // This interface depends on a lower layer interface which is down
};

class NetworkWindowsInterface final : public INetworkInterfaceWrapper
{
    public:
        explicit NetworkWindowsInterface(Utils::NetworkWindowsHelper::NetworkFamilyTypes family,
                                         const PIP_ADAPTER_ADDRESSES& addrs,
                                         const PIP_ADAPTER_UNICAST_ADDRESS& unicastAddress,
                                         const PIP_ADAPTER_INFO& adapterInfo)
            : m_interfaceFamily(family)
            , m_interfaceAddress(addrs)
            , m_currentUnicastAddress(unicastAddress)
            , m_adapterInfo(adapterInfo)
        {
            if (!addrs)
            {
                throw std::runtime_error { "Nullptr instance of network interface" };
            }

            if (Utils::NetworkWindowsHelper::NetworkFamilyTypes::UNDEF == family)
            {
                throw std::runtime_error { "Undefined network instance family value" };
            }
        }

        std::string name() const override
        {
            return getAdapterEncodedUTF8(m_interfaceAddress->FriendlyName);
        }

        std::string adapter() const override
        {
            return getAdapterEncodedUTF8(m_interfaceAddress->Description);
        }

        int family() const override
        {
            return m_interfaceFamily;
        }

        std::string address() const override
        {
            std::string retVal;

            if (m_currentUnicastAddress)
            {
                retVal = Utils::NetworkWindowsHelper::IAddressToString(this->adapterFamily(),
                                                                       (reinterpret_cast<sockaddr_in*>(m_currentUnicastAddress->Address.lpSockaddr))->sin_addr);
            }

            return retVal;
        }

        std::string addressV6() const override
        {
            std::string retVal;

            if (m_currentUnicastAddress)
            {
                retVal = Utils::NetworkWindowsHelper::IAddressToString(this->adapterFamily(),
                                                                       (reinterpret_cast<sockaddr_in6*>(m_currentUnicastAddress->Address.lpSockaddr))->sin6_addr);
            }

            return retVal;
        }

        std::string netmask() const override
        {
            std::string retVal;

            ULONG mask { 0 };
            static auto pfnGetConvertLengthToIpv4Mask { Utils::getConvertLengthToIpv4MaskFunctionAddress() };

            if (pfnGetConvertLengthToIpv4Mask)
            {
                if (m_currentUnicastAddress && !pfnGetConvertLengthToIpv4Mask(m_currentUnicastAddress->OnLinkPrefixLength, &mask))
                {
                    retVal = Utils::NetworkWindowsHelper::IAddressToString(this->adapterFamily(), *(reinterpret_cast<in_addr*>(&mask)));
                }
            }

            return retVal;
        }

        std::string netmaskV6() const override
        {
            std::string retVal;

            if (m_currentUnicastAddress)
            {
                // Get ipv6Netmask based on current OnLinkPrefixLength value
                retVal = Utils::NetworkWindowsHelper::ipv6Netmask(m_currentUnicastAddress->OnLinkPrefixLength);
            }

            return retVal;
        }

        std::string broadcast() const override
        {
            std::string retVal { UNKNOWN_VALUE };
            const auto address { this->address() };
            const auto netmask { this->netmask() };

            if (address.size() && netmask.size())
            {
                const auto broadcast { Utils::NetworkWindowsHelper::broadcastAddress(address, netmask) };
                retVal = broadcast.empty() ? UNKNOWN_VALUE : broadcast;
            }

            return retVal;
        }

        std::string broadcastV6() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string gateway() const override
        {
            std::string retVal;
            constexpr auto GATEWAY_SEPARATOR { "," };

            auto gatewayAddress { m_interfaceAddress->FirstGatewayAddress };

            while (gatewayAddress)
            {
                const auto gatewayFamily { gatewayAddress->Address.lpSockaddr->sa_family };
                const auto sockAddress   { gatewayAddress->Address.lpSockaddr };

                if (AF_INET == gatewayFamily)
                {
                    retVal += Utils::NetworkWindowsHelper::IAddressToString(gatewayFamily,
                                                                            (reinterpret_cast<sockaddr_in*>(sockAddress))->sin_addr);
                    retVal += GATEWAY_SEPARATOR;
                }
                else if (AF_INET6 == gatewayFamily)
                {
                    retVal += Utils::NetworkWindowsHelper::IAddressToString(gatewayFamily,
                                                                            (reinterpret_cast<sockaddr_in6*>(sockAddress))->sin6_addr);
                    retVal += GATEWAY_SEPARATOR;
                }

                gatewayAddress = gatewayAddress->Next;
            }

            if (retVal.empty())
            {
                retVal = UNKNOWN_VALUE;
            }
            else
            {
                // Remove last GATEWAY_SEPARATOR (,)
                retVal = retVal.substr(0, retVal.size() - 1);
            }

            return retVal;
        }

        std::string metrics() const override
        {
            std::string retVal;

            retVal = std::to_string(m_interfaceAddress->Ipv4Metric);

            return retVal;
        }

        std::string metricsV6() const override
        {
            std::string retVal;

            retVal = std::to_string(m_interfaceAddress->Ipv6Metric);

            return retVal;
        }

        uint32_t dhcp() const override
        {
            uint32_t retVal { 0 };
            const auto family { this->adapterFamily() };

            if (AF_INET == family)
            {
                const bool ipv4DHCPEnabled
                {
                    (m_interfaceAddress->Flags & IP_ADAPTER_DHCP_ENABLED)&& (m_interfaceAddress->Flags & IP_ADAPTER_IPV4_ENABLED)
                };
                retVal = ipv4DHCPEnabled ? 1 : 0;
            }
            else if (AF_INET6 == family)
            {
                const bool ipv6DHCPEnabled
                {
                    (m_interfaceAddress->Flags & IP_ADAPTER_DHCP_ENABLED)&& (m_interfaceAddress->Flags & IP_ADAPTER_IPV6_ENABLED)
                };
                retVal = ipv6DHCPEnabled ? 1 : 0;
            }

            return retVal;
        }

        uint32_t mtu() const override
        {
            return m_interfaceAddress->Mtu;
        }

        LinkStats stats() const override
        {
            LinkStats retVal {};
            auto ifRow { std::make_unique<MIB_IF_ROW2>() };

            if (!ifRow)
            {
                throw std::system_error
                {
                    static_cast<int>(GetLastError()),
                    std::system_category(),
                    "Unable to allocate memory for MIB_IF_ROW2 struct."
                };
            }

            ifRow->InterfaceIndex = (0 != m_interfaceAddress->IfIndex) ? m_interfaceAddress->IfIndex
                                    : m_interfaceAddress->Ipv6IfIndex;

            if (0 != ifRow->InterfaceIndex)
            {
                static auto pfnGetIfEntry2 { Utils::getIfEntry2FunctionAddress() };

                if (pfnGetIfEntry2)
                {
                    if (NO_ERROR == pfnGetIfEntry2(ifRow.get()))
                    {
                        const auto txPackets { ifRow->OutUcastPkts + ifRow->OutNUcastPkts };
                        const auto rxPackets { ifRow->InUcastPkts  + ifRow->InNUcastPkts  };
                        retVal.txPackets = txPackets;
                        retVal.rxPackets = rxPackets;
                        retVal.txBytes   = ifRow->OutOctets;
                        retVal.rxBytes   = ifRow->InOctets;
                        retVal.txErrors  = ifRow->OutErrors;
                        retVal.rxErrors  = ifRow->InErrors;
                        retVal.txDropped = ifRow->OutDiscards;
                        retVal.rxDropped = ifRow->InDiscards;
                    }
                }
            }

            return retVal;
        }

        std::string type() const override
        {
            std::string retVal { UNKNOWN_VALUE };
            const auto interfaceType { NETWORK_INTERFACE_TYPES.find(m_interfaceAddress->IfType) };

            if (NETWORK_INTERFACE_TYPES.end() != interfaceType)
            {
                retVal = interfaceType->second;
            }

            return retVal;
        }

        std::string state() const override
        {
            std::string retVal { UNKNOWN_VALUE };
            const auto opStatus { NETWORK_OPERATIONAL_STATUS.find(m_interfaceAddress->OperStatus) };

            if (NETWORK_OPERATIONAL_STATUS.end() != opStatus)
            {
                retVal = opStatus->second;
            }

            return retVal;
        }

        std::string MAC() const override
        {
            std::string retVal { "00:00:00:00:00:00" };
            constexpr auto MAC_ADDRESS_LENGTH { 6 };

            if (MAC_ADDRESS_LENGTH == m_interfaceAddress->PhysicalAddressLength)
            {
                std::stringstream ss;

                for (unsigned int idx = 0; idx < MAC_ADDRESS_LENGTH; ++idx)
                {
                    ss << std::hex << std::setfill('0') << std::setw(2);
                    ss << static_cast<int>(static_cast<uint8_t>(m_interfaceAddress->PhysicalAddress[idx]));

                    if (MAC_ADDRESS_LENGTH - 1 != idx)
                    {
                        ss << ":";
                    }
                }

                retVal = ss.str();
            }

            return retVal;
        }

    private:

        std::string getAdapterEncodedUTF8(const std::wstring& name) const
        {
            const std::string utf8AdapterName { Utils::NetworkWindowsHelper::getAdapterNameStr(name) };
            return utf8AdapterName.empty() ? " " : utf8AdapterName;
        }

        int adapterFamily() const
        {
            return m_currentUnicastAddress ? m_currentUnicastAddress->Address.lpSockaddr->sa_family
                   : AF_UNSPEC;
        }

        PIP_ADDR_STRING findInterfaceMatch(const std::string& address) const
        {
            PIP_ADDR_STRING currentInterfaceAddr { nullptr };
            PIP_ADAPTER_INFO currentAdapterInfo { m_adapterInfo };
            bool foundMatch { false };

            while (currentAdapterInfo && !foundMatch)
            {
                if (!(MIB_IF_TYPE_LOOPBACK == currentAdapterInfo->Type))
                {
                    if (currentAdapterInfo->Index == m_interfaceAddress->IfIndex)
                    {
                        // Found an interface match. Now we need an IPv4 match.
                        currentInterfaceAddr = &(currentAdapterInfo->IpAddressList);

                        while (currentInterfaceAddr)
                        {
                            if (strncmp(address.c_str(), currentInterfaceAddr->IpAddress.String, address.length()) == 0)
                            {
                                // IPv4 match found
                                break;
                            }

                            currentInterfaceAddr = currentInterfaceAddr->Next;
                        }

                        foundMatch = true;
                    }
                }

                currentAdapterInfo = currentAdapterInfo->Next;
            }

            return currentInterfaceAddr;
        }

        Utils::NetworkWindowsHelper::NetworkFamilyTypes m_interfaceFamily;
        PIP_ADAPTER_ADDRESSES                           m_interfaceAddress;
        PIP_ADAPTER_UNICAST_ADDRESS                     m_currentUnicastAddress;
        PIP_ADAPTER_INFO                                m_adapterInfo;
};

#endif //_NETWORK_WINDOWS_WRAPPER_H
