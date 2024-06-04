/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * November 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PORT_LINUX_WRAPPER_H
#define _PORT_LINUX_WRAPPER_H

#include <netinet/tcp.h>
#include "iportWrapper.h"
#include "sharedDefs.h"
#include "bits/stdc++.h"

constexpr int IPV6_ADDRESS_HEX_SIZE { 32 };

enum AddressField
{
    IP,
    PORT,
    ADDRESS_FIELD_SIZE
};

enum QueueField
{
    TX,
    RX,
    QUEUE_FIELD_SIZE
};

static const std::map<PortType, std::string> PORTS_TYPE =
{
    { UDP_IPV4,                            "udp"            },
    { UDP_IPV6,                            "udp6"           },
    { TCP_IPV4,                            "tcp"            },
    { TCP_IPV6,                            "tcp6"           }
};

static const std::map<PortType, Protocol> PROTOCOL_TYPE =
{
    { UDP_IPV4,                            UDP              },
    { UDP_IPV6,                            UDP              },
    { TCP_IPV4,                            TCP              },
    { TCP_IPV6,                            TCP              }
};

static const std::map<PortType, IPVersion> IPVERSION_TYPE =
{
    { UDP_IPV4,                            IPV4             },
    { UDP_IPV6,                            IPV6             },
    { TCP_IPV4,                            IPV4             },
    { TCP_IPV6,                            IPV6             }
};

static const std::map<int32_t, std::string> STATE_TYPE =
{
    { TCP_ESTABLISHED,                     "established"    },
    { TCP_SYN_SENT,                        "syn_sent"       },
    { TCP_SYN_RECV,                        "syn_recv"       },
    { TCP_FIN_WAIT1,                       "fin_wait1"      },
    { TCP_FIN_WAIT2,                       "fin_wait2"      },
    { TCP_TIME_WAIT,                       "time_wait"      },
    { TCP_CLOSE,                           "close"          },
    { TCP_CLOSE_WAIT,                      "close_wait"     },
    { TCP_LAST_ACK,                        "last_ack"       },
    { TCP_LISTEN,                          "listening"      },
    { TCP_CLOSING,                         "closing"        }
};

class LinuxPortWrapper final : public IPortWrapper
{
        std::vector<std::string> m_fields;
        PortType m_type;
        std::vector<std::string> m_remoteAddresses;
        std::vector<std::string> m_localAddresses;
        std::vector<std::string> m_queue;

        static std::string IPv4Address(const std::string& hexRawAddress)
        {
            std::stringstream ss;
            in_addr addr;
            ss << std::hex << hexRawAddress;
            ss >> addr.s_addr;
            return Utils::NetworkHelper::IAddressToBinary(AF_INET, &addr);
        }

        static std::string IPv6Address(const std::string& hexRawAddress)
        {
            std::string retVal;

            const auto hexAddressLength { hexRawAddress.length() };

            if (hexAddressLength == IPV6_ADDRESS_HEX_SIZE)
            {
                in6_addr sin6 {};
                auto index { 0l };

                for (auto i = 0ull; i < hexAddressLength; i += CHAR_BIT)
                {
                    std::stringstream ss;
                    ss << std::hex << hexRawAddress.substr(CHAR_BIT * index, CHAR_BIT);
                    ss >> sin6.s6_addr32[index];
                    ++index;
                }

                retVal =  Utils::NetworkHelper::IAddressToBinary(AF_INET6, &sin6);
            }

            return retVal;
        }

    public:
        explicit LinuxPortWrapper(const PortType type, const std::string& row)
            : m_fields{ Utils::split(row, ' ') }
            , m_type { type }
            , m_remoteAddresses { std::move(Utils::split(m_fields.at(REMOTE_ADDRESS), ':')) }
            , m_localAddresses { std::move(Utils::split(m_fields.at(LOCAL_ADDRESS), ':')) }
            , m_queue { std::move(Utils::split(m_fields.at(QUEUE), ':')) }
        { }

        ~LinuxPortWrapper() = default;
        std::string protocol() const override
        {
            std::string retVal;

            const auto it { PORTS_TYPE.find(m_type) };

            if (PORTS_TYPE.end() != it)
            {
                retVal = it->second;
            }

            return retVal;
        }

        std::string localIp() const override
        {
            std::string retVal;

            if (m_localAddresses.size() == AddressField::ADDRESS_FIELD_SIZE)
            {
                if (IPVERSION_TYPE.at(m_type) == IPV4)
                {
                    retVal = IPv4Address(m_localAddresses.at(AddressField::IP));
                }
                else if (IPVERSION_TYPE.at(m_type) == IPV6)
                {
                    retVal = IPv6Address(m_localAddresses.at(AddressField::IP));
                }
            }

            return retVal;
        }
        int32_t localPort() const override
        {
            int32_t retVal { -1 };

            if (m_localAddresses.size() == AddressField::ADDRESS_FIELD_SIZE)
            {
                std::stringstream ss;
                ss << std::hex << m_localAddresses.at(AddressField::PORT);
                ss >> retVal;
            }

            return retVal;
        }
        std::string remoteIP() const override
        {
            std::string retVal;

            if (m_remoteAddresses.size() == AddressField::ADDRESS_FIELD_SIZE)
            {
                if (IPVERSION_TYPE.at(m_type) == IPV4)
                {
                    retVal = IPv4Address(m_remoteAddresses.at(AddressField::IP));
                }
                else if (IPVERSION_TYPE.at(m_type) == IPV6)
                {
                    retVal = IPv6Address(m_remoteAddresses.at(AddressField::IP));
                }
            }

            return retVal;
        }
        int32_t remotePort() const override
        {
            int32_t retVal { -1 };

            if (m_remoteAddresses.size() == AddressField::ADDRESS_FIELD_SIZE)
            {
                std::stringstream ss;
                ss << std::hex << m_remoteAddresses.at(AddressField::PORT);
                ss >> retVal;
            }

            return retVal;
        }
        int32_t txQueue() const override
        {
            int32_t retVal { -1 };

            if (m_queue.size() == QueueField::QUEUE_FIELD_SIZE)
            {
                std::stringstream ss;
                ss << std::hex << m_queue.at(QueueField::TX);
                ss >> retVal;
            }

            return retVal;
        }
        int32_t rxQueue() const override
        {
            int32_t retVal { -1 };

            if (m_queue.size() == QueueField::QUEUE_FIELD_SIZE)
            {
                std::stringstream ss;
                ss << std::hex << m_queue.at(QueueField::RX);
                ss >> retVal;
            }

            return retVal;
        }
        int64_t inode() const override
        {
            int64_t retVal { -1 };

            try
            {
                retVal = static_cast<int64_t>(std::stoll(m_fields.at(INODE)));
            }
            catch (...)
            {}

            return retVal;
        }
        std::string state() const override
        {
            std::string retVal;
            const auto it { PROTOCOL_TYPE.find(m_type) };

            if (PROTOCOL_TYPE.end() != it && TCP == it->second)
            {
                std::stringstream ss;
                int32_t state { 0 };
                ss << std::hex << m_fields.at(STATE);
                ss >> state;

                const auto itState { STATE_TYPE.find(state) };

                if (STATE_TYPE.end() != itState)
                {
                    retVal = itState->second;
                }
            }

            return retVal;
        }

        std::string processName() const override
        {
            return UNKNOWN_VALUE;
        }

        int32_t pid() const override
        {
            return {};
        }
};


#endif //_PORT_LINUX_WRAPPER_H