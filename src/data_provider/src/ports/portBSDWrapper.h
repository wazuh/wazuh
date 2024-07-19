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

#ifndef _PORT_BSD_WRAPPER_H
#define _PORT_BSD_WRAPPER_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "iportWrapper.h"
#include "sharedDefs.h"
#include "stringHelper.h"

static const std::map<int32_t, std::string> PORTS_TYPE =
{
    { SOCKINFO_TCP,                        "tcp"            },
    { SOCKINFO_IN,                         "udp"            }
};

static const std::map<int32_t, std::string> STATE_TYPE =
{
    { TSI_S_ESTABLISHED,                     "established"    },
    { TSI_S_SYN_SENT,                        "syn_sent"       },
    { TSI_S_SYN_RECEIVED,                    "syn_recv"       },
    { TSI_S_FIN_WAIT_1,                      "fin_wait1"      },
    { TSI_S_FIN_WAIT_2,                      "fin_wait2"      },
    { TSI_S_TIME_WAIT,                       "time_wait"      },
    { TSI_S_CLOSED,                          "close"          },
    { TSI_S__CLOSE_WAIT,                     "close_wait"     },
    { TSI_S_LAST_ACK,                        "last_ack"       },
    { TSI_S_LISTEN,                          "listening"      },
    { TSI_S_CLOSING,                         "closing"        }
};

struct ProcessInfo
{
    int32_t pid;
    std::string processName;
    bool operator<(const ProcessInfo& src) const
    {
        return this->pid < src.pid;
    }
};

class BSDPortWrapper final : public IPortWrapper
{
        ProcessInfo m_processInformation;
        std::shared_ptr<socket_fdinfo> m_spSocketInfo;

    public:
        explicit BSDPortWrapper(const ProcessInfo& processInformation, const std::shared_ptr<socket_fdinfo>& socketInfo)
            : m_processInformation { processInformation }
            , m_spSocketInfo { socketInfo }
        {
            if (!m_spSocketInfo)
            {
                throw std::runtime_error {"Invalid socket FD information"};
            }
        };
        ~BSDPortWrapper() = default;

        std::string protocol() const override
        {
            std::string retVal;
            const auto it { PORTS_TYPE.find(m_spSocketInfo->psi.soi_kind) };

            if (it != PORTS_TYPE.end())
            {
                retVal = AF_INET6 == m_spSocketInfo->psi.soi_family ? it->second + "6" : it->second;
            }

            return  retVal;
        }
        std::string localIp() const override
        {
            char ipAddress[NI_MAXHOST] { 0 };

            if (AF_INET6 == m_spSocketInfo->psi.soi_family)
            {
                sockaddr_in6 socketAddressIn6{};
                socketAddressIn6.sin6_family = m_spSocketInfo->psi.soi_family;
                socketAddressIn6.sin6_addr = static_cast<in6_addr>(m_spSocketInfo->psi.soi_proto.pri_in.insi_laddr.ina_6);
                getnameinfo(reinterpret_cast<sockaddr*>(&socketAddressIn6), sizeof(socketAddressIn6), ipAddress, sizeof(ipAddress), nullptr, 0, NI_NUMERICHOST);
            }
            else if (AF_INET == m_spSocketInfo->psi.soi_family)
            {
                sockaddr_in socketAddressIn{};
                socketAddressIn.sin_family = m_spSocketInfo->psi.soi_family;
                socketAddressIn.sin_addr = static_cast<in_addr>(m_spSocketInfo->psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4);
                getnameinfo(reinterpret_cast<sockaddr*>(&socketAddressIn), sizeof(socketAddressIn), ipAddress, sizeof(ipAddress), nullptr, 0, NI_NUMERICHOST);
            }

            return Utils::substrOnFirstOccurrence(ipAddress, "%");
        }
        int32_t localPort() const override
        {
            return ntohs(m_spSocketInfo->psi.soi_proto.pri_in.insi_lport);
        }
        std::string remoteIP() const override
        {
            char ipAddress[NI_MAXHOST] { 0 };

            if (AF_INET6 == m_spSocketInfo->psi.soi_family)

            {
                sockaddr_in6 socketAddressIn6{};
                socketAddressIn6.sin6_family = m_spSocketInfo->psi.soi_family;
                socketAddressIn6.sin6_addr = static_cast<in6_addr>(m_spSocketInfo->psi.soi_proto.pri_in.insi_faddr.ina_6);
                getnameinfo(reinterpret_cast<sockaddr*>(&socketAddressIn6), sizeof(socketAddressIn6), ipAddress, sizeof(ipAddress), nullptr, 0, NI_NUMERICHOST);
            }
            else if (AF_INET == m_spSocketInfo->psi.soi_family)
            {
                sockaddr_in socketAddressIn{};
                socketAddressIn.sin_family = m_spSocketInfo->psi.soi_family;
                socketAddressIn.sin_addr = static_cast<in_addr>(m_spSocketInfo->psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4);
                getnameinfo(reinterpret_cast<sockaddr*>(&socketAddressIn), sizeof(socketAddressIn), ipAddress, sizeof(ipAddress), nullptr, 0, NI_NUMERICHOST);
            }

            return Utils::substrOnFirstOccurrence(ipAddress, "%");
        }
        int32_t remotePort() const override
        {
            return ntohs(m_spSocketInfo->psi.soi_proto.pri_in.insi_fport);
        }
        int32_t txQueue() const override
        {
            return 0;
        }
        int32_t rxQueue() const override
        {
            return 0;
        }
        int64_t inode() const override
        {
            return 0;
        }
        std::string state() const override
        {
            std::string retVal;

            const auto itProtocol { PORTS_TYPE.find(m_spSocketInfo->psi.soi_kind) };

            if (PORTS_TYPE.end() != itProtocol && SOCKINFO_TCP == itProtocol->first)
            {
                const auto itState { STATE_TYPE.find(m_spSocketInfo->psi.soi_proto.pri_tcp.tcpsi_state) };

                if (itState != STATE_TYPE.end())
                {
                    retVal = itState->second;
                }
            }

            return retVal;
        }

        int32_t pid() const override
        {
            return m_processInformation.pid;
        }

        std::string processName() const override
        {
            return m_processInformation.processName;
        }

};


#endif //_PORT_BSD_WRAPPER_H
