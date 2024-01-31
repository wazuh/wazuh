/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 17, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PORT_SOLARIS_WRAPPER_H
#define _PORT_SOLARIS_WRAPPER_H

#include <unistd.h>
#include <inet/mib2.h>

#include "iportWrapper.h"
#include "sharedDefs.h"
#include "bits/stdc++.h"

static const auto cTcp = "tcp";
static const auto cUdp = "udp";
static const auto cTcp6 = "tcp6";
static const auto cUdp6 = "udp6";

static const std::map<int32_t, std::string> STATE_TYPE =
{
    /* For tcpConnState and tcp6ConnState */
    { MIB2_TCP_closed,      "closed"        },
    { MIB2_TCP_listen,      "listen"        },
    { MIB2_TCP_synSent,     "synSent"       },
    { MIB2_TCP_synReceived, "synReceived"   },
    { MIB2_TCP_established, "established"   },
    { MIB2_TCP_finWait1,    "finWait1"      },
    { MIB2_TCP_finWait2,    "finWait2"      },
    { MIB2_TCP_closeWait,   "closeWait"     },
    { MIB2_TCP_lastAck,     "lastAck"       },
    { MIB2_TCP_closing,     "closing"       },
    { MIB2_TCP_timeWait,    "timeWait"      },
    { MIB2_TCP_deleteTCB,   "deleteTCB"     }
};

static const std::map<int, std::string> UDP_STATE =
{
    { MIB2_UDP_unbound,     "unbound"   },
    { MIB2_UDP_idle,        "idle"      },
    { MIB2_UDP_connected,   "connected" },
    { MIB2_UDP_unknown,     "unknown"   }
};

class SolarisPortWrapper final : public IPortWrapper
{
        const mib2_tcpConnEntry_t* tcpEntry;
        const mib2_tcp6ConnEntry_t* tcp6Entry;
        const mib2_udpEntry_t* udpEntry;
        const mib2_udp6Entry_t* udp6Entry;

    public:
        explicit SolarisPortWrapper(const mib2_tcpConnEntry_t* item)
            : tcpEntry(item), tcp6Entry(nullptr),
              udpEntry(nullptr), udp6Entry(nullptr)
        {}

        explicit SolarisPortWrapper(const mib2_tcp6ConnEntry_t* item)
            : tcpEntry(nullptr), tcp6Entry(item),
              udpEntry(nullptr), udp6Entry(nullptr)
        {}

        explicit SolarisPortWrapper(const mib2_udpEntry_t* item)
            : tcpEntry(nullptr), tcp6Entry(nullptr),
              udpEntry(item), udp6Entry(nullptr)
        {}

        explicit SolarisPortWrapper(const mib2_udp6Entry_t* item)
            : tcpEntry(nullptr), tcp6Entry(nullptr),
              udpEntry(nullptr), udp6Entry(item)
        {}

        ~SolarisPortWrapper() = default;

        std::string protocol() const override
        {
            if (tcpEntry)
            {
                return cTcp;
            }
            else if (udpEntry)
            {
                return cUdp;
            }
            else if (tcp6Entry)
            {
                return cTcp6;
            }
            else if (udp6Entry)
            {
                return cUdp6;
            }

            return { "*" };
        }

        std::string localIp() const override
        {
            char buf[INET6_ADDRSTRLEN];

            if (tcpEntry)
            {
                return inet_ntop(AF_INET, &tcpEntry->tcpConnLocalAddress, buf, sizeof(buf));
            }
            else if (tcp6Entry)
            {
                return inet_ntop(AF_INET6, &tcp6Entry->tcp6ConnLocalAddress, buf, sizeof(buf));
            }
            else if (udpEntry)
            {
                return inet_ntop(AF_INET, &udpEntry->udpLocalAddress, buf, sizeof(buf));
            }
            else if (udp6Entry)
            {
                return inet_ntop(AF_INET6, &udp6Entry->udp6LocalAddress, buf, sizeof(buf));
            }

            return {};
        }

        int32_t localPort() const override
        {
            if (tcpEntry)
            {
                return tcpEntry->tcpConnLocalPort;
            }
            else if (tcp6Entry)
            {
                return tcp6Entry->tcp6ConnLocalPort;
            }
            else if (udpEntry)
            {
                return udpEntry->udpLocalPort;
            }
            else if (udp6Entry)
            {
                return udp6Entry->udp6LocalPort;
            }

            return {};
        }

        std::string remoteIP() const override
        {
            char buf[INET6_ADDRSTRLEN];

            if (tcpEntry)
            {
                return inet_ntop(AF_INET, &tcpEntry->tcpConnRemAddress, buf, sizeof(buf));
            }
            else if (tcp6Entry)
            {
                return inet_ntop(AF_INET6, &tcp6Entry-> tcp6ConnRemAddress, buf, sizeof(buf));
            }
            else if (udpEntry)
            {
                return inet_ntop(AF_INET, &udpEntry->udpEntryInfo.ue_RemoteAddress, buf, sizeof(buf));
            }
            else if (udp6Entry)
            {
                return inet_ntop(AF_INET6, &udp6Entry->udp6EntryInfo.ue_RemoteAddress, buf, sizeof(buf));
            }

            return {};
        }

        int32_t remotePort() const override
        {
            if (tcpEntry)
            {
                return tcpEntry->tcpConnRemPort;
            }
            else if (tcp6Entry)
            {
                return tcp6Entry->tcp6ConnRemPort;
            }
            else if (udpEntry)
            {
                return udpEntry->udpEntryInfo.ue_RemotePort;
            }
            else if (udp6Entry)
            {
                return udp6Entry->udp6EntryInfo.ue_RemotePort;
            }

            return {};
        }

        int32_t txQueue() const override
        {
            int sq {};

            if (tcpEntry)
            {
                sq = tcpEntry->tcpConnEntryInfo.ce_snxt -
                     tcpEntry->tcpConnEntryInfo.ce_suna - 1;
            }
            else if (tcp6Entry)
            {
                sq = tcp6Entry->tcp6ConnEntryInfo.ce_snxt -
                     tcp6Entry->tcp6ConnEntryInfo.ce_suna - 1;
            }

            /* no Queue data for UDP datagram */

            return (sq >= 0) ? sq : 0;
        }

        int32_t rxQueue() const override
        {
            int rq {};

            if (tcpEntry)
            {
                rq = tcpEntry->tcpConnEntryInfo.ce_rnxt -
                     tcpEntry->tcpConnEntryInfo.ce_rack;
            }
            else if (tcp6Entry)
            {
                rq = tcp6Entry->tcp6ConnEntryInfo.ce_rnxt -
                     tcp6Entry->tcp6ConnEntryInfo.ce_rack;
            }

            /* no Queue data for UDP datagram */

            return (rq >= 0) ? rq : 0;
        }

        int64_t inode() const override
        {
            return {};
        }

        std::string state() const override
        {
            std::string retVal;

            auto status = [&retVal](auto connState)
            {
                const auto itState { STATE_TYPE.find(connState) };

                if (STATE_TYPE.end() != itState)
                {
                    retVal = itState->second;
                }
            };

            auto udp_status = [&retVal](auto connState)
            {
                const auto itState { UDP_STATE.find(connState) };

                if (UDP_STATE.end() != itState)
                {
                    retVal = itState->second;
                }
                else
                {
                    retVal = UDP_STATE.find(MIB2_UDP_unknown)->second;
                }
            };

            if (tcpEntry)
            {
                status(tcpEntry->tcpConnState);
            }
            else if (tcp6Entry)
            {
                status(tcp6Entry->tcp6ConnState);
            }
            else if (udpEntry)
            {
                udp_status(udpEntry->udpEntryInfo.ue_state);
            }
            else if (udp6Entry)
            {
                udp_status(udp6Entry->udp6EntryInfo.ue_state);
            }

            return retVal;
        }

        std::string processName() const override
        {
            return {};
        }

        int32_t pid() const override
        {
            if (tcpEntry)
            {
                return tcpEntry->tcpConnCreationProcess;
            }
            else if (tcp6Entry)
            {
                return tcp6Entry->tcp6ConnCreationProcess;
            }
            else if (udpEntry)
            {
                return udpEntry->udpCreationProcess;
            }
            else if (udp6Entry)
            {
                return udp6Entry->udp6CreationProcess;
            }

            return {};
        }
};

#endif //_PORT_SOLARIS_WRAPPER_H
