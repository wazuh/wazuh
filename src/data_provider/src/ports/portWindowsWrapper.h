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

#ifndef _PORT_WINDOWS_WRAPPER_H
#define _PORT_WINDOWS_WRAPPER_H
#include <ws2ipdef.h>
#include "iportWrapper.h"
#include "sharedDefs.h"
#include "stringHelper.h"
#include "windowsHelper.h"

static const std::map<int32_t, std::string> STATE_TYPE =
{
    { MIB_TCP_STATE_ESTAB,                 "established"    },
    { MIB_TCP_STATE_SYN_SENT,              "syn_sent"       },
    { MIB_TCP_STATE_SYN_RCVD,              "syn_recv"       },
    { MIB_TCP_STATE_FIN_WAIT1,             "fin_wait1"      },
    { MIB_TCP_STATE_FIN_WAIT2,             "fin_wait2"      },
    { MIB_TCP_STATE_TIME_WAIT,             "time_wait"      },
    { MIB_TCP_STATE_CLOSED,                "close"          },
    { MIB_TCP_STATE_CLOSE_WAIT,            "close_wait"     },
    { MIB_TCP_STATE_LAST_ACK,              "last_ack"       },
    { MIB_TCP_STATE_LISTEN,                "listening"      },
    { MIB_TCP_STATE_CLOSING,               "closing"        },
    { MIB_TCP_STATE_DELETE_TCB,            "delete_tcp"     }
};

static const std::map<pid_t, std::string> SYSTEM_PROCESSES =
{
    { 0,                                   "System Idle Process"   },
    { 4,                                   "System"                },
};

struct PortTables
{
    std::unique_ptr<MIB_TCPTABLE_OWNER_PID []> tcp;
    std::unique_ptr<MIB_TCP6TABLE_OWNER_PID []> tcp6;
    std::unique_ptr<MIB_UDPTABLE_OWNER_PID []> udp;
    std::unique_ptr<MIB_UDP6TABLE_OWNER_PID []> udp6;
};

class WindowsPortWrapper final : public IPortWrapper
{
        const std::string m_protocol;
        const int32_t m_localPort;
        const std::string m_localIpAddress;
        const int32_t m_remotePort;
        const std::string m_remoteIpAddress;
        const uint32_t m_state;
        const uint32_t m_pid;
        const std::string m_processName;

        static std::string getIpV4Address(const DWORD addr)
        {
            in_addr ipaddress;
            ipaddress.S_un.S_addr = addr;
            return Utils::NetworkWindowsHelper::IAddressToString(AF_INET, ipaddress);
        }

        static std::string getProcessName(const std::map<pid_t, std::string> processDataList, const pid_t pid)
        {
            std::string retVal { UNKNOWN_VALUE };
            const auto itSystemProcess { SYSTEM_PROCESSES.find(pid) } ;

            if (SYSTEM_PROCESSES.end() != itSystemProcess)
            {
                retVal = itSystemProcess->second;
            }
            else
            {
                const auto itCurrentProcessList { processDataList.find(pid) } ;
                {
                    if (processDataList.end() != itCurrentProcessList)
                    {
                        retVal = itCurrentProcessList->second;
                    }
                }
            }

            return retVal;
        }
        WindowsPortWrapper() = delete;
    public:
        WindowsPortWrapper(const _MIB_TCPROW_OWNER_PID& data, const std::map<pid_t, std::string>& processDataList)
            : m_protocol { "tcp" }
            , m_localPort { ntohs(data.dwLocalPort) }
            , m_localIpAddress { getIpV4Address(data.dwLocalAddr) }
            , m_remotePort { ntohs(data.dwRemotePort) }
            , m_remoteIpAddress { getIpV4Address(data.dwRemoteAddr) }
            , m_state { data.dwState }
            , m_pid { data.dwOwningPid }
            , m_processName { getProcessName(processDataList, data.dwOwningPid) }
        { }

        WindowsPortWrapper(const _MIB_TCP6ROW_OWNER_PID& data, const std::map<pid_t, std::string>& processDataList)
            : m_protocol { "tcp6" }
            , m_localPort { ntohs(data.dwLocalPort) }
            , m_localIpAddress { Utils::NetworkWindowsHelper::getIpV6Address(data.ucLocalAddr) }
            , m_remotePort { ntohs(data.dwRemotePort) }
            , m_remoteIpAddress { Utils::NetworkWindowsHelper::getIpV6Address(data.ucRemoteAddr) }
            , m_state { data.dwState }
            , m_pid { data.dwOwningPid }
            , m_processName { getProcessName(processDataList, data.dwOwningPid) }
        { }

        WindowsPortWrapper(const _MIB_UDPROW_OWNER_PID& data, const std::map<pid_t, std::string>& processDataList)
            : m_protocol { "udp" }
            , m_localPort { ntohs(data.dwLocalPort) }
            , m_localIpAddress { getIpV4Address(data.dwLocalAddr) }
            , m_remotePort { 0 }
            , m_state { 0 }
            , m_pid { data.dwOwningPid }
            , m_processName { getProcessName(processDataList, data.dwOwningPid) }
        { }

        WindowsPortWrapper(const _MIB_UDP6ROW_OWNER_PID& data, const std::map<pid_t, std::string>& processDataList)
            : m_protocol("udp6")
            , m_localPort { ntohs(data.dwLocalPort) }
            , m_localIpAddress { Utils::NetworkWindowsHelper::getIpV6Address(data.ucLocalAddr) }
            , m_remotePort { 0 }
            , m_state { 0 }
            , m_pid { data.dwOwningPid }
            , m_processName { getProcessName(processDataList, data.dwOwningPid) }
        { }

        ~WindowsPortWrapper() = default;
        std::string protocol() const override
        {
            return m_protocol;
        }
        std::string localIp() const override
        {
            return m_localIpAddress;
        }
        int32_t localPort() const override
        {
            return m_localPort;
        }
        std::string remoteIP() const override
        {
            return m_remoteIpAddress;
        }
        int32_t remotePort() const override
        {
            return m_remotePort;
        }
        int32_t txQueue() const override
        {
            return {};
        }
        int32_t rxQueue() const override
        {
            return {};
        }
        int64_t inode() const override
        {
            return {};
        }
        std::string state() const override
        {
            std::string retVal { UNKNOWN_VALUE };
            const auto itState { STATE_TYPE.find(m_state) };

            if (STATE_TYPE.end() != itState)
            {
                retVal = itState->second;
            }

            return retVal;
        }
        int32_t pid() const override
        {
            return m_pid;
        }
        std::string processName() const override
        {
            return Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(m_processName);
        }
};


#endif //_PORT_WINDOWS_WRAPPER_H
