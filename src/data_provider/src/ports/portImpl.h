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

#ifndef _PORT_IMPL_H
#define _PORT_IMPL_H

#include "iportInterface.h"
#include "iportWrapper.h"
#include "sharedDefs.h"

class PortImpl final : public IOSPort
{
    private:
        const IPortWrapper& m_portRawData;
    public:
        explicit PortImpl(const IPortWrapper& portRawData)
            : m_portRawData { portRawData }
        { }
        // LCOV_EXCL_START
        ~PortImpl() = default;
        // LCOV_EXCL_STOP
        void buildPortData(nlohmann::json& port) override
        {
            port["network_transport"] = m_portRawData.protocol();
            port["source_ip"] = m_portRawData.localIp();
            port["source_port"] = m_portRawData.localPort();
            port["destination_ip"] = m_portRawData.remoteIP();
            port["destination_port"] = m_portRawData.remotePort();
            port["host_network_egress_queue"] = m_portRawData.txQueue();
            port["host_network_ingress_queue"] = m_portRawData.rxQueue();
            port["file_inode"] = m_portRawData.inode();
            port["interface_state"] = m_portRawData.state();
            port["process_pid"] = m_portRawData.pid();
            port["process_name"] = m_portRawData.processName();
        }
};
#endif // _PORT_IMPL_H