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
        std::shared_ptr<IPortWrapper> m_spPortRawData;
    public:
        explicit PortImpl(const std::shared_ptr<IPortWrapper>& portRawData)
            : m_spPortRawData(portRawData)
        { }
        // LCOV_EXCL_START
        ~PortImpl() = default;
        // LCOV_EXCL_STOP
        void buildPortData(nlohmann::json& port) override
        {
            port["network_transport"] = m_spPortRawData->protocol();
            port["source_ip"] = m_spPortRawData->localIp();
            port["source_port"] = m_spPortRawData->localPort();
            port["destination_ip"] = m_spPortRawData->remoteIP();
            port["destination_port"] = m_spPortRawData->remotePort();
            port["host_network_egress_queue"] = m_spPortRawData->txQueue();
            port["host_network_ingress_queue"] = m_spPortRawData->rxQueue();
            port["file_inode"] = m_spPortRawData->inode();
            port["interface_state"] = m_spPortRawData->state();
            port["process_pid"] = m_spPortRawData->pid();
            port["process_name"] = m_spPortRawData->processName();
        }
};
#endif // _PORT_IMPL_H