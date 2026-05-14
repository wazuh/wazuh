/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <sys/sockio.h>
#include "networkSolarisHelper.hpp"
#include "UtilsWrapperUnix.hpp"
#include <iostream>

int NetworkSolarisHelper::getInterfacesCount(int fd, sa_family_t family)
{
    auto interfaceCount { 0 };

    struct lifnum ifn = { .lifn_family = family, .lifn_flags = 0, .lifn_count = 0 };

    UtilsWrapperUnix::ioctl(fd, SIOCGLIFNUM, reinterpret_cast<char*>(&ifn));
    interfaceCount = ifn.lifn_count;
    return interfaceCount;
}

void NetworkSolarisHelper::getInterfacesConfig(int fd, lifconf& networkInterfacesConf)
{
    UtilsWrapperUnix::ioctl(fd, SIOCGLIFCONF, reinterpret_cast<char*>(&networkInterfacesConf));
}
