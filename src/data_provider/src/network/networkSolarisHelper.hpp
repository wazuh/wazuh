/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_SOLARIS_HELPER_H
#define _NETWORK_SOLARIS_HELPER_H

#include <net/if.h>

class NetworkSolarisHelper final
{
    public:
        static int getInterfacesCount(int fd, sa_family_t family);
        static void getInterfacesConfig(int fd, lifconf& networkInterface);
};

#endif //_NETWORK_SOLARIS_HELPER_H
