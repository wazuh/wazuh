/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <net/if.h>

class NetworkSolarisHelper final
{
    public:
        static int getInterfacesCount(int fd);
        static int getInterfacesV6Count(int fd);
        static bool getInterfaces(int fd, struct lifconf* networkInterface);
};