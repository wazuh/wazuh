/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "UtilsWrapperUnix.hpp"

int UtilsWrapperUnix::createSocket(int domain, int type, int protocol)
{
    auto fd { socket(domain, type, protocol) };

    if (-1 == fd)
    {
        throw std::runtime_error{"Cannot connect to local socket."};
    }

    return fd;
}

int UtilsWrapperUnix::ioctl(int fd, unsigned long request, char* argp)
{
    const auto retVal { ::ioctl(fd, request, argp) };

    if (-1 == retVal)
    {
        throw std::runtime_error{ "Cannot manage device io." };
    }

    return retVal;
}

