/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cerrno>
#include <cstring>
#include <system_error>

#include "UtilsWrapperUnix.hpp"

int UtilsWrapperUnix::createSocket(int domain, int type, int protocol)
{
    auto fd { socket(domain, type, protocol) };

    if (-1 == fd)
    {
        throw std::system_error{errno, std::system_category(), std::strerror(errno)};
    }

    return fd;
}

int UtilsWrapperUnix::ioctl(int fd, unsigned long request, char* argp)
{
    const auto retVal { ::ioctl(fd, request, argp) };

    if (-1 == retVal)
    {
        throw std::system_error{errno, std::system_category(), std::strerror(errno)};
    }

    return retVal;
}
