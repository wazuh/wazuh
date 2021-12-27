#include <sys/sockio.h>
#include "networkSolarisHelper.hpp"
#include "UtilsWrapperUnix.hpp"
#include <iostream>

int NetworkSolarisHelper::getInterfacesCount(int fd, sa_family_t family)
{
    auto interfaceCount { 0 };

    struct lifnum ifn = { .lifn_family = family, .lifn_flags = 0, .lifn_count = 0 };

    if (-1 != UtilsWrapperUnix::ioctl(fd, SIOCGLIFNUM, reinterpret_cast<char *>(&ifn)))
    {
        interfaceCount = ifn.lifn_count;
    }
    else
    {
        throw std::runtime_error { "Invalid interfaces number" };
    }

    return interfaceCount;
}

void NetworkSolarisHelper::getInterfacesConfig(int fd, lifconf &networkInterfacesConf)
{
    if (UtilsWrapperUnix::ioctl(fd, SIOCGLIFCONF, reinterpret_cast<char *>(&networkInterfacesConf)))
    {
        throw std::runtime_error { "Couldn't get network interface " + std::to_string(errno) };
    }
}