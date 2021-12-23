#include <sys/sockio.h>
#include "networkSolarisHelper.hpp"
#include "UtilsWrapperUnix.hpp"

int NetworkSolarisHelper::getInterfacesCount(int fd)
{
    auto interfaceCount { 0 };

    struct lifnum ifn = { .lifn_family = AF_INET, .lifn_flags = 0};

    if (-1 != UtilsWrapperUnix::createIoctl(fd, SIOCGLIFNUM, reinterpret_cast<char *>(&ifn)))
    {
        interfaceCount = ifn.lifn_count;
    }
    else
    {
        throw std::runtime_error { "Invalid interfaces number" };
    }

    return interfaceCount;
}

int NetworkSolarisHelper::getInterfacesV6Count(int fd)
{
    auto interfaceCount { 0 };

    struct lifnum ifn = { .lifn_family = AF_INET6, .lifn_flags = 0};

    if (-1 != UtilsWrapperUnix::createIoctl(fd, SIOCGLIFNUM, reinterpret_cast<char *>(&ifn)))
    {
        interfaceCount = ifn.lifn_count;
    }
    else
    {
        throw std::runtime_error { "Invalid interfaces IPv6 number" };
    }

    return interfaceCount;
}

bool NetworkSolarisHelper::getInterfaces(int fd, struct lifconf* networkInterface)
{
    if (-1 != UtilsWrapperUnix::createIoctl(fd, SIOCGLIFCONF, reinterpret_cast<char *>(networkInterface)))
    {
        throw std::runtime_error { "Couldn't get network interface" };
    }

    return true;
}