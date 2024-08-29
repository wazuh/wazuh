#include "utils/ipUtils.hpp"

#include <arpa/inet.h>

#include <fmt/format.h>

namespace utils::ip
{

uint32_t IPv4ToUInt(const std::string& ipStr)
{
    int a, b, c, d {};
    char z {}; // Character after IP
    uint32_t ipUInt = 0;

    if (sscanf(ipStr.c_str(), "%d.%d.%d.%d%c", &a, &b, &c, &d, &z) != 4)
    {
        throw std::invalid_argument("Invalid IPv4 address format");
    }
    else if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
    {
        throw std::invalid_argument("Invalid IPv4 address format");
    }

    ipUInt = a << 24;
    ipUInt |= b << 16;
    ipUInt |= c << 8;
    ipUInt |= d;

    return ipUInt;
}

// TODO: Missing unit tests fot this
uint32_t IPv4MaskUInt(const std::string& maskStr)
{

    uint32_t maskUInt = 0;

    if (maskStr.find('.') != std::string::npos)
    {
        // Thow an exception if the mask is not valid
        maskUInt = IPv4ToUInt(maskStr);
    }
    else
    {
        size_t afterMask = 0;
        // Thow an `invalid_argument` exception if the mask is not a number
        auto intMask = std::stoi(maskStr, &afterMask);
        if (intMask < 0 || intMask > 32)
        {
            throw std::invalid_argument("Invalid IPv4 mask format");
        }

        if (afterMask != maskStr.size())
        {
            throw std::invalid_argument("Invalid IPv4 mask format");
        }

        maskUInt = intMask == 0 ? 0 : 0xFFFFFFFF << (32 - intMask);
    }

    return maskUInt;
}

bool checkStrIsIPv4(const std::string& ip)
{
    struct in_addr buf;
    return inet_pton(AF_INET, ip.c_str(), &buf) == 1;
}

bool checkStrIsIPv6(const std::string& ip)
{
    struct in6_addr buf;
    return inet_pton(AF_INET6, ip.c_str(), &buf) == 1;
}

bool isSpecialIPv4Address(const std::string& ip)
{
    uint32_t ipUInt = IPv4ToUInt(ip);

    if ((ipUInt >= 0x0A000000 && ipUInt <= 0x0AFFFFFF)     // 10.x.x.x range
        || (ipUInt >= 0xAC100000 && ipUInt <= 0xAC1FFFFF)  // 172.16.x.x to 172.31.x.x
        || (ipUInt >= 0xC0A80000 && ipUInt <= 0xC0A8FFFF)  // 192.168.x.x range
        || (ipUInt >= 0x7F000000 && ipUInt <= 0x7FFFFFFF)) // 127.x.x.x loopback range

    {
        return true;
    }
    return false;
}

bool isSpecialIPv6Address(const std::string& ip)
{
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1)
    {
        throw std::invalid_argument("Invalid IPv6 address");
    }

    return IN6_IS_ADDR_LOOPBACK(&addr)                              // Loopback
           || IN6_IS_ADDR_LINKLOCAL(&addr)                          // Link-local fe80::/10
           || (addr.s6_addr[0] == 0xFC || addr.s6_addr[0] == 0xFD); // ULA fc00::/7
}

} // namespace utils::ip
