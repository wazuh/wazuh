#include <sys/socket.h>
#include <net/if.h>
#include "networkSolarisHelper.hpp"

int NetworkSolarisHelper::getInterfacesCount(int fd)
{
    auto interfaceCount { 0 };

    struct lifnum ifn = { .lifn_family = AF_INET };

    if (ioclt(fd, SIOCGLIFNUM, &ifn) != -1)
    {
        interfaceCount = ifn.lifn_count;
    }
    else
    {
        throw std::runtime_error { "Invalid interfaces number" };
    }

    return interfaceCount;
}
/*
 void networkSolarisHelper::getInterface(nlohmann::json& network)
 {
     if (numInterface != -1)
     {
        nlohmann::json ipv4JS {};
        struct lifconf ifConf = {.lifc_family = AF_INET, .lifc_len = numInterface * sizeof(struct lifreq) };
        ifConf.lifc_buf = new(ifConf.lifc_len); // Ask if is possible make with smart pointer

        if (ifConf.lifc_buf != nullptr)
        {
            // Get interface
            const auto fd {socket(AF_INET, SOCK_DGRAM, 0)};

            // Scan interfaces
            if (fd != -1 && ioctl(fd, SIOCGLIFCONF, &if_conf) != -1)
            {
                for (auto i = 0; i < numInterface; i++)
                {
                    struct lifreq * if_req = if_conf.lifc_req + i;
                }
            }

            close(fd);
            delete if_conf.lifc_buf;
        }

        network["IPv4"].push_back(ipv4JS)
     }
 }
 */