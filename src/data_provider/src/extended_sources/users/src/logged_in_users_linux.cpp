/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "logged_in_users_linux.hpp"
#include "utmpx_wrapper.hpp"

#include <utmpx.h>
#include <paths.h>

#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

std::mutex LoggedInUsersProvider::utmpxMutex;

const std::map<size_t, std::string> LoggedInUsersProvider::loginTypes =
{
    {EMPTY, "empty"},
    {BOOT_TIME, "boot_time"},
    {NEW_TIME, "new_time"},
    {OLD_TIME, "old_time"},
    {INIT_PROCESS, "init"},
    {LOGIN_PROCESS, "login"},
    {USER_PROCESS, "user"},
    {DEAD_PROCESS, "dead"},
};

LoggedInUsersProvider::LoggedInUsersProvider(std::shared_ptr<IUtmpxWrapper> wrapper)
    : m_utmpxWrapper(std::move(wrapper)) {}

LoggedInUsersProvider::LoggedInUsersProvider()
    : m_utmpxWrapper(std::make_shared<UtmpxWrapper>()) {}

nlohmann::json LoggedInUsersProvider::collect()
{
    std::lock_guard<std::mutex> lock(utmpxMutex);
    nlohmann::json results = nlohmann::json::array();
    struct utmpx* entry = nullptr;

    m_utmpxWrapper->utmpxname(_PATH_UTMPX);
    m_utmpxWrapper->setutxent();

    while ((entry = m_utmpxWrapper->getutxent()) != nullptr)
    {
        if (entry->ut_pid == 1)
        {
            continue;
        }

        nlohmann::json row;
        auto it = loginTypes.find(entry->ut_type);
        row["type"] = (it != loginTypes.end()) ? it->second : "unknown";

        row["user"] = std::string(entry->ut_user, strnlen(entry->ut_user, sizeof(entry->ut_user)));
        row["tty"]  = std::string(entry->ut_line, strnlen(entry->ut_line, sizeof(entry->ut_line)));
        row["time"] = entry->ut_tv.tv_sec;
        row["pid"]  = entry->ut_pid;


        char ipStr[INET6_ADDRSTRLEN] = {0};

        // IPv4
        if (entry->ut_addr_v6[1] == 0 && entry->ut_addr_v6[2] == 0 && entry->ut_addr_v6[3] == 0)
        {
            struct in_addr ipv4Addr;
            ipv4Addr.s_addr = static_cast<uint32_t>(entry->ut_addr_v6[0]);

            if (inet_ntop(AF_INET, &ipv4Addr, ipStr, sizeof(ipStr)))
            {
                row["host"] = ipStr;
            }
            else
            {
                row["host"] = nullptr;
            }
        }
        else
        {
            struct in6_addr ipv6Addr;
            std::memcpy(&ipv6Addr, entry->ut_addr_v6, sizeof(ipv6Addr));

            if (inet_ntop(AF_INET6, &ipv6Addr, ipStr, sizeof(ipStr)))
            {
                row["host"] = ipStr;
            }
            else
            {
                row["host"] = nullptr;
            }
        }

        results.push_back(std::move(row));
    }

    m_utmpxWrapper->endutxent();
    return results;
}
