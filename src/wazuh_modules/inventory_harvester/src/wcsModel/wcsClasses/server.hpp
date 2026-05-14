/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SERVER_WCS_MODEL_HPP
#define _SERVER_WCS_MODEL_HPP

#include "nat.hpp"
#include "reflectiveJson.hpp"
#include <string_view>
#include <vector>

struct Server final
{
    // Add ECS Server fields here
    std::string_view address;
    std::int64_t bytes = DEFAULT_INT_VALUE;
    std::string_view domain;
    std::string_view ip;
    std::string_view mac;
    NAT nat;
    std::string_view packets;
    std::string_view port;
    std::string_view registered_domain;
    std::string_view subdomain;
    std::string_view top_level_domain;

    REFLECTABLE(MAKE_FIELD("address", &Server::address),
                MAKE_FIELD("bytes", &Server::bytes),
                MAKE_FIELD("domain", &Server::domain),
                MAKE_FIELD("ip", &Server::ip),
                MAKE_FIELD("mac", &Server::mac),
                MAKE_FIELD("nat", &Server::nat),
                MAKE_FIELD("packets", &Server::packets),
                MAKE_FIELD("port", &Server::port),
                MAKE_FIELD("registered_domain", &Server::registered_domain),
                MAKE_FIELD("subdomain", &Server::subdomain),
                MAKE_FIELD("top_level_domain", &Server::top_level_domain));
};

#endif // _SERVER_WCS_MODEL_HPP
