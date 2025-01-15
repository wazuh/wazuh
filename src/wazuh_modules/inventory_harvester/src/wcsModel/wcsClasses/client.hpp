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

#ifndef _CLIENT_WCS_MODEL_HPP
#define _CLIENT_WCS_MODEL_HPP

#include "nat.hpp"
#include "reflectiveJson.hpp"
#include <string_view>
#include <vector>

struct Client final
{
    // Add ECS client fields here
    std::string_view address;
    std::uint32_t bytes;
    std::string_view domain;
    std::string_view ip;
    std::string_view mac;
    NAT nat;
    std::string_view packets;
    std::string_view port;
    std::string_view registered_domain;
    std::string_view subdomain;
    std::string_view top_level_domain;

    REFLECTABLE(MAKE_FIELD("address", &Client::address),
                MAKE_FIELD("bytes", &Client::bytes),
                MAKE_FIELD("domain", &Client::domain),
                MAKE_FIELD("ip", &Client::ip),
                MAKE_FIELD("mac", &Client::mac),
                MAKE_FIELD("nat", &Client::nat),
                MAKE_FIELD("packets", &Client::packets),
                MAKE_FIELD("port", &Client::port),
                MAKE_FIELD("registered_domain", &Client::registered_domain),
                MAKE_FIELD("subdomain", &Client::subdomain),
                MAKE_FIELD("top_level_domain", &Client::top_level_domain));
};

#endif // _CLIENT_WCS_MODEL_HPP
