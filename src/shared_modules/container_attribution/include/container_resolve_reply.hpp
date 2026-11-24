/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_RESOLVE_REPLY_HPP
#define _CONTAINER_RESOLVE_REPLY_HPP

#include <json.hpp>

#include <string>

namespace container_attribution
{
    /* The container id out of a `resolve` reply.
     *
     * LookupResult::json carries the WHOLE reply line, not the "data" object — the
     * client extracts only the status string and leaves parsing to the consumer. */
    inline std::string ContainerIdFromResolveReply(const std::string& reply)
    {
        const auto parsed = nlohmann::json::parse(reply, nullptr, false);

        if (parsed.is_discarded() || !parsed.is_object()) return {};

        const auto data = parsed.find("data");

        if (data != parsed.end() && data->is_object())
        {
            const auto id = data->find("container_id");

            if (id != data->end() && id->is_string()) return id->get<std::string>();
        }

        const auto id = parsed.find("container_id");

        if (id != parsed.end() && id->is_string()) return id->get<std::string>();

        return {};
    }
} // namespace container_attribution

#endif // _CONTAINER_RESOLVE_REPLY_HPP
