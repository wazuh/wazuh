/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_AGENT_ID_HPP
#define _INVSYNC_COMMON_AGENT_ID_HPP

/**
 * @file agentId.hpp
 * @brief The one spelling of an agent id this module writes and compares.
 *
 * An agent id is a string, not a number: "001" is agent 001, and "1", "01" or "0001" are not
 * other spellings of it. The canonical text is the one remoted's token verifier enforces on `kid`
 * and `sub` and forwards in `X-Wazuh-Agent-Id` -- decimal digits that fit a 32-bit unsigned value,
 * zero-padded to at least three characters ("001", "1000"). Every document `_id`,
 * `wazuh.agent.id` and query uses it, so a deletion always matches what indexing wrote.
 *
 * Both helpers delegate to remoted's own definition (jwt/canonicalAgentId.hpp) rather than
 * restating it, so the two daemons cannot drift apart.
 */

#include "jwt/canonicalAgentId.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace invsync::common
{
    /**
     * @brief True iff @p value is already the canonical spelling of an agent id.
     *
     * For identities that come from remoted (the `X-Wazuh-Agent-Id` header) and for whatever is
     * compared against them: any other spelling is a contract violation, not something to repair.
     */
    inline bool isCanonicalAgentId(std::string_view value)
    {
        return jwt_profile::v1::CanonicalAgentId::parseCanonical(value).has_value();
    }

    /**
     * @brief The canonical spelling of @p value, accepting leading zeros or their absence ("7",
     * "0007" -> "007").
     *
     * Only for the manager-internal routes, whose caller writes the id as it stores it. Rejects
     * anything that is not ASCII digits or does not fit a 32-bit unsigned value -- an agent id
     * larger than that cannot exist, and parsing it must never wrap.
     */
    inline std::optional<std::string> canonicalAgentId(std::string_view value)
    {
        const auto parsed = jwt_profile::v1::CanonicalAgentId::parse(value);
        if (!parsed)
        {
            return std::nullopt;
        }
        return parsed->text();
    }
} // namespace invsync::common

#endif // _INVSYNC_COMMON_AGENT_ID_HPP
