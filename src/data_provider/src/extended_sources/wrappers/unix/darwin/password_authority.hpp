/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstring>
#include <string>
#include <vector>

#include "json.hpp"

namespace od
{
    /// Authority tag present only on accounts that have a local password set.
    constexpr auto SHADOW_HASH_TAG {";ShadowHash;"};

    /// Prefix of the algorithm list embedded in the ShadowHash authority.
    constexpr auto HASH_LIST_TAG {"HASHLIST:<"};

    /// Password status values, aligned with the ones the Linux shadow provider reports.
    constexpr auto PASSWORD_STATUS_ACTIVE {"active"};
    constexpr auto PASSWORD_STATUS_NOT_SET {"not_set"};

    /// @brief Derives the password data of an account from its authentication authorities.
    ///
    /// macOS stores no shadow file. An account that has a password carries a `;ShadowHash;`
    /// authority, which also lists the enabled algorithms as `HASHLIST:<alg1,alg2,...>`; an
    /// account without one carries no such authority. Kept free of OpenDirectory types so the
    /// parsing can be exercised directly, since the format is Apple's and may change.
    ///
    /// @param authorities The values of the record's `AuthenticationAuthority` attribute.
    /// @return A JSON object with "password_status" and "password_hash_algorithm". The algorithm
    ///         is empty when the authority carries no readable list.
    inline nlohmann::json parseAuthenticationAuthority(const std::vector<std::string>& authorities)
    {
        nlohmann::json passwordData
        {
            {"password_status", PASSWORD_STATUS_NOT_SET},
            {"password_hash_algorithm", ""}
        };

        for (const auto& authority : authorities)
        {
            if (authority.find(SHADOW_HASH_TAG) == std::string::npos)
            {
                continue;
            }

            passwordData["password_status"] = PASSWORD_STATUS_ACTIVE;

            const auto listStart { authority.find(HASH_LIST_TAG) };

            if (listStart != std::string::npos)
            {
                const auto algorithmsStart { listStart + std::strlen(HASH_LIST_TAG) };
                const auto algorithmsEnd { authority.find('>', algorithmsStart) };

                if (algorithmsEnd != std::string::npos)
                {
                    // The list is ordered by preference, so the first entry is the algorithm in use.
                    const auto algorithms { authority.substr(algorithmsStart, algorithmsEnd - algorithmsStart) };
                    const auto separator { algorithms.find(',') };
                    passwordData["password_hash_algorithm"] = separator == std::string::npos
                                                              ? algorithms
                                                              : algorithms.substr(0, separator);
                }
            }

            // The first ShadowHash authority is the one that describes the password. A later one
            // would describe an additional mechanism, not replace it, so it is not read.
            break;
        }

        return passwordData;
    }
} // namespace od
