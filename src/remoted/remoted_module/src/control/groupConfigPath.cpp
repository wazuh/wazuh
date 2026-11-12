/*
 * Wazuh remoted module - Shared configuration path of an agent's groups
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "groupConfigPath.hpp"
#include "groupSelector.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <utility>

namespace remoted::control
{
    namespace
    {
        /// MAX_GROUP_NAME.
        constexpr std::size_t kMaxGroupNameSize {255};

        // Hex characters in a multigroup directory name. Must equal wazuh-db's
        // WDB_GROUP_HASH_SIZE (32): the first sixteen SHA-256 digest bytes.
        constexpr std::size_t kMultigroupHashHexChars {32};

        constexpr auto kMergedConfigFilename {"/merged.mg"};

        bool isGroupNameChar(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                   c == '-';
        }

        /// The multigroup directory name of @p csv, or "" if the digest fails.
        std::string multigroupHash(const std::string& csv)
        {
            unsigned char digest[EVP_MAX_MD_SIZE] {};
            unsigned int digestLength {0};

            if (EVP_Digest(csv.data(), csv.size(), digest, &digestLength, EVP_sha256(), nullptr) != 1 ||
                digestLength * 2 < kMultigroupHashHexChars)
            {
                return {};
            }

            static constexpr char HEX_DIGITS[] = "0123456789abcdef";

            std::string name;
            name.reserve(kMultigroupHashHexChars);
            for (std::size_t i = 0; i < kMultigroupHashHexChars / 2; ++i)
            {
                name.push_back(HEX_DIGITS[(digest[i] >> 4) & 0x0F]);
                name.push_back(HEX_DIGITS[digest[i] & 0x0F]);
            }
            return name;
        }
    } // namespace

    bool isValidGroupName(std::string_view name)
    {
        if (name.empty() || name.size() > kMaxGroupNameSize || name == "." || name == "..")
        {
            return false;
        }

        for (const char c : name)
        {
            if (!isGroupNameChar(c))
            {
                return false;
            }
        }
        return true;
    }

    std::string resolveMergedConfigPath(std::vector<std::string> groups,
                                        const std::string& sharedGroupsRoot,
                                        const std::string& multiGroupsRoot)
    {
        groups = membershipGroups(std::move(groups));

        for (const auto& group : groups)
        {
            if (!isValidGroupName(group))
            {
                return {};
            }
        }

        // Plain concatenation, not a path join: the result is a cache key that must equal the
        // path MergedMgWatcher reports for the same file.
        if (groups.size() == 1)
        {
            return sharedGroupsRoot + "/" + groups.front() + kMergedConfigFilename;
        }

        const auto hash = multigroupHash(toGroupsCsv(groups));
        if (hash.empty())
        {
            return {};
        }
        return multiGroupsRoot + "/" + hash + kMergedConfigFilename;
    }
} // namespace remoted::control
