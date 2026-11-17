/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry_token_cache.hpp"

#include "hashHelper.h"
#include "wazuhCommon.hpp"

namespace containerimages
{
    std::string RegistryTokenCache::makeKey(const std::string& host,
                                            const std::string& accessKeyIdKey,
                                            const std::string& secretAccessKeyKey,
                                            const std::string& region,
                                            const std::string& accessKeyId,
                                            const std::string& secretAccessKey)
    {
        // Hashed piece by piece from the caller's copies, so no further copy of either
        // value is made that would have to be scrubbed.
        Utils::HashData hash {Utils::HashType::Sha256};
        hash.update(accessKeyId.data(), accessKeyId.size());
        hash.update("\n", 1);
        hash.update(secretAccessKey.data(), secretAccessKey.size());
        const auto digest {hash.hash()};

        return host + '\n' + accessKeyIdKey + '\n' + secretAccessKeyKey + '\n' + region + '\n' +
               wazuh::hex_encode(digest.data(), digest.size());
    }
} // namespace containerimages
