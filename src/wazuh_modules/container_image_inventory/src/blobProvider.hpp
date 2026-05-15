/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BLOB_PROVIDER_HPP
#define _BLOB_PROVIDER_HPP

#include <string>
#include <vector>

namespace container_image_inventory
{
    // Abstract source of byte blobs identified by an opaque key. Archive mode
    // uses tar member paths; remote mode uses content-addressed digests.
    class BlobProvider
    {
    public:
        virtual ~BlobProvider() = default;
        // Returns the raw bytes for `key`. Throws std::runtime_error on
        // failure (missing key, network error, etc).
        virtual std::vector<unsigned char> get_blob(const std::string& key) = 0;
    };
} // namespace container_image_inventory

#endif
