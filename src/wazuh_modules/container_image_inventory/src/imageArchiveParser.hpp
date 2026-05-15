/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IMAGE_ARCHIVE_PARSER_HPP
#define _IMAGE_ARCHIVE_PARSER_HPP

#include <map>
#include <string>
#include <vector>

#include "blobProvider.hpp"
#include "containerImageInventoryTypes.hpp"

namespace container_image_inventory
{
    struct ImageManifestEntry
    {
        std::string config;
        std::vector<std::string> layers;
        std::vector<std::string> repo_tags;
    };

    class ImageArchiveParser
    {
    public:
        explicit ImageArchiveParser(TraceFn trace = nullptr);

        bool load(const std::string& archive_path);

        bool has_member(const std::string& name) const;
        const std::vector<unsigned char>& member_bytes(const std::string& name) const;

        ImageManifestEntry read_manifest();
        ImageMetadata read_image_config(const ImageManifestEntry& entry);

    private:
        TraceFn m_trace;
        std::map<std::string, std::vector<unsigned char>> m_members;
        void trace(const std::string& msg) const;
    };

    // Adapter that exposes outer-archive member bytes through BlobProvider.
    class ArchiveBlobProvider : public BlobProvider
    {
    public:
        explicit ArchiveBlobProvider(ImageArchiveParser& parser);
        std::vector<unsigned char> get_blob(const std::string& key) override;

    private:
        ImageArchiveParser& m_parser;
    };

    std::string normalize_tar_path(const std::string& raw);
    std::string sha256_hex(const unsigned char* data, size_t len);
} // namespace container_image_inventory

#endif
