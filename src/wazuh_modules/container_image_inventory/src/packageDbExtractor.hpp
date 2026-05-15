/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_DB_EXTRACTOR_HPP
#define _PACKAGE_DB_EXTRACTOR_HPP

#include <map>
#include <string>
#include <vector>

#include "blobProvider.hpp"
#include "containerImageInventoryTypes.hpp"
#include "overlayFsResolver.hpp"

namespace container_image_inventory
{
    enum class PackageBackend
    {
        None,
        Dpkg,
        Apk,
        RpmSqlite,
        RpmBdb,
        RpmNdbUnsupported
    };

    struct CandidatePath
    {
        std::string path;
        PackageBackend backend;
    };

    // Ordered list of probed candidate paths.
    std::vector<CandidatePath> candidate_db_paths();

    struct SelectedDb
    {
        PackageBackend backend{PackageBackend::None};
        std::string database_path;
        ResolvedEntry entry;
        std::vector<unsigned char> bytes;
    };

    // Pick the highest-priority candidate from the resolved VFS and read its
    // bytes through the BlobProvider. For NDB the bytes are not extracted
    // because the parser is detect-only.
    SelectedDb pick_database(BlobProvider& provider,
                             const std::map<std::string, ResolvedEntry>& vfs,
                             TraceFn trace);

    std::string write_temp_file(const std::vector<unsigned char>& bytes,
                                const std::string& suffix);
} // namespace container_image_inventory

#endif
