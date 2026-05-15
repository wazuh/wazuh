/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "packageDbExtractor.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

#include "tarUtils.hpp"

namespace container_image_inventory
{
    std::vector<CandidatePath> candidate_db_paths()
    {
        return {
            {"var/lib/dpkg/status", PackageBackend::Dpkg},
            {"lib/apk/db/installed", PackageBackend::Apk},
            {"var/lib/rpm/rpmdb.sqlite", PackageBackend::RpmSqlite},
            {"usr/lib/sysimage/rpm/rpmdb.sqlite", PackageBackend::RpmSqlite},
            {"var/lib/rpm/Packages", PackageBackend::RpmBdb},
            {"usr/lib/sysimage/rpm/Packages", PackageBackend::RpmBdb},
            {"var/lib/rpm/Packages.db", PackageBackend::RpmNdbUnsupported},
            {"usr/lib/sysimage/rpm/Packages.db", PackageBackend::RpmNdbUnsupported},
        };
    }

    SelectedDb pick_database(BlobProvider& provider,
                             const std::map<std::string, ResolvedEntry>& vfs,
                             TraceFn trace)
    {
        SelectedDb sel;
        for (const auto& cand : candidate_db_paths())
        {
            auto it = vfs.find(cand.path);
            if (it == vfs.end() || it->second.is_deleted)
            {
                continue;
            }
            sel.backend = cand.backend;
            sel.database_path = cand.path;
            sel.entry = it->second;
            if (trace)
            {
                std::string be;
                switch (cand.backend)
                {
                    case PackageBackend::Dpkg: be = "dpkg"; break;
                    case PackageBackend::Apk: be = "apk"; break;
                    case PackageBackend::RpmSqlite: be = "rpm/sqlite"; break;
                    case PackageBackend::RpmBdb: be = "rpm/bdb"; break;
                    case PackageBackend::RpmNdbUnsupported: be = "rpm/ndb-unsupported"; break;
                    default: be = "none"; break;
                }
                trace("selected backend=" + be + " database=" + cand.path);
            }
            if (cand.backend != PackageBackend::RpmNdbUnsupported)
            {
                const auto layer_bytes = provider.get_blob(sel.entry.layer_key);
                if (!extract_tar_member(layer_bytes, sel.entry.tar_member_name, sel.bytes))
                {
                    throw std::runtime_error("failed to extract DB file from layer");
                }
            }
            return sel;
        }
        return sel;
    }

    std::string write_temp_file(const std::vector<unsigned char>& bytes,
                                const std::string& suffix)
    {
        std::string tmpl = "/tmp/cii-poc-XXXXXX" + suffix;
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        int fd = mkstemps(buf.data(), static_cast<int>(suffix.size()));
        if (fd < 0)
        {
            throw std::runtime_error("mkstemps failed");
        }
        ssize_t n = write(fd, bytes.data(), bytes.size());
        close(fd);
        if (n != static_cast<ssize_t>(bytes.size()))
        {
            throw std::runtime_error("temp write short");
        }
        return std::string(buf.data());
    }
} // namespace container_image_inventory
