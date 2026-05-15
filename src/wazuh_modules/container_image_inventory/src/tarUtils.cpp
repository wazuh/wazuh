/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tarUtils.hpp"

#include <archive.h>
#include <archive_entry.h>

#include "imageArchiveParser.hpp"

namespace container_image_inventory
{
    namespace
    {
        struct ArchiveHandle
        {
            struct archive* a{nullptr};
            ~ArchiveHandle()
            {
                if (a)
                {
                    archive_read_free(a);
                }
            }
        };

        struct archive* open_tar(const std::vector<unsigned char>& bytes)
        {
            struct archive* a = archive_read_new();
            archive_read_support_format_tar(a);
            archive_read_support_format_gnutar(a);
            archive_read_support_filter_gzip(a);
            archive_read_support_filter_none(a);
            if (archive_read_open_memory(a, bytes.data(), bytes.size()) != ARCHIVE_OK)
            {
                archive_read_free(a);
                return nullptr;
            }
            return a;
        }
    } // namespace

    std::vector<TarMember> list_tar_members(const std::vector<unsigned char>& bytes)
    {
        std::vector<TarMember> out;
        ArchiveHandle h;
        h.a = open_tar(bytes);
        if (!h.a)
        {
            return out;
        }
        struct archive_entry* entry;
        while (archive_read_next_header(h.a, &entry) == ARCHIVE_OK)
        {
            const char* path = archive_entry_pathname(entry);
            if (!path)
            {
                archive_read_data_skip(h.a);
                continue;
            }
            TarMember m;
            m.raw_name = path;
            m.normalized = normalize_tar_path(path);
            m.is_file = (archive_entry_filetype(entry) == AE_IFREG);
            out.push_back(std::move(m));
            archive_read_data_skip(h.a);
        }
        return out;
    }

    bool extract_tar_member(const std::vector<unsigned char>& bytes,
                            const std::string& raw_name,
                            std::vector<unsigned char>& out_bytes)
    {
        ArchiveHandle h;
        h.a = open_tar(bytes);
        if (!h.a)
        {
            return false;
        }
        struct archive_entry* entry;
        while (archive_read_next_header(h.a, &entry) == ARCHIVE_OK)
        {
            const char* path = archive_entry_pathname(entry);
            if (!path || std::string(path) != raw_name)
            {
                archive_read_data_skip(h.a);
                continue;
            }
            int64_t sz = archive_entry_size(entry);
            out_bytes.clear();
            out_bytes.reserve(sz > 0 ? sz : 0);
            unsigned char buf[8192];
            la_ssize_t r;
            while ((r = archive_read_data(h.a, buf, sizeof(buf))) > 0)
            {
                out_bytes.insert(out_bytes.end(), buf, buf + r);
            }
            return true;
        }
        return false;
    }
} // namespace container_image_inventory
