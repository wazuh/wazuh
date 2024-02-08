/*
 * Utils abstract wait
 * Copyright (C) 2015, Wazuh Inc.
 * Feb 8, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ARCHIVE_HELPER_HPP
#define _ARCHIVE_HELPER_HPP

#include "archive.h"
#include "archive_entry.h"
#include "customDeleter.hpp"

namespace Utils
{
    /**
     * @brief Decompression for .tar compressed files.
     *
     */
    class ArchiveHelper
    {
    private:
        static int copy_data(struct archive* ar, struct archive* aw)
        {
            int r;
            const void* buff;
            size_t size;
            int64_t offset;

            for (;;)
            {
                r = archive_read_data_block(ar, &buff, &size, &offset);
                if (r == ARCHIVE_EOF)
                    return (ARCHIVE_OK);
                if (r != ARCHIVE_OK)
                    return (r);
                r = archive_write_data_block(aw, buff, size, offset);
                if (r != ARCHIVE_OK)
                {
                    fprintf(stderr, "archive_write_data_block(): %s", archive_error_string(aw));
                    return (r);
                }
            }
        }

    public:
        ArchiveHelper(const ArchiveHelper&) = delete;
        ArchiveHelper& operator=(const ArchiveHelper&) = delete;
        ArchiveHelper(ArchiveHelper&&) = delete;
        ArchiveHelper& operator=(ArchiveHelper&&) = delete;

        /**
         * @brief Uncompress TAR file.
         *
         * @param filePath Compressed (.tar) file path.
         */
        static void
        decompress(const std::string& filename, const std::string& outputDir = "", int flags = ARCHIVE_EXTRACT_UNLINK)
        {
            struct archive* a;
            struct archive* ext;
            struct archive_entry* entry;
            int r;

            a = archive_read_new();
            ext = archive_write_disk_new();

            archive_write_disk_set_options(ext, flags);
            archive_read_support_format_tar(a);

            r = archive_read_open_filename(a, filename.c_str(), 0);

            if (r != ARCHIVE_OK)
            {
                throw std::runtime_error("Couldn't open file");
            }

            for (;;)
            {
                r = archive_read_next_header(a, &entry);
                if (r == ARCHIVE_EOF)
                    break;
                if (r != ARCHIVE_OK)
                {
                    perror("Couldn't read file");
                    exit(1);
                }

                r = archive_write_header(ext, entry);
                if (r != ARCHIVE_OK)
                {
                    fprintf(stderr, "archive_write_header(): %s", archive_error_string(ext));
                }
                else
                {
                    copy_data(a, ext);
                    r = archive_write_finish_entry(ext);
                    if (r != ARCHIVE_OK)
                    {
                        fprintf(stderr, "archive_write_finish_entry(): %s", archive_error_string(ext));
                        exit(1);
                    }
                }
            }

            archive_read_close(a);
            archive_read_free(a);

            archive_write_close(ext);
            archive_write_free(ext);
        }
    };
} // namespace Utils

#endif // _ARCHIVE_HELPER_HPP
