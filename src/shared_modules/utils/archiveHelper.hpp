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
#include <filesystem>

template<typename F, typename G, F func1, G func2>
struct Deleter
{
    template<typename T>
    constexpr void operator()(T* arg) const
    {
        func1(arg);
        func2(arg);
    }
};

using ArchiveReadPtr = std::unique_ptr<
    struct archive,
    Deleter<decltype(&archive_read_close), decltype(&archive_read_free), archive_read_close, archive_read_free>>;
using ArchiveWritePtr = std::unique_ptr<
    struct archive,
    Deleter<decltype(&archive_write_close), decltype(&archive_write_free), archive_write_close, archive_write_free>>;

using ArchiveEntryPtr = std::unique_ptr<struct archive_entry>;

namespace Utils
{
    /**
     * @brief Decompression for .tar compressed files.
     *
     */
    class ArchiveHelper
    {
    private:
        static void copyData(struct archive* ar, struct archive* aw)
        {
            int r;
            const void* buff;
            size_t size;
            int64_t offset;

            for (;;)
            {
                r = archive_read_data_block(ar, &buff, &size, &offset);
                if (r == ARCHIVE_EOF)
                    return;
                if (r != ARCHIVE_OK)
                    throw std::runtime_error("Couldn't read file");
                if (archive_write_data_block(aw, buff, size, offset) != ARCHIVE_OK)
                {
                    throw std::runtime_error(archive_error_string(aw));
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
        static void decompress(const std::string& filename,
                               const std::string& output = "",
                               const std::vector<std::string>& extractOnly = {},
                               int flags = ARCHIVE_EXTRACT_UNLINK)
        {
            struct archive_entry* entry;
            int r;
            ArchiveReadPtr archiveRead(archive_read_new());
            ArchiveWritePtr archiveWrite(archive_write_disk_new());

            archive_write_disk_set_options(archiveRead.get(), flags);
            archive_read_support_format_tar(archiveRead.get());

            r = archive_read_open_filename(archiveRead.get(), filename.c_str(), 0);

            if (r != ARCHIVE_OK)
            {
                throw std::runtime_error("Couldn't open file");
            }

            for (;;)
            {
                r = archive_read_next_header(archiveRead.get(), &entry);
                if (r == ARCHIVE_EOF)
                    break;
                if (r != ARCHIVE_OK)
                {
                    throw std::runtime_error("Couldn't read file");
                }

                std::filesystem::path outputDir(std::filesystem::current_path() / output /
                                                archive_entry_pathname(entry));

                if (std::find_if(extractOnly.cbegin(),
                                 extractOnly.cend(),
                                 [&outputDir](const std::string& path)
                                 {
                                     size_t pos = outputDir.string().find(path);
                                     return pos != std::string::npos;
                                 }) != extractOnly.cend() ||
                    extractOnly.empty())
                {
                    archive_entry_set_pathname(entry, outputDir.c_str());
                    r = archive_write_header(archiveWrite.get(), entry);
                    if (r != ARCHIVE_OK)
                    {
                        throw std::runtime_error(archive_error_string(archiveWrite.get()));
                    }
                    else
                    {
                        copyData(archiveRead.get(), archiveWrite.get());
                        r = archive_write_finish_entry(archiveWrite.get());
                        if (r != ARCHIVE_OK)
                        {
                            throw std::runtime_error(archive_error_string(archiveWrite.get()));
                        }
                    }
                }
            }
        }
    };
} // namespace Utils

#endif // _ARCHIVE_HELPER_HPP
