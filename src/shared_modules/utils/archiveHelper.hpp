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
#include <algorithm>
#include <atomic>
#include <filesystem>
#include <vector>

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

// C++ smart pointers usage to avoid manually free allocated memory.
using ArchiveReadPtr = std::unique_ptr<
    struct archive,
    Deleter<decltype(&archive_read_close), decltype(&archive_read_free), archive_read_close, archive_read_free>>;
using ArchiveWritePtr = std::unique_ptr<
    struct archive,
    Deleter<decltype(&archive_write_close), decltype(&archive_write_free), archive_write_close, archive_write_free>>;

namespace Utils
{
    /**
     * @brief Decompression for .tar compressed files.
     *
     */
    class ArchiveHelper
    {
    private:
        static void
        copyData(struct archive* archiveRead, struct archive* archiveWrite, const std::atomic<bool>& forceStop)
        {
            const void* buff {};
            size_t size {};
            int64_t offset {};

            while (!forceStop.load())
            {
                auto retVal = archive_read_data_block(archiveRead, &buff, &size, &offset);
                if (retVal == ARCHIVE_EOF)
                {
                    break;
                }

                if (retVal != ARCHIVE_OK)
                {
                    const std::string errMsg =
                        archive_error_string(archiveRead) ? archive_error_string(archiveRead) : "Unknown error";
                    throw std::runtime_error("Error reading file during data copy. Error: " + errMsg);
                }

                if (archive_write_data_block(archiveWrite, buff, size, offset) != ARCHIVE_OK)
                {
                    throw std::runtime_error(archive_error_string(archiveWrite));
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
         * @param filename Compressed (.tar) file name.
         * @param outputDir Destination path.
         * @param extractOnly Compressed element to extract.
         * @param flags Extraction flags.
         */
        static void decompress(const std::string& filename,
                               const std::atomic<bool>& forceStop = false,
                               const std::string& outputDir = "",
                               const std::vector<std::string>& extractOnly = {},
                               int flags = 0)
        {
            struct archive_entry* entry;
            ArchiveReadPtr archiveRead(archive_read_new());
            ArchiveWritePtr archiveWrite(archive_write_disk_new());
            std::vector<std::string> content {};

            archive_write_disk_set_options(archiveRead.get(), flags);
            archive_read_support_format_tar(archiveRead.get());

            auto retVal = archive_read_open_filename(archiveRead.get(), filename.c_str(), 0);

            if (retVal == ARCHIVE_EOF)
            {
                return;
            }

            if (retVal != ARCHIVE_OK)
            {
                const std::string errMsg =
                    archive_error_string(archiveRead.get()) ? archive_error_string(archiveRead.get()) : "Unknown error";
                throw std::runtime_error("Error opening file during decompression. Error: " + errMsg);
            }

            while (!forceStop.load())
            {
                retVal = archive_read_next_header(archiveRead.get(), &entry);
                if (retVal == ARCHIVE_EOF)
                {
                    return;
                }

                if (retVal != ARCHIVE_OK)
                {
                    const std::string errMsg = archive_error_string(archiveRead.get())
                                                   ? archive_error_string(archiveRead.get())
                                                   : "Unknown error";
                    throw std::runtime_error("Error reading next header during decompression. Error: " + errMsg);
                }

                std::filesystem::path outputDirPath(std::filesystem::current_path() / outputDir /
                                                    archive_entry_pathname(entry));

                if (std::find_if(extractOnly.cbegin(),
                                 extractOnly.cend(),
                                 [&outputDirPath](const std::string& path)
                                 {
                                     size_t pos = outputDirPath.string().find(path);
                                     return pos != std::string::npos;
                                 }) != extractOnly.cend() ||
                    extractOnly.empty())
                {
                    archive_entry_set_pathname(entry, outputDirPath.c_str());
                    content.emplace_back(outputDirPath);

                    if (archive_write_header(archiveWrite.get(), entry) != ARCHIVE_OK)
                    {
                        throw std::runtime_error(archive_error_string(archiveWrite.get()));
                    }

                    copyData(archiveRead.get(), archiveWrite.get(), forceStop);
                    retVal = archive_write_finish_entry(archiveWrite.get());
                    if (retVal != ARCHIVE_OK)
                    {
                        throw std::runtime_error(archive_error_string(archiveWrite.get()));
                    }
                }
            }

            if (forceStop.load())
            {
                for (const auto& item : content)
                {
                    std::filesystem::remove_all(item);
                }
            }
        }
    };
} // namespace Utils

#endif // _ARCHIVE_HELPER_HPP
