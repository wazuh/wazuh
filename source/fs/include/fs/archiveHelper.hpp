/*
 * Copyright (C) 2015, Wazuh Inc.
 * Feb 8, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FS_ARCHIVE_HELPER_HPP
#define _FS_ARCHIVE_HELPER_HPP

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <memory>
#include <vector>

#include <archive.h>
#include <archive_entry.h>

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

namespace fs
{
/**
 * @brief Decompression for .tar compressed files.
 *
 */
class ArchiveHelper
{
private:
    /**
     * @brief Function that write read data to disk.
     *
     * @param archiveRead Read structure.
     * @param archiveWrite Write structure.
     */
    static void copyData(struct archive* archiveRead, struct archive* archiveWrite);

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
                           const std::string& outputDir = "",
                           const std::vector<std::string>& extractOnly = {},
                           int flags = 0);
};
} // namespace fs

#endif // _FS_ARCHIVE_HELPER_HPP
