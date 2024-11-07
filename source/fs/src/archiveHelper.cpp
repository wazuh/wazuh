/*
 * Copyright (C) 2015, Wazuh Inc.
 * November 5, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fs/archiveHelper.hpp"

namespace fs
{
void ArchiveHelper::copyData(struct archive* archiveRead, struct archive* archiveWrite)
{
    const void* buff {};
    size_t size {};
    int64_t offset {};

    int retVal {ARCHIVE_EOF};
    while (retVal = archive_read_data_block(archiveRead, &buff, &size, &offset), retVal == ARCHIVE_OK)
    {
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

void ArchiveHelper::decompress(const std::string& filename,
                               const std::string& outputDir,
                               const std::vector<std::string>& extractOnly,
                               int flags)
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

    while (retVal = archive_read_next_header(archiveRead.get(), &entry), retVal == ARCHIVE_OK)
    {
        if (retVal == ARCHIVE_EOF)
        {
            break;
        }

        if (retVal != ARCHIVE_OK)
        {
            const std::string errMsg =
                archive_error_string(archiveRead.get()) ? archive_error_string(archiveRead.get()) : "Unknown error";
            throw std::runtime_error("Error reading next header during decompression. Error: " + errMsg);
        }

        std::filesystem::path outputDirPath(std::filesystem::current_path() / outputDir
                                            / archive_entry_pathname(entry));

        if (std::find_if(extractOnly.cbegin(),
                         extractOnly.cend(),
                         [&outputDirPath](const std::string& path)
                         {
                             size_t pos = outputDirPath.string().find(path);
                             return pos != std::string::npos;
                         })
                != extractOnly.cend()
            || extractOnly.empty())
        {
            archive_entry_set_pathname(entry, outputDirPath.c_str());
            content.emplace_back(outputDirPath);

            if (archive_write_header(archiveWrite.get(), entry) != ARCHIVE_OK)
            {
                throw std::runtime_error(archive_error_string(archiveWrite.get()));
            }

            copyData(archiveRead.get(), archiveWrite.get());
            retVal = archive_write_finish_entry(archiveWrite.get());
            if (retVal != ARCHIVE_OK)
            {
                throw std::runtime_error(archive_error_string(archiveWrite.get()));
            }
        }
    }
}
} // namespace fs
