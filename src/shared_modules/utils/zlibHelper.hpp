/*
 * Wazuh - Shared Modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ZLIB_HELPER_HPP
#define _ZLIB_HELPER_HPP

#include "customDeleter.hpp"
#include "minizip/unzip.h"
#include "stringHelper.h"
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <zlib.h>

#define KB (1024)
#define MB (1024 * 1024)

using ZFilePtr = std::unique_ptr<gzFile_s, CustomDeleter<decltype(&gzclose), gzclose>>;
using UnzFilePtr = std::unique_ptr<void, CustomDeleter<decltype(&unzClose), unzClose>>;

inline constexpr int GZ_BUF_LEN {16 * KB};
inline constexpr int ZIP_BUF_LEN {100 * MB};

namespace Utils
{
    /**
     * @brief Decompression for .gz compressed files
     *
     */
    class ZlibHelper final
    {
    private:
        ZlibHelper() = default;
        ~ZlibHelper() = default;

    public:
        ZlibHelper(const ZlibHelper&) = delete;
        ZlibHelper& operator=(const ZlibHelper&) = delete;
        ZlibHelper(ZlibHelper&&) = delete;
        ZlibHelper& operator=(ZlibHelper&&) = delete;

        /**
         * @brief Uncompress GZIP file.
         *
         * @param gzFilePath Compressed (.gz) file path.
         * @param outputFilePath Uncompressed file pah.
         */
        static void gzipDecompress(const std::filesystem::path& gzFilePath, const std::filesystem::path& outputFilePath)
        {
            // Check input file extension.
            if (gzFilePath.extension() != ".gz")
            {
                throw std::runtime_error("Input file " + gzFilePath.string() + " doesn't have .gz extension");
            }

            // Create uncompressed file.
            std::ofstream outputFile {outputFilePath};
            if (!outputFile.good())
            {
                throw std::runtime_error("Unable to create destination file: " + outputFilePath.string());
            }

            // Open compressed file.
            ZFilePtr gzFile {gzopen(gzFilePath.c_str(), "rb")};
            if (!gzFile)
            {
                throw std::runtime_error("Unable to open compressed file: " + gzFilePath.string());
            }

            int len {};
            char buf[GZ_BUF_LEN] {};
            do
            {
                len = gzread(gzFile.get(), buf, sizeof(buf));

                if (len > 0)
                {
                    if (outputFile.write(buf, len).bad())
                    {
                        // LCOV_EXCL_START
                        throw std::runtime_error("Unable to write to destination file: " + outputFilePath.string());
                        // LCOV_EXCL_STOP
                    }

                    buf[0] = '\0';
                }
            } while (len == sizeof(buf));
            outputFile.close();
        }

        /**
         * @brief Uncompress ZIP file and returns a list with the decompressed files.
         *
         * @param zipFilePath Compressed (.zip) file path.
         * @param outputDir Folder where the output files will be stored.
         * @return std::vector<std::string> List of decompressed files.
         */
        static std::vector<std::string> zipDecompress(const std::filesystem::path& zipFilePath,
                                                      const std::filesystem::path& outputDir)
        {
            // Open .zip file.
            UnzFilePtr spUnzFile {unzOpen(zipFilePath.c_str())};
            if (!spUnzFile)
            {
                throw std::runtime_error {"Unable to open compressed file: " + zipFilePath.string()};
            }

            // Get .zip file information (amount of files, i.e.).
            unz_global_info globalInfo;
            if (unzGetGlobalInfo(spUnzFile.get(), &globalInfo) != UNZ_OK)
            {
                throw std::runtime_error {"Unable to get global information of file: " + zipFilePath.string()};
            }

            // Iterate all compressed files within the .zip file.
            std::vector<std::string> decompressedFiles;
            decompressedFiles.reserve(globalInfo.number_entry);
            for (uLong currentFileIndex {0}; currentFileIndex < globalInfo.number_entry; ++currentFileIndex)
            {
                constexpr auto MAX_FILENAME_LEN {4096};
                unz_file_info fileInfo;
                char filename[MAX_FILENAME_LEN];
                if (unzGetCurrentFileInfo(
                        spUnzFile.get(), &fileInfo, filename, sizeof(filename), nullptr, 0, nullptr, 0) != UNZ_OK)
                {
                    throw std::runtime_error {"Unable to get current file information from zip file: " +
                                              zipFilePath.string()};
                }

                // Open current file within the .zip file.
                if (unzOpenCurrentFile(spUnzFile.get()) != UNZ_OK)
                {
                    throw std::runtime_error {"Unable to open current file: " + std::string(filename)};
                }

                const auto outputFilepath {outputDir / std::string(filename)};
                const auto isDir {Utils::endsWith(outputFilepath.string(), "/")};
                if (isDir)
                {
                    // Create output directory.
                    std::filesystem::create_directory(outputFilepath);
                }
                else
                {
                    // Create outputfile.
                    std::ofstream outFile {outputFilepath, std::ios::binary};
                    if (!outFile.good())
                    {
                        throw std::runtime_error {"Unable to create destination file: " + outputFilepath.string()};
                    }

                    // Read current file content.
                    unsigned long bytesRead, totalBytesRead {0};
                    do
                    {
                        // Read compressed data by ZIP_BUF_LEN chunks.
                        std::vector<char> buffer(ZIP_BUF_LEN);
                        bytesRead = unzReadCurrentFile(spUnzFile.get(), buffer.data(), buffer.size());
                        totalBytesRead += bytesRead;

                        // Store current chunk into output file.
                        outFile.write(buffer.data(), bytesRead);
                    } while (bytesRead > 0);

                    // Close output file.
                    outFile.close();

                    // Check total amount of bytes read.
                    if (totalBytesRead != fileInfo.uncompressed_size)
                    {
                        unzCloseCurrentFile(spUnzFile.get());
                        throw std::runtime_error {"Unable to read content of current file: " + std::string(filename)};
                    }
                }

                // Close current file.
                if (unzCloseCurrentFile(spUnzFile.get()) != UNZ_OK)
                {
                    throw std::runtime_error {"Unable to close current file: " + std::string(filename)};
                }

                if (!isDir)
                {
                    // Push filename into the output vector.
                    decompressedFiles.push_back(outputFilepath.string());
                }

                // Go to next file within the .zip file.
                if (currentFileIndex + 1 < globalInfo.number_entry)
                {
                    if (unzGoToNextFile(spUnzFile.get()) != UNZ_OK)
                    {
                        throw std::runtime_error {"Unable to get next file of: " + zipFilePath.string()};
                    }
                }
            }

            return decompressedFiles;
        }
    };
} // namespace Utils

#endif // _ZLIB_HELPER_HPP
