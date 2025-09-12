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
#include "defer.hpp"
#include "minizip/unzip.h"
#include "stringHelper.h"
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <zlib.h>

using ZFilePtr = std::unique_ptr<gzFile_s, CustomDeleter<decltype(&gzclose), gzclose>>;
using UnzFilePtr = std::unique_ptr<void, CustomDeleter<decltype(&unzClose), unzClose>>;

inline constexpr auto KB {1024};

inline constexpr auto GZ_BUF_LEN {16 * KB};
inline constexpr auto ZIP_BUF_LEN {64 * KB};

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
         * @brief Compress file to GZIP format.
         *
         * @param inputFilePath Input file path to compress.
         * @param gzFilePath Output compressed (.gz) file path.
         * @param compressionLevel Compression level (0-9, where 0 is no compression and 9 is maximum compression).
         */
        static void gzipCompress(const std::filesystem::path& inputFilePath,
                                 const std::filesystem::path& gzFilePath,
                                 int compressionLevel = 6)
        {
            // Validate compression level
            if (compressionLevel < 0 || compressionLevel > 9)
            {
                throw std::runtime_error("Invalid compression level: " + std::to_string(compressionLevel) +
                                         ". Must be between 0 and 9.");
            }

            // Check if input file exists
            if (!std::filesystem::exists(inputFilePath))
            {
                throw std::runtime_error("Input file does not exist: " + inputFilePath.string());
            }

            // Open input file
            std::ifstream inputFile {inputFilePath, std::ios::binary};
            if (!inputFile.good())
            {
                throw std::runtime_error("Unable to open input file: " + inputFilePath.string());
            }

            // Create compression mode string
            std::string mode = "wb" + std::to_string(compressionLevel);

            // Open compressed file for writing
            ZFilePtr gzFile {gzopen(gzFilePath.c_str(), mode.c_str())};
            if (!gzFile)
            {
                throw std::runtime_error("Unable to create compressed file: " + gzFilePath.string());
            }

            // Compress file content
            char buf[GZ_BUF_LEN] {};
            while (inputFile.read(buf, sizeof(buf)) || inputFile.gcount() > 0)
            {
                auto bytesRead = inputFile.gcount();
                if (gzwrite(gzFile.get(), buf, static_cast<unsigned int>(bytesRead)) != bytesRead)
                {
                    throw std::runtime_error("Error writing to compressed file: " + gzFilePath.string());
                }
            }

            inputFile.close();
        }

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
                // File doesn't exist or is invalid (e.g. empty ZIP).
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
            do
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

                // Close current file when going out of scope.
                DEFER([&spUnzFile]() { unzCloseCurrentFile(spUnzFile.get()); });

                // Check for possible Zip Slip vulnerability.
                const auto outputFilepath {(outputDir / std::string(filename)).lexically_normal()};
                if (!Utils::startsWith(outputFilepath, outputDir))
                {
                    throw std::runtime_error {"A potentially insecure path was found: " + outputFilepath.string()};
                }

                if (Utils::endsWith(outputFilepath, "/"))
                {
                    // The file is a directory. Create it.
                    std::filesystem::create_directory(outputFilepath);
                }
                else
                {
                    // Create output file.
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

                    // Close output file to flush the stream and check for error flags.
                    outFile.close();
                    if (!outFile.good())
                    {
                        throw std::runtime_error {"Error while writing output file: " + outputFilepath.string()};
                    }

                    // Check total amount of bytes read.
                    if (totalBytesRead != fileInfo.uncompressed_size)
                    {
                        throw std::runtime_error {"Unable to read content of current file: " + std::string(filename)};
                    }

                    // Push filename into the output vector.
                    decompressedFiles.push_back(outputFilepath);
                }
            } while (unzGoToNextFile(spUnzFile.get()) == UNZ_OK);

            return decompressedFiles;
        }
    };
} // namespace Utils

#endif // _ZLIB_HELPER_HPP
