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
#include <filesystem>
#include <fstream>
#include <utility>
#include <zlib.h>

using ZFilePtr = std::unique_ptr<gzFile_s, CustomDeleter<decltype(&gzclose), gzclose>>;

inline constexpr int BUF_LEN {16384};

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
                throw std::runtime_error("Unable to create destination file");
            }

            // Open compressed file.
            ZFilePtr gzFile {gzopen(gzFilePath.c_str(), "rb")};
            if (!gzFile)
            {
                throw std::runtime_error("Unable to open compressed file");
            }

            int len {};
            char buf[BUF_LEN] {};
            do
            {
                len = gzread(gzFile.get(), buf, sizeof(buf));

                if (len > 0)
                {
                    if (outputFile.write(buf, len).bad())
                    {
                        // LCOV_EXCL_START
                        throw std::runtime_error("Unable to write to destination file");
                        // LCOV_EXCL_STOP
                    }

                    buf[0] = '\0';
                }
            } while (len == sizeof(buf));
            outputFile.close();
        }
    };
} // namespace Utils

#endif // _ZLIB_HELPER_HPP
