/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fileCompressor.hpp"

#include <gtest/gtest.h>

// ZSTD_getFrameHeader()/ZSTD_FrameHeader live behind this opt-in (same as the
// manager's zstdDecoder.cpp) -- used here only to assert the pledged content
// size made it into the frame, not in the production code under test.
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

// opendir/readdir, not <filesystem>: mingw-w64 ships dirent.h, so the winagent cross-build --
// the only platform where the leak this guards is observable -- compiles this with no #ifdef.
#include <dirent.h>

#include <fstream>
#include <string_view>
#include <vector>

namespace
{
    std::string writeTempFile(const std::string& name, const std::string& contents)
    {
        const std::string path = ::testing::TempDir() + name;
        std::ofstream file {path, std::ios::binary};
        file << contents;
        file.close();
        return path;
    }

    std::string readWholeFile(const std::string& path)
    {
        std::ifstream file {path, std::ios::binary};
        return std::string {std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {}};
    }

    // Counts this class's own sibling temp files (createExclusiveTempFile's "hc_zstd_" prefix) so
    // a leak shows up as a rising count rather than an absolute one -- the spool dir is a shared
    // temp dir that may already hold unrelated files.
    std::size_t countCompressorTempFiles(const std::string& dir)
    {
        DIR* handle = opendir(dir.c_str());

        if (handle == nullptr)
        {
            return 0;
        }

        std::size_t count = 0;

        while (const dirent* entry = readdir(handle))
        {
            if (std::string_view {entry->d_name}.rfind("hc_zstd_", 0) == 0)
            {
                count++;
            }
        }

        closedir(handle);
        return count;
    }

    bool fileExists(const std::string& path)
    {
        return std::ifstream {path}.good();
    }

    class FileCompressorTest : public ::testing::Test
    {
        protected:
            ZstdFileCompressor m_compressor;
            std::string m_spoolDir = ::testing::TempDir();
    };
} // namespace

TEST_F(FileCompressorTest, RoundTripCompressesAndDecompressesBackToTheSource)
{
    // Long and repetitive so it actually shrinks under zstd's frame overhead.
    const std::string plain(2000, 'a');
    const std::string sourcePath = writeTempFile("hc_fc_roundtrip_src.bin", plain);

    const auto result = m_compressor.compress(sourcePath, plain.size(), m_spoolDir, nullptr);

    ASSERT_TRUE(result.has_value());
    const auto& [spoolFile, compressedSize] = *result;
    ASSERT_NE(nullptr, spoolFile);
    EXPECT_TRUE(fileExists(spoolFile->path()));
    EXPECT_LT(compressedSize, plain.size());

    const std::string compressedBytes = readWholeFile(spoolFile->path());
    ASSERT_EQ(compressedSize, compressedBytes.size());

    std::vector<char> decompressed(plain.size());
    const size_t decompressedSize = ZSTD_decompress(decompressed.data(), decompressed.size(),
                                                    compressedBytes.data(), compressedBytes.size());
    ASSERT_FALSE(ZSTD_isError(decompressedSize));
    ASSERT_EQ(plain.size(), decompressedSize);
    EXPECT_EQ(plain, std::string(decompressed.begin(), decompressed.end()));
}

TEST_F(FileCompressorTest, CompressedFrameDeclaresThePledgedContentSize)
{
    const std::string plain(500, 'b');
    const std::string sourcePath = writeTempFile("hc_fc_pledged_src.bin", plain);

    const auto result = m_compressor.compress(sourcePath, plain.size(), m_spoolDir, nullptr);

    ASSERT_TRUE(result.has_value());
    const std::string compressedBytes = readWholeFile(result->first->path());

    ZSTD_FrameHeader header {};
    const size_t headerResult = ZSTD_getFrameHeader(&header, compressedBytes.data(), compressedBytes.size());
    ASSERT_EQ(0u, headerResult); // 0 == header fully parsed.
    EXPECT_EQ(plain.size(), header.frameContentSize);
}

TEST_F(FileCompressorTest, UnreadableSourceReturnsNullopt)
{
    const auto result =
        m_compressor.compress("/nonexistent/hc-spool/session.bin", 4, m_spoolDir, nullptr);
    EXPECT_FALSE(result.has_value());
}

TEST_F(FileCompressorTest, UnwritableSpoolDirReturnsNullopt)
{
    const std::string sourcePath = writeTempFile("hc_fc_unwritable_src.bin", "body");
    const auto result = m_compressor.compress(sourcePath, 4, "/nonexistent/hc-spool-dir", nullptr);
    EXPECT_FALSE(result.has_value());
}

TEST_F(FileCompressorTest, EmptySpoolDirFallsBackToADefaultTempDirectory)
{
    // ModuleConfig::spoolDir is never actually populated by the C bridge
    // today -- callers (StatefulStream) pass it straight through, so an empty
    // string here must still succeed rather than trying to write to "/".
    const std::string sourcePath = writeTempFile("hc_fc_empty_dir_src.bin", "body");
    const auto result = m_compressor.compress(sourcePath, 4, "", nullptr);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(fileExists(result->first->path()));
}

TEST_F(FileCompressorTest, AbortFlagStopsCompressionAndReturnsNullopt)
{
    const std::string plain(2000, 'c');
    const std::string sourcePath = writeTempFile("hc_fc_abort_src.bin", plain);

    const std::atomic<bool> abortFlag {true}; // Already set before the first chunk is read.
    const auto result = m_compressor.compress(sourcePath, plain.size(), m_spoolDir, &abortFlag);

    EXPECT_FALSE(result.has_value());
}

TEST_F(FileCompressorTest, AnAbortedCompressionLeavesNoTempFileBehind)
{
    // Passes on POSIX either way -- an open file unlinks fine there. It is Windows that refuses to
    // delete a file with a live handle, so this only ever fails on the winagent build, and only if
    // a failure path removes the temp file before closing it.
    const std::size_t before = countCompressorTempFiles(m_spoolDir);
    const std::string plain(2000, 'c');
    const std::string sourcePath = writeTempFile("hc_fc_leak_src.bin", plain);

    const std::atomic<bool> abortFlag {true};
    const auto result = m_compressor.compress(sourcePath, plain.size(), m_spoolDir, &abortFlag);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(before, countCompressorTempFiles(m_spoolDir));
}

TEST_F(FileCompressorTest, EmptySourceProducesAValidMinimalFrame)
{
    const std::string sourcePath = writeTempFile("hc_fc_empty_src.bin", "");

    const auto result = m_compressor.compress(sourcePath, 0, m_spoolDir, nullptr);

    ASSERT_TRUE(result.has_value());
    const std::string compressedBytes = readWholeFile(result->first->path());
    std::vector<char> decompressed(1);
    const size_t decompressedSize = ZSTD_decompress(decompressed.data(), decompressed.size(),
                                                    compressedBytes.data(), compressedBytes.size());
    ASSERT_FALSE(ZSTD_isError(decompressedSize));
    EXPECT_EQ(0u, decompressedSize);
}
