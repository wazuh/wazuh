/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fileDecompressor.hpp"

#include <gtest/gtest.h>

// ZSTD_c_windowLog/streaming internals used here only to build fixtures (the inverse of
// production's decompress()), not exercised by the production code under test -- same rationale
// as the manager's own zstdTestHelper.hpp, which this file's window-log fixture mirrors.
#include <zstd.h>

// opendir/readdir, not <filesystem>: mingw-w64 ships dirent.h (/usr/share/mingw-w64/include),
// so the winagent cross-build -- the only platform where the leak this guards is observable --
// compiles this with no #ifdef.
#include <dirent.h>

#include <fstream>
#include <string_view>

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

    // Counts this class's own sibling temp files (createExclusiveTempFile's "hc_zstd_dec_"
    // prefix) so a leak shows up as a rising count rather than an absolute one -- the spool dir is
    // a shared temp dir that may already hold unrelated files.
    std::size_t countDecompressorTempFiles(const std::string& dir)
    {
        DIR* handle = opendir(dir.c_str());

        if (handle == nullptr)
        {
            return 0;
        }

        std::size_t count = 0;

        while (const dirent* entry = readdir(handle))
        {
            if (std::string_view {entry->d_name}.rfind("hc_zstd_dec_", 0) == 0)
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

    std::string zstdCompress(std::string_view plain, int level = 3)
    {
        std::string out(ZSTD_compressBound(plain.size()), '\0');
        const std::size_t written = ZSTD_compress(out.data(), out.size(), plain.data(), plain.size(), level);
        EXPECT_FALSE(ZSTD_isError(written));
        out.resize(written);
        return out;
    }

    // Forces the frame header to DECLARE a window of 2^windowLog bytes, regardless of how little
    // content actually needs it -- mirrors the manager's own zstdTestHelper.hpp
    // (zstdCompressWithDeclaredWindowLog), used there to exercise the identical kMaxDeclaredWindowSize
    // guard on the request-decoding side. Fed and ended in separate calls: the frame header must be
    // written before zstd has seen the whole input, or it sizes the window down to match.
    std::string zstdCompressWithDeclaredWindowLog(std::string_view plain, int windowLog)
    {
        ZSTD_CCtx* cctx = ZSTD_createCCtx();
        EXPECT_NE(nullptr, cctx);
        struct Guard
        {
            ZSTD_CCtx* ctx;
            ~Guard()
            {
                ZSTD_freeCCtx(ctx);
            }
        } guard {cctx};

        ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, windowLog);

        std::string out(ZSTD_compressBound(plain.size()) + 1024, '\0');
        ZSTD_outBuffer output {out.data(), out.size(), 0};

        ZSTD_inBuffer in {plain.data(), plain.size(), 0};

        while (in.pos < in.size)
        {
            const std::size_t ret = ZSTD_compressStream2(cctx, &output, &in, ZSTD_e_continue);
            EXPECT_FALSE(ZSTD_isError(ret));
        }

        ZSTD_inBuffer end {nullptr, 0, 0};
        std::size_t remaining = 0;

        do
        {
            remaining = ZSTD_compressStream2(cctx, &output, &end, ZSTD_e_end);
            EXPECT_FALSE(ZSTD_isError(remaining));
        }
        while (remaining != 0);

        out.resize(output.pos);
        return out;
    }

    class FileDecompressorTest : public ::testing::Test
    {
        protected:
            ZstdFileDecompressor m_decompressor;
            std::string m_tempDir = ::testing::TempDir();
    };
} // namespace

TEST_F(FileDecompressorTest, RoundTripDecompressesBackToTheSourceAndReplacesTheFileInPlace)
{
    const std::string plain(2000, 'a');
    const std::string compressed = zstdCompress(plain);
    const std::string path = writeTempFile("hc_fd_roundtrip.bin", compressed);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(plain.size(), *result);
    EXPECT_EQ(plain, readWholeFile(path)); // Same path, now holding plain bytes.
}

TEST_F(FileDecompressorTest, MalformedHeaderReturnsNulloptAndLeavesTheOriginalUntouched)
{
    const std::string garbage = "not a zstd frame at all";
    const std::string path = writeTempFile("hc_fd_malformed.bin", garbage);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(garbage, readWholeFile(path)); // Untouched: the caller discards it itself.
}

TEST_F(FileDecompressorTest, AFailedDecompressionLeavesNoTempFileBehind)
{
    // Passes on POSIX either way -- an open file unlinks fine there. It is Windows that refuses to
    // delete a file with a live handle, so this only ever fails on the winagent build, and only if
    // a failure path removes the temp file before closing it.
    const std::size_t before = countDecompressorTempFiles(m_tempDir);
    const std::string path = writeTempFile("hc_fd_leak.bin", "not a zstd frame at all");

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(before, countDecompressorTempFiles(m_tempDir));
}

TEST_F(FileDecompressorTest, TruncatedFrameReturnsNullopt)
{
    const std::string plain(5000, 'b');
    const std::string compressed = zstdCompress(plain);
    // Cut off the back half: a valid header, an incomplete body.
    const std::string truncated = compressed.substr(0, compressed.size() / 2);
    const std::string path = writeTempFile("hc_fd_truncated.bin", truncated);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    EXPECT_FALSE(result.has_value());
}

TEST_F(FileDecompressorTest, DeclaredWindowOverTheHardCeilingIsRefused)
{
    // windowLog 24 = 16 MiB, over the 8 MiB ceiling -- mirrors the manager's own equivalent test
    // for its request-side decoder (zstdDecoder_test.cpp).
    const std::string plain(128, 'q');
    const std::string compressed = zstdCompressWithDeclaredWindowLog(plain, 24);
    const std::string path = writeTempFile("hc_fd_window_over.bin", compressed);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    EXPECT_FALSE(result.has_value());
}

TEST_F(FileDecompressorTest, DeclaredWindowAtTheHardCeilingIsStillAccepted)
{
    // windowLog 23 (8 MiB) is what zstd itself uses at its highest normal levels -- the ceiling
    // must not be tighter than that, or this feature's own legitimate 64 MiB merged.mg traffic
    // would be refused (see fileDecompressor.cpp's kMaxDeclaredWindowLog comment).
    const std::string plain(128, 'q');
    const std::string compressed = zstdCompressWithDeclaredWindowLog(plain, 23);
    const std::string path = writeTempFile("hc_fd_window_at.bin", compressed);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(plain, readWholeFile(path));
}

TEST_F(FileDecompressorTest, DeclaredWindowOverTheCeilingIsRefusedInAConcatenatedSecondFrameToo)
{
    // ZSTD_decompressStream() decodes concatenated frames and re-allocates for each one, so a
    // ceiling enforced by parsing only the first frame's header is no ceiling at all: without
    // ZSTD_d_windowLogMax this ~100-byte input makes the decoder reserve 128 MiB.
    const std::string compressed = zstdCompressWithDeclaredWindowLog(std::string(64, 'a'), 16) +
                                   zstdCompressWithDeclaredWindowLog(std::string(64, 'b'), 27);
    const std::string path = writeTempFile("hc_fd_window_second_frame.bin", compressed);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(compressed, readWholeFile(path));
}

TEST_F(FileDecompressorTest, AFrameDecodingToNoPlainBytesAtAllIsRefused)
{
    // A bare skippable frame (magic 0x184D2A50 + a 4-byte length + its payload). zstd consumes
    // these silently and produces nothing, so without the zero-output check this would "succeed"
    // and rename an empty file over the caller's download.
    const std::string skippable {"\x50\x2A\x4D\x18\x04\x00\x00\x00\xDE\xAD\xBE\xEF", 12};
    const std::string path = writeTempFile("hc_fd_skippable_only.bin", skippable);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(skippable, readWholeFile(path));
}

TEST_F(FileDecompressorTest, OutputExceedingTheCapAbortsAsSoonAsItIsCrossed)
{
    const std::string plain(10000, 'c');
    const std::string compressed = zstdCompress(plain);
    const std::string path = writeTempFile("hc_fd_overcap.bin", compressed);

    const auto result = m_decompressor.decompress(path, 100, nullptr);

    EXPECT_FALSE(result.has_value());
    // The original (still-compressed) file is left in place for the caller to discard.
    EXPECT_TRUE(fileExists(path));
}

TEST_F(FileDecompressorTest, OutputExactlyAtTheCapSucceeds)
{
    const std::string plain(1000, 'd');
    const std::string compressed = zstdCompress(plain);
    const std::string path = writeTempFile("hc_fd_exactcap.bin", compressed);

    const auto result = m_decompressor.decompress(path, plain.size(), nullptr);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(plain.size(), *result);
}

TEST_F(FileDecompressorTest, ZeroCapMeansUnlimited)
{
    const std::string plain(200000, 'e');
    const std::string compressed = zstdCompress(plain);
    const std::string path = writeTempFile("hc_fd_nocap.bin", compressed);

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(plain.size(), *result);
}

TEST_F(FileDecompressorTest, UnreadableSourceReturnsNullopt)
{
    const auto result =
        m_decompressor.decompress("/nonexistent/hc-spool/response.bin", 0, nullptr);
    EXPECT_FALSE(result.has_value());
}

TEST_F(FileDecompressorTest, ABareFilenameDecompressesInTheWorkingDirectory)
{
    // The scratch file now follows the target instead of a caller-supplied spool dir, so a target
    // with no directory component has to resolve to "." rather than to the system temp dir.
    const std::string plain(500, 'g');
    const std::string compressed = zstdCompress(plain);
    const std::string path = "hc_fd_bare_name.bin";
    {
        std::ofstream file {path, std::ios::binary};
        file << compressed;
    }

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(plain, readWholeFile(path));
    std::remove(path.c_str());
}

TEST_F(FileDecompressorTest, EmptySourceFileReturnsNullopt)
{
    const std::string path = writeTempFile("hc_fd_empty_src.bin", "");

    const auto result = m_decompressor.decompress(path, 0, nullptr);

    EXPECT_FALSE(result.has_value());
}

TEST_F(FileDecompressorTest, AbortFlagStopsDecompressionAndReturnsNullopt)
{
    const std::string plain(2000, 'h');
    const std::string compressed = zstdCompress(plain);
    const std::string path = writeTempFile("hc_fd_abort.bin", compressed);

    const std::atomic<bool> abortFlag {true}; // Already set before the first chunk is read.
    const auto result = m_decompressor.decompress(path, 0, &abortFlag);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(compressed, readWholeFile(path)); // Untouched.
}
