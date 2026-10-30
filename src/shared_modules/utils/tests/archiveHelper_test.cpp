/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * February 9, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "archiveHelper_test.hpp"
#include "archiveHelper.hpp"
#include <filesystem>
#include <fstream>
#ifndef _WIN32
#include <csignal>
#include <sys/resource.h>
#endif

const auto BASE_PATH {std::filesystem::current_path() / "input_files/archiveHelper/"};
const auto OUTPUT_DIR_PATH {std::filesystem::current_path() / "output_dir"};
const auto OUTPUT_NESTED_DIRS_PATH {std::filesystem::current_path() / "output_dir/output_subdir"};

const auto COMPRESSED_MULTIPLE_FILES_PATH {BASE_PATH / "content_examples.tar"};
const auto COMPRESSED_DIR_PATH {BASE_PATH / "content_dir.tar"};
const auto BASE_EXAMPLE1_PATH {BASE_PATH / "content_example1.json"};
const auto BASE_EXAMPLE2_PATH {BASE_PATH / "content_example2.json"};

const auto DECOMPRESSED_FILE1_PATH {"content_example1.json"};
const auto DECOMPRESSED_FILE2_PATH {"content_example2.json"};
const auto DECOMPRESSED_DIR_PATH {"content_dir"};
const auto DECOMPRESSED_DIR_FILE1_PATH {std::filesystem::current_path() / DECOMPRESSED_DIR_PATH /
                                        "content_example1.json"};
const auto DECOMPRESSED_DIR_FILE2_PATH {std::filesystem::current_path() / DECOMPRESSED_DIR_PATH /
                                        "content_example2.json"};
const auto DECOMPRESSED_OUTPUT_DIR_FILE1_PATH {OUTPUT_DIR_PATH / DECOMPRESSED_DIR_PATH / "content_example1.json"};
const auto DECOMPRESSED_OUTPUT_DIR_FILE2_PATH {OUTPUT_DIR_PATH / DECOMPRESSED_DIR_PATH / "content_example2.json"};

const auto DECOMPRESSED_OUTPUT_NESTED_DIRS_FILE1_PATH {OUTPUT_NESTED_DIRS_PATH / DECOMPRESSED_DIR_PATH /
                                                       "content_example1.json"};
const auto DECOMPRESSED_OUTPUT_NESTED_DIRS_FILE2_PATH {OUTPUT_NESTED_DIRS_PATH / DECOMPRESSED_DIR_PATH /
                                                       "content_example2.json"};

TEST(ArchiveHelperTest, InvalidInputPath)
{
    try
    {
        Utils::ArchiveHelper::decompress("./nonexistent_file");
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ("Error opening file during decompression. Error: Failed to open './nonexistent_file'", e.what());
    }
    catch (...)
    {
        FAIL() << "Expected std::runtime_error";
    }
}

TEST(ArchiveHelperTest, InvalidFormat)
{
    EXPECT_TRUE(std::filesystem::exists(BASE_EXAMPLE1_PATH));
    try
    {
        Utils::ArchiveHelper::decompress(BASE_EXAMPLE1_PATH);
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ("Error opening file during decompression. Error: Unrecognized archive format", e.what());
    }
    catch (...)
    {
        FAIL() << "Expected std::runtime_error";
    }
}

TEST(ArchiveHelperTest, SuccessfulDecompressionMultipleFiles)
{
    Utils::ArchiveHelper::decompress(COMPRESSED_MULTIPLE_FILES_PATH);

    std::ifstream inputFile(DECOMPRESSED_FILE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile1;
    getline(inputFile, decompressedFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(DECOMPRESSED_FILE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile2;
    getline(inputFile, decompressedFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile1;
    getline(inputFile, originalFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile2;
    getline(inputFile, originalFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    EXPECT_STREQ(decompressedFile1.c_str(), originalFile1.c_str());
    EXPECT_STREQ(decompressedFile2.c_str(), originalFile2.c_str());
    EXPECT_TRUE(std::filesystem::remove_all(DECOMPRESSED_FILE1_PATH));
    EXPECT_TRUE(std::filesystem::remove_all(DECOMPRESSED_FILE2_PATH));
}

TEST(ArchiveHelperTest, SuccessfulDecompressionDirectory)
{
    Utils::ArchiveHelper::decompress(COMPRESSED_DIR_PATH);

    std::ifstream inputFile(DECOMPRESSED_DIR_FILE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile1;
    getline(inputFile, decompressedFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(DECOMPRESSED_DIR_FILE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile2;
    getline(inputFile, decompressedFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile1;
    getline(inputFile, originalFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile2;
    getline(inputFile, originalFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    EXPECT_STREQ(decompressedFile1.c_str(), originalFile1.c_str());
    EXPECT_STREQ(decompressedFile2.c_str(), originalFile2.c_str());
    EXPECT_TRUE(std::filesystem::remove_all(DECOMPRESSED_DIR_PATH));
}

TEST(ArchiveHelperTest, SuccessfulDecompressionDirectoryCustomTargetPath)
{
    const bool stop = false;
    Utils::ArchiveHelper::decompress(COMPRESSED_DIR_PATH, stop, OUTPUT_DIR_PATH.string());

    std::ifstream inputFile(DECOMPRESSED_OUTPUT_DIR_FILE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile1;
    getline(inputFile, decompressedFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(DECOMPRESSED_OUTPUT_DIR_FILE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile2;
    getline(inputFile, decompressedFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile1;
    getline(inputFile, originalFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile2;
    getline(inputFile, originalFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    EXPECT_STREQ(decompressedFile1.c_str(), originalFile1.c_str());
    EXPECT_STREQ(decompressedFile2.c_str(), originalFile2.c_str());
    EXPECT_TRUE(std::filesystem::remove_all(OUTPUT_DIR_PATH));
}

TEST(ArchiveHelperTest, SuccessfulDecompressionDirectoryCustomNestedTargetPaths)
{
    const bool stop = false;
    Utils::ArchiveHelper::decompress(COMPRESSED_DIR_PATH, stop, OUTPUT_NESTED_DIRS_PATH.string());

    std::ifstream inputFile(DECOMPRESSED_OUTPUT_NESTED_DIRS_FILE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile1;
    getline(inputFile, decompressedFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(DECOMPRESSED_OUTPUT_NESTED_DIRS_FILE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile2;
    getline(inputFile, decompressedFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile1;
    getline(inputFile, originalFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE2_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile2;
    getline(inputFile, originalFile2);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    EXPECT_STREQ(decompressedFile1.c_str(), originalFile1.c_str());
    EXPECT_STREQ(decompressedFile2.c_str(), originalFile2.c_str());
    EXPECT_TRUE(std::filesystem::remove_all(OUTPUT_DIR_PATH));
}

TEST(ArchiveHelperTest, SuccessfulDecompressionExtractOnly)
{
    std::vector<std::string> extractOnly;
    extractOnly.emplace_back("content_dir/content_example1.json");
    const bool stop = false;
    Utils::ArchiveHelper::decompress(COMPRESSED_DIR_PATH, stop, OUTPUT_DIR_PATH.string(), extractOnly);

    std::ifstream inputFile(DECOMPRESSED_OUTPUT_DIR_FILE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string decompressedFile1;
    getline(inputFile, decompressedFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    inputFile.open(DECOMPRESSED_OUTPUT_DIR_FILE2_PATH);
    EXPECT_FALSE(inputFile.is_open());

    inputFile.open(BASE_EXAMPLE1_PATH);
    ASSERT_TRUE(inputFile.is_open());
    std::string originalFile1;
    getline(inputFile, originalFile1);
    inputFile.close();
    ASSERT_FALSE(inputFile.is_open());

    EXPECT_STREQ(decompressedFile1.c_str(), originalFile1.c_str());
    EXPECT_TRUE(std::filesystem::remove_all(OUTPUT_DIR_PATH));
}

#ifndef _WIN32
// Lowers RLIMIT_FSIZE and ignores SIGXFSZ, so a write past the limit fails with EFBIG; restores both on exit.
class FileSizeLimitGuard final
{
    rlimit m_previousLimit {};
    struct sigaction m_previousAction {};

public:
    explicit FileSizeLimitGuard(rlim_t limit)
    {
        struct sigaction ignore {};
        ignore.sa_handler = SIG_IGN;
        sigaction(SIGXFSZ, &ignore, &m_previousAction);
        getrlimit(RLIMIT_FSIZE, &m_previousLimit);
        rlimit newLimit {limit, m_previousLimit.rlim_max};
        setrlimit(RLIMIT_FSIZE, &newLimit);
    }

    ~FileSizeLimitGuard()
    {
        setrlimit(RLIMIT_FSIZE, &m_previousLimit);
        sigaction(SIGXFSZ, &m_previousAction, nullptr);
    }
};

TEST(ArchiveHelperTest, WriteFailureReportsErrnoReason)
{
    const bool stop = false;
    try
    {
        // Both extracted files are larger than 1 KiB.
        FileSizeLimitGuard guard(1024);
        rlimit current {};
        ASSERT_EQ(0, getrlimit(RLIMIT_FSIZE, &current));
        ASSERT_EQ(1024u, current.rlim_cur);
        Utils::ArchiveHelper::decompress(COMPRESSED_MULTIPLE_FILES_PATH, stop, OUTPUT_DIR_PATH.string());
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ("Error writing decompressed data: File too large", e.what());
    }
    catch (...)
    {
        FAIL() << "Expected std::runtime_error";
    }
    std::filesystem::remove_all(OUTPUT_DIR_PATH);
}
#endif
