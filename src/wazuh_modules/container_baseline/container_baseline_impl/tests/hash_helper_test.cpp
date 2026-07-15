#include "hash_helper.hpp"

#include <cstdio>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

using wazuh::container_baseline::FileHashes;
using wazuh::container_baseline::HashFile;

namespace {

class HashFileTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        path_ = "/tmp/cbaseline_hash_test_file";
        std::ofstream f(path_, std::ios::binary);
        f << "abc";
    }

    void TearDown() override { std::remove(path_.c_str()); }

    std::string path_;
};

} // namespace

TEST_F(HashFileTest, KnownVectorAbc)
{
    FileHashes hashes;
    ASSERT_TRUE(HashFile(path_, 0, hashes));

    // Well-known test vectors for the 3-byte input "abc".
    EXPECT_EQ(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
    EXPECT_EQ(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT_EQ(hashes.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(HashFileTest, MissingFileFails)
{
    FileHashes hashes;
    EXPECT_FALSE(HashFile("/tmp/cbaseline_hash_test_file_does_not_exist", 0, hashes));
}

TEST_F(HashFileTest, MaxBytesCutoffChangesDigest)
{
    FileHashes full;
    FileHashes truncated;
    ASSERT_TRUE(HashFile(path_, 0, full));
    ASSERT_TRUE(HashFile(path_, 1, truncated)); // only hashes "a"

    EXPECT_NE(full.sha256, truncated.sha256);
}
