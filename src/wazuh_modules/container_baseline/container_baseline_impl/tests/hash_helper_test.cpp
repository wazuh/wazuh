#include "hash_helper.hpp"

#include <cstdio>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

using wazuh::container_baseline::FileHashes;
using wazuh::container_baseline::HashFile;
using wazuh::container_baseline::HashSelection;

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
    ASSERT_TRUE(HashFile(path_, hashes));

    // Well-known test vectors for the 3-byte input "abc".
    EXPECT_EQ(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
    EXPECT_EQ(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT_EQ(hashes.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(HashFileTest, MissingFileFails)
{
    FileHashes hashes;
    EXPECT_FALSE(HashFile("/tmp/cbaseline_hash_test_file_does_not_exist", hashes));
}

TEST_F(HashFileTest, SelectionComputesOnlyRequestedDigests)
{
    FileHashes hashes;
    HashSelection only_sha256;
    only_sha256.md5 = false;
    only_sha256.sha1 = false;
    only_sha256.sha256 = true;

    ASSERT_TRUE(HashFile(path_, hashes, only_sha256));

    EXPECT_TRUE(hashes.md5.empty());
    EXPECT_TRUE(hashes.sha1.empty());
    EXPECT_EQ(hashes.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(HashFileTest, SelectingNothingFails)
{
    FileHashes hashes;
    HashSelection none;
    none.md5 = none.sha1 = none.sha256 = false;

    EXPECT_FALSE(HashFile(path_, hashes, none));
    EXPECT_TRUE(hashes.sha256.empty());
}

TEST_F(HashFileTest, DigestAlwaysCoversTheWholeFile)
{
    // Regression guard for the removed byte-cutoff behaviour: HashFile must
    // never produce a digest of a file PREFIX. A prefix digest matches no other
    // reader's value and collides for any two files sharing that prefix, so
    // callers that need to bound I/O must skip the file (leaving the hash
    // fields empty) rather than ask for a partial digest.
    {
        std::ofstream f(path_, std::ios::binary);
        f << "abcdefghijklmnopqrstuvwxyz";
    }

    FileHashes hashes;
    ASSERT_TRUE(HashFile(path_, hashes));

    // sha256("abcdefghijklmnopqrstuvwxyz"), not sha256 of any prefix.
    EXPECT_EQ(hashes.sha256, "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
    EXPECT_NE(hashes.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
