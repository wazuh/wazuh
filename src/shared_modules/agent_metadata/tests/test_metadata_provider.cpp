/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "metadata_provider.h"
#include <cstring>
#include <thread>
#include <atomic>
#include <vector>

#ifndef _WIN32
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <climits>
#endif

class MetadataProviderTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Reset provider before each test to ensure test isolation
            metadata_provider_reset();
        }

        void TearDown() override
        {
            // Reset provider after each test
            metadata_provider_reset();
        }

        // Helper to create sample metadata
        agent_metadata_t createSampleMetadata()
        {
            agent_metadata_t metadata{};
            std::strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);
            std::strncpy(metadata.agent_name, "test_agent", sizeof(metadata.agent_name) - 1);
            std::strncpy(metadata.agent_version, "4.5.0", sizeof(metadata.agent_version) - 1);
            std::strncpy(metadata.architecture, "x86_64", sizeof(metadata.architecture) - 1);
            std::strncpy(metadata.hostname, "test_host", sizeof(metadata.hostname) - 1);
            std::strncpy(metadata.os_name, "Ubuntu", sizeof(metadata.os_name) - 1);
            std::strncpy(metadata.os_type, "linux", sizeof(metadata.os_type) - 1);
            std::strncpy(metadata.os_version, "22.04", sizeof(metadata.os_version) - 1);
            metadata.groups = nullptr;
            metadata.groups_count = 0;
            return metadata;
        }
};

// Test update with valid metadata
TEST_F(MetadataProviderTest, UpdateValidMetadata)
{
    agent_metadata_t metadata = createSampleMetadata();
    EXPECT_EQ(metadata_provider_update(&metadata), 0);
}

// Test update with NULL pointer
TEST_F(MetadataProviderTest, UpdateNullMetadata)
{
    EXPECT_EQ(metadata_provider_update(nullptr), -1);
}

// Test get metadata after update
TEST_F(MetadataProviderTest, GetMetadataAfterUpdate)
{
    agent_metadata_t metadata = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);

    EXPECT_STREQ(retrieved.agent_id, "001");
    EXPECT_STREQ(retrieved.agent_name, "test_agent");
    EXPECT_STREQ(retrieved.agent_version, "4.5.0");
    EXPECT_STREQ(retrieved.architecture, "x86_64");
    EXPECT_STREQ(retrieved.hostname, "test_host");
    EXPECT_STREQ(retrieved.os_name, "Ubuntu");
    EXPECT_STREQ(retrieved.os_type, "linux");
    EXPECT_STREQ(retrieved.os_version, "22.04");
    EXPECT_EQ(retrieved.groups_count, 0u);
    EXPECT_EQ(retrieved.groups, nullptr);
}

// Test get metadata with NULL pointer
TEST_F(MetadataProviderTest, GetMetadataNullPointer)
{
    EXPECT_EQ(metadata_provider_get(nullptr), -1);
}

// Test get metadata before any update
TEST_F(MetadataProviderTest, GetMetadataBeforeUpdate)
{
    agent_metadata_t retrieved{};
    EXPECT_EQ(metadata_provider_get(&retrieved), -1);
}

// Test metadata with groups
TEST_F(MetadataProviderTest, UpdateMetadataWithGroups)
{
    agent_metadata_t metadata = createSampleMetadata();

    // Add groups
    const char* group_names[] = {"group1", "group2", "group3"};
    metadata.groups = new char* [3];
    metadata.groups_count = 3;

    for (size_t i = 0; i < 3; ++i)
    {
        metadata.groups[i] = new char[strlen(group_names[i]) + 1];
        strcpy(metadata.groups[i], group_names[i]);
    }

    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    // Clean up input metadata
    for (size_t i = 0; i < metadata.groups_count; ++i)
    {
        delete[] metadata.groups[i];
    }

    delete[] metadata.groups;

    // Retrieve and verify
    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);

    EXPECT_EQ(retrieved.groups_count, 3u);
    ASSERT_NE(retrieved.groups, nullptr);
    EXPECT_STREQ(retrieved.groups[0], "group1");
    EXPECT_STREQ(retrieved.groups[1], "group2");
    EXPECT_STREQ(retrieved.groups[2], "group3");

    // Clean up retrieved metadata
    metadata_provider_free_metadata(&retrieved);
}

// Test multiple updates (verify replacement)
TEST_F(MetadataProviderTest, MultipleUpdates)
{
    agent_metadata_t metadata1 = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata1), 0);

    agent_metadata_t metadata2 = createSampleMetadata();
    std::strncpy(metadata2.agent_id, "002", sizeof(metadata2.agent_id) - 1);
    std::strncpy(metadata2.hostname, "updated_host", sizeof(metadata2.hostname) - 1);

    ASSERT_EQ(metadata_provider_update(&metadata2), 0);

    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);

    // Should have the updated values
    EXPECT_STREQ(retrieved.agent_id, "002");
    EXPECT_STREQ(retrieved.hostname, "updated_host");
}

// Test free metadata with groups
TEST_F(MetadataProviderTest, FreeMetadataWithGroups)
{
    agent_metadata_t metadata{};
    metadata.groups = new char* [2];
    metadata.groups_count = 2;
    metadata.groups[0] = new char[10];
    metadata.groups[1] = new char[10];
    strcpy(metadata.groups[0], "group1");
    strcpy(metadata.groups[1], "group2");

    // Should not crash
    metadata_provider_free_metadata(&metadata);

    EXPECT_EQ(metadata.groups, nullptr);
    EXPECT_EQ(metadata.groups_count, 0u);
}

// Test free metadata with NULL pointer
TEST_F(MetadataProviderTest, FreeMetadataNullPointer)
{
    // Should not crash
    metadata_provider_free_metadata(nullptr);
}

// Test free metadata without groups
TEST_F(MetadataProviderTest, FreeMetadataWithoutGroups)
{
    agent_metadata_t metadata{};
    metadata.groups = nullptr;
    metadata.groups_count = 0;

    // Should not crash
    metadata_provider_free_metadata(&metadata);
}

// Test thread safety - concurrent updates
TEST_F(MetadataProviderTest, ThreadSafetyConcurrentUpdates)
{
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&, i]()
        {
            agent_metadata_t metadata = createSampleMetadata();
            std::string agent_id = "agent_" + std::to_string(i);
            std::strncpy(metadata.agent_id, agent_id.c_str(), sizeof(metadata.agent_id) - 1);

            if (metadata_provider_update(&metadata) == 0)
            {
                success_count++;
            }
        });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(success_count, num_threads);

    // Should be able to retrieve some metadata
    agent_metadata_t retrieved{};
    EXPECT_EQ(metadata_provider_get(&retrieved), 0);
}

// Test thread safety - concurrent reads
TEST_F(MetadataProviderTest, ThreadSafetyConcurrentReads)
{
    agent_metadata_t metadata = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&]()
        {
            agent_metadata_t retrieved{};

            if (metadata_provider_get(&retrieved) == 0)
            {
                success_count++;
                metadata_provider_free_metadata(&retrieved);
            }
        });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(success_count, num_threads);
}

// Test large string values
TEST_F(MetadataProviderTest, LargeStringValues)
{
    agent_metadata_t metadata = createSampleMetadata();

    // Fill with large strings (but within bounds)
    std::string large_string(250, 'X');
    std::strncpy(metadata.hostname, large_string.c_str(), sizeof(metadata.hostname) - 1);

    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);

    EXPECT_EQ(std::string(retrieved.hostname).length(), 250u);
}

// Test empty string values
TEST_F(MetadataProviderTest, EmptyStringValues)
{
    agent_metadata_t metadata = createSampleMetadata();

    // Set empty strings
    metadata.agent_id[0] = '\0';
    metadata.hostname[0] = '\0';

    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);

    EXPECT_STREQ(retrieved.agent_id, "");
    EXPECT_STREQ(retrieved.hostname, "");
}

// Test groups replacement on update
TEST_F(MetadataProviderTest, GroupsReplacementOnUpdate)
{
    // First update with 2 groups
    agent_metadata_t metadata1 = createSampleMetadata();
    metadata1.groups = new char* [2];
    metadata1.groups_count = 2;
    metadata1.groups[0] = new char[10];
    metadata1.groups[1] = new char[10];
    strcpy(metadata1.groups[0], "group1");
    strcpy(metadata1.groups[1], "group2");

    ASSERT_EQ(metadata_provider_update(&metadata1), 0);

    // Clean up first metadata
    for (size_t i = 0; i < metadata1.groups_count; ++i)
    {
        delete[] metadata1.groups[i];
    }

    delete[] metadata1.groups;

    // Second update with 3 different groups
    agent_metadata_t metadata2 = createSampleMetadata();
    metadata2.groups = new char* [3];
    metadata2.groups_count = 3;
    metadata2.groups[0] = new char[10];
    metadata2.groups[1] = new char[10];
    metadata2.groups[2] = new char[10];
    strcpy(metadata2.groups[0], "groupA");
    strcpy(metadata2.groups[1], "groupB");
    strcpy(metadata2.groups[2], "groupC");

    ASSERT_EQ(metadata_provider_update(&metadata2), 0);

    // Clean up second metadata
    for (size_t i = 0; i < metadata2.groups_count; ++i)
    {
        delete[] metadata2.groups[i];
    }

    delete[] metadata2.groups;

    // Verify the new groups replaced the old ones
    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);

    EXPECT_EQ(retrieved.groups_count, 3u);
    EXPECT_STREQ(retrieved.groups[0], "groupA");
    EXPECT_STREQ(retrieved.groups[1], "groupB");
    EXPECT_STREQ(retrieved.groups[2], "groupC");

    metadata_provider_free_metadata(&retrieved);
}

#ifndef _WIN32

extern const char* g_testBinaryPath;

// #38766: a provider teardown registered after agentd's atexit(w_https_client_stop) runs
// before it, so the drain that follows reads a dangling pointer and the process is
// killed instead of exiting. Re-executes this binary because the fixture's SetUp() has
// already built the singleton here; see runAtexitChild() in main.cpp.
TEST_F(MetadataProviderTest, ReadFromAtexitAfterProviderTeardownDoesNotCrash)
{
    ASSERT_NE(g_testBinaryPath, nullptr);

    const pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        setenv("WAZUH_METADATA_ATEXIT_CHILD", "1", 1);
        execl(g_testBinaryPath, g_testBinaryPath, static_cast<char*>(nullptr));
        _exit(4); // Only reached if exec failed.
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);

    ASSERT_FALSE(WIFSIGNALED(status)) << "child died with signal " << WTERMSIG(status)
                                      << ": the provider was torn down while a later exit handler still read it";
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

// #38813: the shm fd was left open for the provider's whole lifetime, with no O_CLOEXEC,
// so it leaked into every child process spawned afterward (e.g. SCA's command rules via
// wm_exec()) -- exactly what an enforcing SELinux policy denies once such a child
// transitions into a restricted domain, even though the child never touches the file.
// mmap() doesn't need the fd once it succeeds, so the fix closes it right away instead of
// relying on O_CLOEXEC alone; this asserts that steady state directly.
//
// Linux-only: relies on /proc/self/fd, which macOS (no procfs) doesn't have. SELinux is
// Linux-only too, so the regression this guards against can't occur on macOS anyway.
#ifdef __linux__
TEST_F(MetadataProviderTest, MetadataFdNotLeftOpenAfterConstruction)
{
    agent_metadata_t metadata = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata), 0); // triggers singleton construction

    DIR* fdDir = opendir("/proc/self/fd");
    ASSERT_NE(fdDir, nullptr);

    struct dirent* entry;
    char linkTarget[PATH_MAX];

    while ((entry = readdir(fdDir)) != nullptr)
    {
        std::string path = std::string("/proc/self/fd/") + entry->d_name;
        ssize_t len = readlink(path.c_str(), linkTarget, sizeof(linkTarget) - 1);

        if (len > 0)
        {
            linkTarget[len] = '\0';
            EXPECT_EQ(std::string(linkTarget).find(".wazuh_agent_metadata"), std::string::npos)
                    << "fd " << entry->d_name << " still points at the metadata shm file";
        }
    }

    closedir(fdDir);
}
#endif // __linux__

#endif
