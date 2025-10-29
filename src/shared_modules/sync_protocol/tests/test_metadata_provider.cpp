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

class MetadataProviderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Initialize provider before each test
        metadata_provider_init();
    }

    void TearDown() override
    {
        // Shutdown provider after each test
        metadata_provider_shutdown();
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
        std::strncpy(metadata.os_distribution_release, "jammy", sizeof(metadata.os_distribution_release) - 1);
        std::strncpy(metadata.os_full, "22.04 LTS", sizeof(metadata.os_full) - 1);
        std::strncpy(metadata.checksum_metadata, "abc123", sizeof(metadata.checksum_metadata) - 1);
        metadata.global_version = 1000;
        metadata.groups = nullptr;
        metadata.groups_count = 0;
        return metadata;
    }
};

// Test initialization
TEST_F(MetadataProviderTest, InitializeProvider)
{
    // Should succeed (already initialized in SetUp)
    EXPECT_EQ(metadata_provider_init(), 0);
}

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
    EXPECT_STREQ(retrieved.os_distribution_release, "jammy");
    EXPECT_STREQ(retrieved.os_full, "22.04 LTS");
    EXPECT_STREQ(retrieved.checksum_metadata, "abc123");
    EXPECT_EQ(retrieved.global_version, 1000);
    EXPECT_EQ(retrieved.groups_count, 0);
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
    metadata.groups = new char*[3];
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

    EXPECT_EQ(retrieved.groups_count, 3);
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
    metadata2.global_version = 2000;

    ASSERT_EQ(metadata_provider_update(&metadata2), 0);

    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);

    // Should have the updated values
    EXPECT_STREQ(retrieved.agent_id, "002");
    EXPECT_STREQ(retrieved.hostname, "updated_host");
    EXPECT_EQ(retrieved.global_version, 2000);
}

// Test free metadata with groups
TEST_F(MetadataProviderTest, FreeMetadataWithGroups)
{
    agent_metadata_t metadata{};
    metadata.groups = new char*[2];
    metadata.groups_count = 2;
    metadata.groups[0] = new char[10];
    metadata.groups[1] = new char[10];
    strcpy(metadata.groups[0], "group1");
    strcpy(metadata.groups[1], "group2");

    // Should not crash
    metadata_provider_free_metadata(&metadata);

    EXPECT_EQ(metadata.groups, nullptr);
    EXPECT_EQ(metadata.groups_count, 0);
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

// Test callback registration
TEST_F(MetadataProviderTest, RegisterCallback)
{
    bool callback_called = false;

    auto callback = [](const agent_metadata_t* metadata, void* user_data) {
        bool* called = static_cast<bool*>(user_data);
        *called = true;
    };

    int callback_id = metadata_provider_register_callback(callback, &callback_called);
    EXPECT_GE(callback_id, 0);

    agent_metadata_t metadata = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    EXPECT_TRUE(callback_called);

    // Clean up
    EXPECT_EQ(metadata_provider_unregister_callback(callback_id), 0);
}

// Test callback with NULL function pointer
TEST_F(MetadataProviderTest, RegisterNullCallback)
{
    EXPECT_EQ(metadata_provider_register_callback(nullptr, nullptr), -1);
}

// Test unregister callback
TEST_F(MetadataProviderTest, UnregisterCallback)
{
    auto callback = [](const agent_metadata_t* metadata, void* user_data) {};

    int callback_id = metadata_provider_register_callback(callback, nullptr);
    ASSERT_GE(callback_id, 0);

    EXPECT_EQ(metadata_provider_unregister_callback(callback_id), 0);

    // Unregistering again should fail
    EXPECT_EQ(metadata_provider_unregister_callback(callback_id), -1);
}

// Test unregister invalid callback ID
TEST_F(MetadataProviderTest, UnregisterInvalidCallbackId)
{
    EXPECT_EQ(metadata_provider_unregister_callback(99999), -1);
}

// Test multiple callbacks
TEST_F(MetadataProviderTest, MultipleCallbacks)
{
    int callback1_count = 0;
    int callback2_count = 0;

    auto callback1 = [](const agent_metadata_t* metadata, void* user_data) {
        int* count = static_cast<int*>(user_data);
        (*count)++;
    };

    auto callback2 = [](const agent_metadata_t* metadata, void* user_data) {
        int* count = static_cast<int*>(user_data);
        (*count)++;
    };

    int id1 = metadata_provider_register_callback(callback1, &callback1_count);
    int id2 = metadata_provider_register_callback(callback2, &callback2_count);

    ASSERT_GE(id1, 0);
    ASSERT_GE(id2, 0);
    ASSERT_NE(id1, id2);

    agent_metadata_t metadata = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    EXPECT_EQ(callback1_count, 1);
    EXPECT_EQ(callback2_count, 1);

    // Clean up
    EXPECT_EQ(metadata_provider_unregister_callback(id1), 0);
    EXPECT_EQ(metadata_provider_unregister_callback(id2), 0);
}

// Test callback receives correct metadata
TEST_F(MetadataProviderTest, CallbackReceivesCorrectMetadata)
{
    std::string received_agent_id;

    auto callback = [](const agent_metadata_t* metadata, void* user_data) {
        std::string* id = static_cast<std::string*>(user_data);
        *id = metadata->agent_id;
    };

    int callback_id = metadata_provider_register_callback(callback, &received_agent_id);
    ASSERT_GE(callback_id, 0);

    agent_metadata_t metadata = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    EXPECT_EQ(received_agent_id, "001");

    // Clean up
    EXPECT_EQ(metadata_provider_unregister_callback(callback_id), 0);
}

// Test shutdown clears state
TEST_F(MetadataProviderTest, ShutdownClearsState)
{
    agent_metadata_t metadata = createSampleMetadata();
    ASSERT_EQ(metadata_provider_update(&metadata), 0);

    metadata_provider_shutdown();

    agent_metadata_t retrieved{};
    // After shutdown, get should fail or require re-init
    EXPECT_EQ(metadata_provider_get(&retrieved), -1);
}

// Test thread safety - concurrent updates
TEST_F(MetadataProviderTest, ThreadSafetyConcurrentUpdates)
{
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&, i]() {
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
        threads.emplace_back([&]() {
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

    EXPECT_EQ(std::string(retrieved.hostname).length(), 250);
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
    metadata1.groups = new char*[2];
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
    metadata2.groups = new char*[3];
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

    EXPECT_EQ(retrieved.groups_count, 3);
    EXPECT_STREQ(retrieved.groups[0], "groupA");
    EXPECT_STREQ(retrieved.groups[1], "groupB");
    EXPECT_STREQ(retrieved.groups[2], "groupC");

    metadata_provider_free_metadata(&retrieved);
}
