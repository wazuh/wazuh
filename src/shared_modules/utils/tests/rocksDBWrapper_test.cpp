/*
 * Wazuh - Shared Modules utils tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 9, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "rocksDBWrapper_test.hpp"

/**
 * @brief Tests the put function
 */
TEST_F(RocksDBWrapperTest, TestPut)
{
    EXPECT_NO_THROW(db_wrapper->put("key1", "value1"));
}

/**
 * @brief Tests the put function with an empty key
 */
TEST_F(RocksDBWrapperTest, TestPutEmptyKey)
{
    EXPECT_THROW(db_wrapper->put("", "value1"), std::invalid_argument);
}

/**
 * @brief Tests the put function with an empty value
 */
TEST_F(RocksDBWrapperTest, TestPutEmptyValue)
{
    EXPECT_NO_THROW(db_wrapper->put("key2", ""));
}

/**
 * @brief Tests the put function with a key that already exists
 */
TEST_F(RocksDBWrapperTest, TestPutExistingKey)
{
    EXPECT_NO_THROW(db_wrapper->put("key3", "value3"));
    EXPECT_NO_THROW(db_wrapper->put("key3", "value3"));
}

/**
 * @brief Tests that the value is updated when the put function is called with an existing key
 */
TEST_F(RocksDBWrapperTest, TestPutExistingKeyUpdateValue)
{
    const std::string value3 {"value3"};
    EXPECT_NO_THROW(db_wrapper->put("key3", value3));
    std::string value {};
    db_wrapper->get("key3", value);
    EXPECT_EQ(value, value3);

    const std::string newValue {"newValue"};
    value = {};
    EXPECT_NO_THROW(db_wrapper->put("key3", newValue)); // The value should be updated
    db_wrapper->get("key3", value);
    EXPECT_EQ(value, newValue);
}

/**
 * @brief Tests the get function
 */
TEST_F(RocksDBWrapperTest, TestGet)
{
    db_wrapper->put("key2", "value2");
    std::string value {};
    EXPECT_TRUE(db_wrapper->get("key2", value));
    EXPECT_EQ(value, "value2");
}

/**
 * @brief Tests the get function with pinnable slice
 */
TEST_F(RocksDBWrapperTest, TestGetPinnableSlice)
{
    db_wrapper->put("key2", "value2");
    rocksdb::PinnableSlice value;
    EXPECT_TRUE(db_wrapper->get("key2", value));
    EXPECT_EQ(value, "value2");

    value.Reset();
    EXPECT_TRUE(value.empty());
    EXPECT_TRUE(db_wrapper->get("key2", value));
    EXPECT_EQ(value.ToString(), "value2");
}

/**
 * @brief Tests the get function with a non-existent key
 */
TEST_F(RocksDBWrapperTest, TestGetNonExistentKey)
{
    std::string value {};
    EXPECT_FALSE(db_wrapper->get("non_existent_key", value));
}

/**
 * @brief Tests the get function with an empty key
 */
TEST_F(RocksDBWrapperTest, TestGetEmptyKey)
{
    std::string value {};
    EXPECT_THROW(db_wrapper->get("", value), std::invalid_argument);
}

/**
 * @brief Tests the get function with an empty database
 */
TEST_F(RocksDBWrapperTest, TestGetEmptyDB)
{
    Utils::RocksDBWrapper new_db_wrapper("new_test.db");
    std::string value {};
    EXPECT_FALSE(new_db_wrapper.get("key1", value));
}

/**
 * @brief Tests the delete_ function
 */
TEST_F(RocksDBWrapperTest, TestDelete)
{
    db_wrapper->put("key3", "value3");
    EXPECT_NO_THROW(db_wrapper->delete_("key3"));
    std::string value {};
    EXPECT_FALSE(db_wrapper->get("key3", value)); // The key should have been deleted
}

/**
 * @brief Tests the delete_ function with a non-existent key
 */
TEST_F(RocksDBWrapperTest, TestDeleteNonExistentKey)
{
    EXPECT_NO_THROW(db_wrapper->delete_("non_existent_key"));
}

/**
 * @brief Tests the delete_ function with an empty key
 */
TEST_F(RocksDBWrapperTest, TestDeleteEmptyKey)
{
    EXPECT_THROW(db_wrapper->delete_(""), std::invalid_argument);
}

/**
 * @brief Tests the delete_ function with an empty database
 */
TEST_F(RocksDBWrapperTest, TestDeleteEmptyDB)
{
    Utils::RocksDBWrapper new_db_wrapper("new_test.db");
    EXPECT_NO_THROW(new_db_wrapper.delete_("key1"));
}

/**
 * @brief Tests the deleteAll function
 */
TEST_F(RocksDBWrapperTest, TestGetLastKeyValue)
{
    db_wrapper->put("key4", "value4");
    db_wrapper->put("key5", "value5");

    const auto [lastKey, lastValue] = db_wrapper->getLastKeyValue();
    EXPECT_EQ(lastKey, "key5");
    EXPECT_EQ(lastValue, "value5");
}

/**
 * @brief Tests the getLastKeyValue function with an empty database
 */
TEST_F(RocksDBWrapperTest, TestGetLastKeyValueEmptyDB)
{
    Utils::RocksDBWrapper new_db_wrapper("new_test.db");
    EXPECT_THROW(new_db_wrapper.getLastKeyValue(), std::runtime_error);
}

/**
 * @brief Tests the deleteAll function
 */
TEST_F(RocksDBWrapperTest, TestDeleteAll)
{
    db_wrapper->put("key6", "value6");
    db_wrapper->put("key7", "value7");
    EXPECT_NO_THROW(db_wrapper->deleteAll());
    std::string value {};
    EXPECT_FALSE(db_wrapper->get("key6", value)); // The key should have been deleted
    EXPECT_FALSE(db_wrapper->get("key7", value)); // The key should have been deleted
}

/**
 * @brief Tests the deleteAll function with an empty database
 */
TEST_F(RocksDBWrapperTest, TestDeleteAllEmptyDB)
{
    Utils::RocksDBWrapper new_db_wrapper("new_test.db");
    EXPECT_NO_THROW(db_wrapper->deleteAll());
}

/**
 * @brief Tests the range for loop
 */
TEST_F(RocksDBWrapperTest, TestRangeForLoop)
{
    constexpr auto NUM_ELEMENTS {4};
    constexpr auto NUM_ELEMENTS_ONE_MATCH {1};
    const std::array<std::pair<std::string, std::string>, NUM_ELEMENTS> elements {std::make_pair("key1", "value1"),
                                                                                  std::make_pair("key2", "value2"),
                                                                                  std::make_pair("key3", "value3"),
                                                                                  std::make_pair("key4", "value4")};
    for (const auto& [key, value] : elements)
    {
        db_wrapper->put(key, value);
    }

    auto counter {0};

    for (const auto& [key, value] : db_wrapper->seek("k"))
    {
        EXPECT_EQ(key, elements[counter].first);
        EXPECT_EQ(value, elements[counter].second);
        ++counter;
    }

    EXPECT_EQ(counter, NUM_ELEMENTS);

    counter = 0;

    for (const auto& [key, value] : db_wrapper->seek("key2"))
    {
        EXPECT_EQ(key, elements[counter + NUM_ELEMENTS_ONE_MATCH].first);
        EXPECT_EQ(value, elements[counter + NUM_ELEMENTS_ONE_MATCH].second);
        ++counter;
    }

    EXPECT_EQ(counter, NUM_ELEMENTS_ONE_MATCH);

    counter = 0;

    for (const auto& [key, value] : db_wrapper->seek("key5"))
    {
        ++counter;
    }

    EXPECT_EQ(counter, 0);

    counter = 0;

    for (const auto& [key, value] : *db_wrapper)
    {
        EXPECT_EQ(key, elements[counter].first);
        EXPECT_EQ(value, elements[counter].second);
        ++counter;
    }

    EXPECT_EQ(counter, NUM_ELEMENTS);
}

/**
 * @brief Tests the range for loop with buffers
 */
TEST_F(RocksDBWrapperTest, TestRangeForLoopWithBinaryBuffers)
{
    constexpr auto NUM_ELEMENTS {4};
    constexpr auto NUM_ELEMENTS_ONE_MATCH {1};
    constexpr char BINARY_BUFFER[] {0x01, 0x02, 0x00, 0x04, 0x05};
    constexpr auto BINARY_BUFFER_SIZE {sizeof(BINARY_BUFFER)};
    const std::array<std::pair<std::string, const char*>, NUM_ELEMENTS> elements {
        std::make_pair("key1", BINARY_BUFFER),
        std::make_pair("key2", BINARY_BUFFER),
        std::make_pair("key3", BINARY_BUFFER),
        std::make_pair("key4", BINARY_BUFFER)};
    for (const auto& [key, value] : elements)
    {
        db_wrapper->put(key, {value, BINARY_BUFFER_SIZE});
    }

    auto counter {0};

    for (const auto& [key, value] : db_wrapper->seek("k"))
    {
        EXPECT_EQ(key, elements[counter].first);
        EXPECT_EQ(value.size(), BINARY_BUFFER_SIZE);
        EXPECT_EQ(std::memcmp(value.data(), elements[counter].second, BINARY_BUFFER_SIZE), 0);
        ++counter;
    }

    EXPECT_EQ(counter, NUM_ELEMENTS);

    counter = 0;

    for (const auto& [key, value] : db_wrapper->seek("key2"))
    {
        EXPECT_EQ(key, elements[counter + NUM_ELEMENTS_ONE_MATCH].first);
        EXPECT_EQ(value.size(), BINARY_BUFFER_SIZE);
        EXPECT_EQ(std::memcmp(value.data(), elements[counter + NUM_ELEMENTS_ONE_MATCH].second, BINARY_BUFFER_SIZE), 0);
        ++counter;
    }

    EXPECT_EQ(counter, NUM_ELEMENTS_ONE_MATCH);

    counter = 0;

    for (const auto& [key, value] : db_wrapper->seek("key5"))
    {
        ++counter;
    }

    EXPECT_EQ(counter, 0);

    counter = 0;

    for (const auto& [key, value] : *db_wrapper)
    {
        EXPECT_EQ(key, elements[counter].first);
        EXPECT_EQ(value.size(), BINARY_BUFFER_SIZE);
        EXPECT_EQ(std::memcmp(value.data(), elements[counter].second, BINARY_BUFFER_SIZE), 0);
        ++counter;
    }

    EXPECT_EQ(counter, NUM_ELEMENTS);
}

/**
 * @brief Tests create folders and directories recursively based
 * on the provided path argument when initializing RocksDB instances
 */
TEST_F(RocksDBWrapperTest, TestCreateFolderRecursively)
{
    const std::string DATABASE_NAME {"folder1/folder2/test.db"};

    std::optional<Utils::RocksDBWrapper> db_wrapper;

    EXPECT_NO_THROW({ db_wrapper = Utils::RocksDBWrapper(DATABASE_NAME); });

    db_wrapper->deleteAll();
    std::filesystem::remove_all(DATABASE_NAME);
}

TEST_F(RocksDBWrapperTest, TestBatchDelete)
{
    // Insert
    std::vector<std::pair<std::string, rocksdb::Slice>> keyValueVector {
        {std::make_pair("key1", rocksdb::Slice("value1"))},
        {std::make_pair("key2", rocksdb::Slice("value2"))},
        {std::make_pair("key3", rocksdb::Slice("value3"))}};

    EXPECT_NO_THROW(db_wrapper->put(keyValueVector));

    // Get
    rocksdb::PinnableSlice value;
    EXPECT_TRUE(db_wrapper->get("key1", value));
    EXPECT_EQ(value, "value1");

    EXPECT_TRUE(db_wrapper->get("key2", value));
    EXPECT_EQ(value, "value2");

    EXPECT_TRUE(db_wrapper->get("key3", value));
    EXPECT_EQ(value, "value3");

    // Remove
    std::vector<std::string> keyVector {"key1", "key2", "key3"};
    db_wrapper->delete_(keyVector);

    EXPECT_FALSE(db_wrapper->get("key1", value));
    EXPECT_FALSE(db_wrapper->get("key2", value));
    EXPECT_FALSE(db_wrapper->get("key3", value));
}

TEST_F(RocksDBWrapperTest, TestColumFamilyDB)
{
    auto cfDb = std::make_shared<Utils::RocksDBWrapper>(DATABASE_CF_NAME, std::vector<std::string>({"cf1", "cf2"}));

    // Insert
    cfDb->put(ROCKSDB_DEFAULT_COLUMN, "key0", rocksdb::Slice("value0"));
    cfDb->put("cf1", "key1", rocksdb::Slice("value1"));
    cfDb->put( "cf2", "key2", rocksdb::Slice("value2"));

    // Get
    rocksdb::PinnableSlice value;

    EXPECT_TRUE(cfDb->get(ROCKSDB_DEFAULT_COLUMN, "key0", value));
    EXPECT_EQ(value, "value0");

    EXPECT_TRUE(cfDb->get("cf1", "key1", value));
    EXPECT_EQ(value, "value1");

    EXPECT_TRUE(cfDb->get("cf2", "key2", value));
    EXPECT_EQ(value, "value2");

    // Remove
    EXPECT_NO_THROW(cfDb->delete_(ROCKSDB_DEFAULT_COLUMN, "key0"));
    EXPECT_NO_THROW(cfDb->delete_("cf1", "key1"));
    EXPECT_NO_THROW(cfDb->delete_("cf2", "key2"));

    EXPECT_FALSE(cfDb->get(ROCKSDB_DEFAULT_COLUMN, "key0", value));
    EXPECT_FALSE(cfDb->get("cf1", "key1", value));
    EXPECT_FALSE(cfDb->get("cf2", "key2", value));

    // Clean
    EXPECT_NO_THROW(cfDb.reset());
    std::filesystem::remove_all(DATABASE_CF_NAME);
}

TEST_F(RocksDBWrapperTest, TestColumFamilyDBBatch)
{
    auto cfDb = std::make_shared<Utils::RocksDBWrapper>(DATABASE_CF_NAME, std::vector<std::string>({"cf1", "cf2"}));

    // Insert
    std::vector<std::tuple<std::string, std::string, rocksdb::Slice>> columnKeyValueVector {
        {std::make_tuple(ROCKSDB_DEFAULT_COLUMN, "key0", rocksdb::Slice("value0"))},
        {std::make_tuple("cf1", "key1", rocksdb::Slice("value1"))},
        {std::make_tuple("cf2", "key2", rocksdb::Slice("value2"))}};

    EXPECT_NO_THROW(cfDb->put(columnKeyValueVector));

    // Get
    rocksdb::PinnableSlice value;

    EXPECT_TRUE(cfDb->get(ROCKSDB_DEFAULT_COLUMN, "key0", value));
    EXPECT_EQ(value, "value0");

    EXPECT_TRUE(cfDb->get("cf1", "key1", value));
    EXPECT_EQ(value, "value1");

    EXPECT_TRUE(cfDb->get("cf2", "key2", value));
    EXPECT_EQ(value, "value2");

    // Remove
    std::vector<std::pair<std::string, std::string>> columnKeyVector {
        std::make_pair(ROCKSDB_DEFAULT_COLUMN, "key0"), std::make_pair("cf1", "key1"), std::make_pair("cf2", "key2")};

    cfDb->delete_(columnKeyVector);

    EXPECT_FALSE(cfDb->get(ROCKSDB_DEFAULT_COLUMN, "key0", value));
    EXPECT_FALSE(cfDb->get("cf1", "key1", value));
    EXPECT_FALSE(cfDb->get( "cf2", "key2", value));

    // Clean
    EXPECT_NO_THROW(cfDb.reset());
    std::filesystem::remove_all(DATABASE_CF_NAME);
}

TEST_F(RocksDBWrapperTest, TestColumFamilyDBSeek)
{
    auto cfDb = std::make_shared<Utils::RocksDBWrapper>(DATABASE_CF_NAME, std::vector<std::string>({"cf1", "cf2"}));

    // Insert
    std::vector<std::tuple<std::string, std::string, rocksdb::Slice>> columnKeyValueVector {
        std::make_tuple(ROCKSDB_DEFAULT_COLUMN, "key_default_0", rocksdb::Slice("value_default_0")),
        std::make_tuple(ROCKSDB_DEFAULT_COLUMN, "key_default_1", rocksdb::Slice("value_default_1")),
        std::make_tuple(ROCKSDB_DEFAULT_COLUMN, "key_default_2", rocksdb::Slice("value_default_2")),
        std::make_tuple("cf1", "key_cf1_0", rocksdb::Slice("value_cf1_0")),
        std::make_tuple("cf1", "key_cf1_1", rocksdb::Slice("value_cf1_1")),
        std::make_tuple("cf1", "key_cf1_2", rocksdb::Slice("value_cf1_2")),
        std::make_tuple("cf2", "key_cf2_0", rocksdb::Slice("value_cf2_0")),
        std::make_tuple("cf2", "key_cf2_1", rocksdb::Slice("value_cf2_1")),
        std::make_tuple("cf2", "key_cf2_2", rocksdb::Slice("value_cf2_2"))};

    EXPECT_NO_THROW(cfDb->put(columnKeyValueVector));

    // Seek default column
    std::vector<std::string> prefixArray {"default", "cf1", "cf2"};

    auto testLambda = [&](auto prefix)
    {
        auto counter {0};
        for (const auto& [key, value] : cfDb->seek(prefix, "key_" + prefix + "_"))
        {
            EXPECT_EQ(key, "key_" + prefix + "_" + std::to_string(counter));
            EXPECT_EQ(value, "value_" + prefix + "_" + std::to_string(counter));
            ++counter;
        }
        EXPECT_EQ(counter, 3);
    };

    for (const auto& prefix : prefixArray)
    {
        testLambda(prefix);
    }
}
