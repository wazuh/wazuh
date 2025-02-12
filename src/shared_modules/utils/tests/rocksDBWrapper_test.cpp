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
#include <fstream>

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
 * @brief Tests the deleteAll function with column family
 */
TEST_F(RocksDBWrapperTest, TestDeleteAllColumnFamily)
{
    db_wrapper->createColumn("column_A");
    db_wrapper->put("key6", "value6", "column_A");
    db_wrapper->put("key7", "value7", "column_A");
    EXPECT_NO_THROW(db_wrapper->deleteAll());
    std::string value {};
    EXPECT_FALSE(db_wrapper->get("key6", value, "column_A")); // The key should have been deleted
    EXPECT_FALSE(db_wrapper->get("key7", value, "column_A")); // The key should have been deleted
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
 * @brief Tests the deleteAll function with concurrent threads
 */
TEST_F(RocksDBWrapperTest, MultiThreadTest)
{
    constexpr auto COLUMN_NAME_A {"column_A"};
    constexpr auto KEY_A {"key_A"};
    constexpr auto VALUE_A {"value_A"};

    const int MAX_ELEMENTS {100};

    if (!db_wrapper->columnExists(COLUMN_NAME_A))
    {
        db_wrapper->createColumn(COLUMN_NAME_A);
    }

    std::thread switcher(
        [&]()
        {
            for (int i = 0; i < MAX_ELEMENTS; ++i)
            {
                std::string value;
                if (db_wrapper->get(KEY_A, value, COLUMN_NAME_A))
                {
                    db_wrapper->delete_(KEY_A, COLUMN_NAME_A);
                }
                else
                {
                    db_wrapper->put(KEY_A, VALUE_A, COLUMN_NAME_A);
                }
            }
        });

    std::thread pruner(
        [&]()
        {
            for (int i = 0; i < MAX_ELEMENTS; ++i)
            {
                db_wrapper->deleteAll(COLUMN_NAME_A);
            }
        });

    switcher.join();
    pruner.join();
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
    const auto databaseFolder {OUTPUT_FOLDER / "folder1" / "folder2" / "test_db"};
    EXPECT_NO_THROW(std::make_unique<Utils::RocksDBWrapper>(databaseFolder));
}

/**
 * @brief Tests the creation of one column.
 *
 */
TEST_F(RocksDBWrapperTest, CreateColumn)
{
    constexpr auto COLUMN_NAME {"column_A"};

    EXPECT_NO_THROW(db_wrapper->createColumn(COLUMN_NAME));
}

/**
 * @brief Tests the creation of one column twice.
 *
 */
TEST_F(RocksDBWrapperTest, CreateColumnTwiceThrows)
{
    constexpr auto COLUMN_NAME {"column_A"};

    db_wrapper->createColumn(COLUMN_NAME);
    EXPECT_THROW(db_wrapper->createColumn(COLUMN_NAME), std::runtime_error);
}

/**
 * @brief Tests the column existence for a column that does exist.
 *
 */
TEST_F(RocksDBWrapperTest, ColumnExistPositive)
{
    constexpr auto COLUMN_NAME {"column_A"};

    db_wrapper->createColumn(COLUMN_NAME);
    EXPECT_TRUE(db_wrapper->columnExists(COLUMN_NAME));
}

/**
 * @brief Tests the column load when there are already created columns.
 *
 */
TEST_F(RocksDBWrapperTest, ColumnsSetup)
{
    constexpr auto COLUMN_NAME_A {"column_A"};
    constexpr auto COLUMN_NAME_B {"column_B"};
    constexpr auto KEY_A {"key_A"};
    constexpr auto VALUE_A {"value_A"};
    constexpr auto KEY_B {"key_B"};
    constexpr auto VALUE_B {"value_B"};

    db_wrapper->createColumn(COLUMN_NAME_A);
    db_wrapper->createColumn(COLUMN_NAME_B);
    db_wrapper->put(KEY_A, VALUE_A, COLUMN_NAME_A);
    db_wrapper->put(KEY_B, VALUE_B, COLUMN_NAME_B);

    // Reset wrapper. This will call the destructor and then the constructor again.
    db_wrapper.reset();
    ASSERT_NO_THROW({ db_wrapper = std::make_unique<Utils::RocksDBWrapper>(m_databaseFolder); });

    EXPECT_TRUE(db_wrapper->columnExists(COLUMN_NAME_A));
    EXPECT_TRUE(db_wrapper->columnExists(COLUMN_NAME_B));

    std::string readValue;
    EXPECT_TRUE(db_wrapper->get(KEY_A, readValue, COLUMN_NAME_A));
    EXPECT_TRUE(db_wrapper->get(KEY_B, readValue, COLUMN_NAME_B));
}

/**
 * @brief Tests the column existence for a column that doesn't exist.
 *
 */
TEST_F(RocksDBWrapperTest, ColumnExistNegative)
{
    constexpr auto COLUMN_NAME {"column_A"};

    EXPECT_FALSE(db_wrapper->columnExists(COLUMN_NAME));
}

/**
 * @brief Tests the column existence for a empty column name.
 *
 */
TEST_F(RocksDBWrapperTest, ColumnExistEmptyThrows)
{
    constexpr auto COLUMN_NAME {""};

    EXPECT_NO_THROW(db_wrapper->columnExists(COLUMN_NAME));
}

/**
 * @brief Tests the creation of various columns.
 *
 */
TEST_F(RocksDBWrapperTest, CreateMultipleColumns)
{
    constexpr auto COLUMN_NAME_A {"column_A"};
    constexpr auto COLUMN_NAME_B {"column_B"};
    constexpr auto COLUMN_NAME_C {"column_C"};

    EXPECT_NO_THROW(db_wrapper->createColumn(COLUMN_NAME_C));
}

/**
 * @brief Tests the creation of a column with empty name.
 *
 */
TEST_F(RocksDBWrapperTest, CreateColumnEmptyNameThrows)
{
    constexpr auto COLUMN_NAME {""};
    EXPECT_NO_THROW(db_wrapper->createColumn(COLUMN_NAME));
}

/**
 * @brief Test put data into a created column.
 *
 */
TEST_F(RocksDBWrapperTest, PutIntoColumn)
{
    constexpr auto COLUMN_NAME {"column_A"};
    constexpr auto KEY {"key_A"};
    constexpr auto VALUE {"value_A"};

    db_wrapper->createColumn(COLUMN_NAME);

    EXPECT_NO_THROW(db_wrapper->put(KEY, VALUE, COLUMN_NAME));
}

/**
 * @brief Test put data into an inexistent column.
 *
 */
TEST_F(RocksDBWrapperTest, PutIntoInexistentColumnThrows)
{
    constexpr auto COLUMN_NAME {"column_A"};
    constexpr auto KEY {"key_A"};
    constexpr auto VALUE {"value_A"};

    EXPECT_THROW(db_wrapper->put(KEY, VALUE, COLUMN_NAME), std::runtime_error);
}

/**
 * @brief Test get data into an inexistent column.
 *
 */
TEST_F(RocksDBWrapperTest, GetFromInexistentColumnThrows)
{
    constexpr auto COLUMN_NAME {"column_A"};
    constexpr auto KEY {"key_A"};
    std::string readValue;

    EXPECT_THROW(db_wrapper->get(KEY, readValue, COLUMN_NAME), std::runtime_error);
}

/**
 * @brief Test put and get data from a created column.
 *
 */
TEST_F(RocksDBWrapperTest, PutAndGetFromColumn)
{
    constexpr auto COLUMN_NAME {"column_A"};
    constexpr auto KEY {"key_A"};
    constexpr auto VALUE {"value_A"};
    std::string readValue;

    db_wrapper->createColumn(COLUMN_NAME);

    ASSERT_NO_THROW(db_wrapper->put(KEY, VALUE, COLUMN_NAME));
    ASSERT_TRUE(db_wrapper->get(KEY, readValue, COLUMN_NAME));
    EXPECT_EQ(readValue, VALUE);
}

/**
 * @brief Test put and get data from various created columns.
 *
 */
TEST_F(RocksDBWrapperTest, PutAndGetFromMultipleColumns)
{
    constexpr auto COLUMN_NAME_A {"column_A"};
    constexpr auto KEY_A {"key_A"};
    constexpr auto VALUE_A {"value_A"};
    constexpr auto COLUMN_NAME_B {"column_B"};
    constexpr auto KEY_B {"key_B"};
    constexpr auto VALUE_B {"value_B"};
    std::string readValue;

    db_wrapper->createColumn(COLUMN_NAME_A);
    db_wrapper->createColumn(COLUMN_NAME_B);

    ASSERT_NO_THROW(db_wrapper->put(KEY_A, VALUE_A, COLUMN_NAME_A));
    ASSERT_NO_THROW(db_wrapper->put(KEY_B, VALUE_B, COLUMN_NAME_B));

    ASSERT_TRUE(db_wrapper->get(KEY_A, readValue, COLUMN_NAME_A));
    EXPECT_EQ(readValue, VALUE_A);

    ASSERT_TRUE(db_wrapper->get(KEY_B, readValue, COLUMN_NAME_B));
    EXPECT_EQ(readValue, VALUE_B);
}

/**
 * @brief Test put and get last key value from a created column.
 *
 */
TEST_F(RocksDBWrapperTest, PutAndGetLastKeyValueFromColumn)
{
    constexpr auto COLUMN_NAME {"column_A"};
    constexpr auto KEY_A {"key_A"};
    constexpr auto VALUE_A {"value_A"};
    constexpr auto KEY_B {"key_B"};
    constexpr auto VALUE_B {"value_B"};

    db_wrapper->createColumn(COLUMN_NAME);
    db_wrapper->put(KEY_A, VALUE_A, COLUMN_NAME);
    db_wrapper->put(KEY_B, VALUE_B, COLUMN_NAME);

    const auto lastPair {db_wrapper->getLastKeyValue(COLUMN_NAME)};
    EXPECT_EQ(lastPair.first, KEY_B);
    EXPECT_EQ(lastPair.second, VALUE_B);
}

TEST_F(RocksDBWrapperTest, GetAllColumnFamiliesTest)
{
    constexpr auto COLUMN_NAME_A {"column_A"};
    constexpr auto COLUMN_NAME_B {"column_B"};
    constexpr auto COLUMN_NAME_C {"column_C"};

    db_wrapper->createColumn(COLUMN_NAME_A);
    db_wrapper->createColumn(COLUMN_NAME_B);
    db_wrapper->createColumn(COLUMN_NAME_C);

    const auto columnFamilies {db_wrapper->getAllColumns()};
    EXPECT_EQ(columnFamilies.size(), 4);
    EXPECT_EQ(columnFamilies[0], rocksdb::kDefaultColumnFamilyName);
    EXPECT_EQ(columnFamilies[1], COLUMN_NAME_A);
    EXPECT_EQ(columnFamilies[2], COLUMN_NAME_B);
    EXPECT_EQ(columnFamilies[3], COLUMN_NAME_C);
}

TEST_F(RocksDBWrapperTest, CorruptAndRepairTest)
{
    db_wrapper.reset();

    db_wrapper = std::make_unique<Utils::RocksDBWrapper>(m_databaseFolder, false);

    for (int i = 0; i < 10; i++)
    {
        db_wrapper->put("key" + std::to_string(i), "value" + std::to_string(i));
    }

    db_wrapper.reset();

    bool corrupted {false};
    for (const auto& entry : std::filesystem::directory_iterator(m_databaseFolder))
    {
        if (entry.path().extension() == ".sst")
        {
            std::filesystem::remove(entry.path());
            corrupted = true;
            break;
        }
    }
    EXPECT_TRUE(corrupted);

    EXPECT_ANY_THROW({ db_wrapper = std::make_unique<Utils::RocksDBWrapper>(m_databaseFolder, false, false); });
    EXPECT_NO_THROW({ db_wrapper = std::make_unique<Utils::RocksDBWrapper>(m_databaseFolder, false, true); });
}
