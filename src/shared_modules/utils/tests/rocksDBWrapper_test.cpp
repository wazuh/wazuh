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
#include <map>
#include <set>
#include <string>
#include <vector>

namespace
{
    /**
     * @brief Opens a closed database read-only and returns the compression names of its SST files, per column.
     *
     * @param path Database path.
     * @return std::map<std::string, std::set<std::string>> Column name to the compression names of its files.
     */
    std::map<std::string, std::set<std::string>> tableCompressions(const std::filesystem::path& path)
    {
        const rocksdb::Options options;
        std::vector<std::string> names;
        if (const auto status {rocksdb::DB::ListColumnFamilies(options, path.string(), &names)}; !status.ok())
        {
            throw std::runtime_error("Failed to list columns: " + status.ToString());
        }

        std::vector<rocksdb::ColumnFamilyDescriptor> descriptors;
        for (const auto& name : names)
        {
            descriptors.emplace_back(name, rocksdb::ColumnFamilyOptions());
        }

        std::vector<rocksdb::ColumnFamilyHandle*> handles;
        rocksdb::DB* rawDb {nullptr};
        if (const auto status {rocksdb::DB::OpenForReadOnly(options, path.string(), descriptors, &handles, &rawDb)};
            !status.ok())
        {
            throw std::runtime_error("Failed to open read-only: " + status.ToString());
        }
        const std::unique_ptr<rocksdb::DB> db {rawDb};

        std::map<std::string, std::set<std::string>> result;
        for (auto* handle : handles)
        {
            rocksdb::TablePropertiesCollection properties;
            db->GetPropertiesOfAllTables(handle, &properties);
            for (const auto& [file, table] : properties)
            {
                result[handle->GetName()].insert(table->compression_name);
            }
            db->DestroyColumnFamilyHandle(handle);
        }
        return result;
    }

    /**
     * @brief Returns the compression names of every SST file of a closed database.
     *
     * @param path Database path.
     * @return std::set<std::string> Compression names.
     */
    std::set<std::string> allCompressions(const std::filesystem::path& path)
    {
        std::set<std::string> result;
        for (const auto& [column, compressions] : tableCompressions(path))
        {
            result.insert(compressions.begin(), compressions.end());
        }
        return result;
    }

    const std::set<std::string> NO_COMPRESSION {"NoCompression"};
    const std::set<std::string> LZ4 {"LZ4"};
    const std::set<std::string> ZSTD {"ZSTD"};
    constexpr auto COLUMN_A {"a"};
} // namespace

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

    EXPECT_THROW(db_wrapper->columnExists(COLUMN_NAME), std::invalid_argument);
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
    EXPECT_THROW(db_wrapper->createColumn(COLUMN_NAME), std::invalid_argument);
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

/**
 * @brief The RocksDB library in use must support lz4 and zstd; a library built without them makes every database
 * fall back to no compression.
 */
TEST_F(RocksDBWrapperTest, Lz4AndZstdAreSupported)
{
    EXPECT_TRUE(Utils::RocksDBOptions::isCompressionSupported(Utils::RocksDBCompression::LZ4_ZSTD));
    EXPECT_TRUE(Utils::RocksDBOptions::isCompressionSupported(Utils::RocksDBCompression::ZSTD));
}

TEST_F(RocksDBWrapperTest, NoneIsAlwaysSupported)
{
    EXPECT_TRUE(Utils::RocksDBOptions::isCompressionSupported(Utils::RocksDBCompression::NONE));
}

TEST_F(RocksDBWrapperTest, DefaultWritesWithoutCompression)
{
    const auto path {OUTPUT_FOLDER / "default"};
    {
        Utils::RocksDBWrapper db {path};
        db.put("key", "value");
        db.flush();
    }

    EXPECT_EQ(allCompressions(path), NO_COMPRESSION);
}

TEST_F(RocksDBWrapperTest, Lz4ZstdFlushIsLz4)
{
    const auto path {OUTPUT_FOLDER / "lz4zstd"};
    {
        Utils::RocksDBWrapper db {path, true, true, false, Utils::RocksDBCompression::LZ4_ZSTD};
        db.createColumn(COLUMN_A);
        db.put("key", "value");
        db.put("key", "value", COLUMN_A);
        db.flush();
    }

    const auto compressions {tableCompressions(path)};
    ASSERT_EQ(compressions.size(), 2);
    EXPECT_EQ(compressions.at(rocksdb::kDefaultColumnFamilyName), LZ4);
    EXPECT_EQ(compressions.at(COLUMN_A), LZ4);
}

TEST_F(RocksDBWrapperTest, ZstdAppliedToEveryColumn)
{
    const auto path {OUTPUT_FOLDER / "zstd"};
    {
        Utils::RocksDBWrapper db {path, true, true, false, Utils::RocksDBCompression::ZSTD};
        db.createColumn(COLUMN_A);
        db.put("key", "value");
        db.put("key", "value", COLUMN_A);
        db.flush();
    }

    const auto compressions {tableCompressions(path)};
    ASSERT_EQ(compressions.size(), 2);
    EXPECT_EQ(compressions.at(rocksdb::kDefaultColumnFamilyName), ZSTD);
    EXPECT_EQ(compressions.at(COLUMN_A), ZSTD);
}

TEST_F(RocksDBWrapperTest, CompressionKeptAfterDeleteAll)
{
    const auto path {OUTPUT_FOLDER / "delete_all"};
    {
        Utils::RocksDBWrapper db {path, true, true, false, Utils::RocksDBCompression::LZ4_ZSTD};
        db.createColumn(COLUMN_A);
        db.deleteAll();
        db.put("key", "value", COLUMN_A);
        db.flush();
    }

    EXPECT_EQ(tableCompressions(path).at(COLUMN_A), LZ4);
}

/**
 * @brief Writes keys "key0".."key<count-1>" with the given prefix into the default column and column "a".
 */
static void writeKeys(Utils::RocksDBWrapper& db, const std::string& prefix, const int count)
{
    for (int i = 0; i < count; ++i)
    {
        db.put(prefix + std::to_string(i), "value_" + prefix + std::to_string(i));
        db.put(prefix + std::to_string(i), "value_" + prefix + std::to_string(i), COLUMN_A);
    }
}

/**
 * @brief Creates a database with two columns written without compression.
 */
static void createOldDatabase(const std::filesystem::path& path)
{
    Utils::RocksDBWrapper db {path};
    db.createColumn(COLUMN_A);
    writeKeys(db, "old", 10);
    db.flush();
}

TEST_F(RocksDBWrapperTest, OldDatabaseOpensWithCompression)
{
    const auto path {OUTPUT_FOLDER / "old"};
    createOldDatabase(path);

    {
        std::unique_ptr<Utils::RocksDBWrapper> db;
        ASSERT_NO_THROW(
            db = std::make_unique<Utils::RocksDBWrapper>(path, true, true, false, Utils::RocksDBCompression::LZ4_ZSTD));

        std::string value;
        for (int i = 0; i < 10; ++i)
        {
            const auto key {"old" + std::to_string(i)};
            ASSERT_TRUE(db->get(key, value));
            EXPECT_EQ(value, "value_" + key);
            ASSERT_TRUE(db->get(key, value, COLUMN_A));
            EXPECT_EQ(value, "value_" + key);
        }

        auto count {0};
        for (const auto& [key, read] : db->seek("old", COLUMN_A))
        {
            EXPECT_EQ(read, "value_" + key);
            ++count;
        }
        EXPECT_EQ(count, 10);
    }

    EXPECT_EQ(allCompressions(path), NO_COMPRESSION);
}

TEST_F(RocksDBWrapperTest, OldDatabaseAcceptsNewWrites)
{
    const auto path {OUTPUT_FOLDER / "old"};
    createOldDatabase(path);

    {
        Utils::RocksDBWrapper db {path, true, true, false, Utils::RocksDBCompression::LZ4_ZSTD};
        writeKeys(db, "new", 5);
        db.put("old0", "overwritten", COLUMN_A);
        db.flush();
    }

    EXPECT_EQ(allCompressions(path), (std::set<std::string> {"NoCompression", "LZ4"}));

    Utils::RocksDBWrapper db {path, true, true, false, Utils::RocksDBCompression::LZ4_ZSTD};
    std::string value;
    ASSERT_TRUE(db.get("old0", value, COLUMN_A));
    EXPECT_EQ(value, "overwritten");
    ASSERT_TRUE(db.get("old1", value, COLUMN_A));
    EXPECT_EQ(value, "value_old1");
    ASSERT_TRUE(db.get("new4", value, COLUMN_A));
    EXPECT_EQ(value, "value_new4");
    ASSERT_TRUE(db.get("old0", value));
    EXPECT_EQ(value, "value_old0");
}

TEST_F(RocksDBWrapperTest, ReadsAcrossFormats)
{
    const auto path {OUTPUT_FOLDER / "mixed"};
    const std::vector<std::pair<Utils::RocksDBCompression, std::string>> phases {
        {Utils::RocksDBCompression::NONE, "k1_"},
        {Utils::RocksDBCompression::ZSTD, "k2_"},
        {Utils::RocksDBCompression::LZ4_ZSTD, "k3_"}};

    for (const auto& [compression, prefix] : phases)
    {
        Utils::RocksDBWrapper db {path, true, true, false, compression};
        db.put(prefix + "key", "value_" + prefix);
        db.flush();
    }

    EXPECT_EQ(allCompressions(path), (std::set<std::string> {"NoCompression", "ZSTD", "LZ4"}));

    Utils::RocksDBWrapper db {path, true, true, false, Utils::RocksDBCompression::LZ4_ZSTD};
    std::vector<std::string> keys;
    for (const auto& [key, value] : db.seek("k"))
    {
        EXPECT_EQ(value, "value_" + key.substr(0, 3));
        keys.push_back(key);
    }
    EXPECT_EQ(keys, (std::vector<std::string> {"k1_key", "k2_key", "k3_key"}));

    std::string value;
    EXPECT_TRUE(db.get("k2_key", value));
    EXPECT_EQ(value, "value_k2_");
}

TEST_F(RocksDBWrapperTest, DeleteAllOnOldDatabase)
{
    const auto path {OUTPUT_FOLDER / "old"};
    createOldDatabase(path);

    {
        Utils::RocksDBWrapper db {path, true, true, false, Utils::RocksDBCompression::LZ4_ZSTD};
        db.deleteAll();
        db.put("fresh", "value", COLUMN_A);
        db.flush();

        std::string value;
        EXPECT_FALSE(db.get("old0", value, COLUMN_A));
        EXPECT_TRUE(db.get("fresh", value, COLUMN_A));
    }

    EXPECT_EQ(tableCompressions(path).at(COLUMN_A), LZ4);
}
