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

#include "rocksDBIterator_test.hpp"

TEST_F(RocksDBIteratorTest, TestBasicIteration)
{
    // Insert some elements to the database.
    rocksDb->Put(rocksdb::WriteOptions(), "key1", "value1");
    rocksDb->Put(rocksdb::WriteOptions(), "key2", "value2");
    rocksDb->Put(rocksdb::WriteOptions(), "key3", "value3");

    auto db_iterator {Utils::RocksDBIterator(rocksDb)};

    // Go to the first element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.toFirst());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key1");
    EXPECT_EQ(db_iterator.getValue(), "value1");

    // Go to the next element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.next());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key2");
    EXPECT_EQ(db_iterator.getValue(), "value2");

    // Go to the next element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.next());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key3");
    EXPECT_EQ(db_iterator.getValue(), "value3");

    // Go to the previous element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.prev());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key2");
    EXPECT_EQ(db_iterator.getValue(), "value2");

    // Go to the next element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.next());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key3");
    EXPECT_EQ(db_iterator.getValue(), "value3");

    // Go to the first element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.toFirst());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key1");
    EXPECT_EQ(db_iterator.getValue(), "value1");

    // Go to the last element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.toLast());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key3");
    EXPECT_EQ(db_iterator.getValue(), "value3");

    // Go to the next element and verify that the iterator is invalid.
    EXPECT_FALSE(db_iterator.next());
    EXPECT_FALSE(db_iterator.isValid());
}

TEST_F(RocksDBIteratorTest, TestEmptyDB)
{

    auto db_iterator {Utils::RocksDBIterator(rocksDb)};

    // Go to the first element and verify that the iterator is invalid.
    EXPECT_TRUE(db_iterator.toFirst());
    EXPECT_TRUE(db_iterator.isValid());

    // Go to the last element and verify that the iterator is invalid.
    EXPECT_TRUE(db_iterator.toLast());
    EXPECT_TRUE(db_iterator.isValid());

    // Go to the next element and verify that the iterator is invalid.
    EXPECT_FALSE(db_iterator.next());
    EXPECT_FALSE(db_iterator.isValid());

    // Go to the previous element and verify that the iterator is invalid.
    EXPECT_FALSE(db_iterator.prev());
    EXPECT_FALSE(db_iterator.isValid());
}

TEST_F(RocksDBIteratorTest, TestGoTo)
{
    // Insert some elements to the database.
    rocksDb->Put(rocksdb::WriteOptions(), "key1", "value1");
    rocksDb->Put(rocksdb::WriteOptions(), "key2", "value2");
    rocksDb->Put(rocksdb::WriteOptions(), "key3", "value3");

    auto db_iterator {Utils::RocksDBIterator(rocksDb)};

    // Go to a specific element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.goTo("key2"));
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key2");
    EXPECT_EQ(db_iterator.getValue(), "value2");

    // Go to the previous element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.prev());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key1");
    EXPECT_EQ(db_iterator.getValue(), "value1");

    // Go to the last element and verify that the iterator is valid.
    EXPECT_TRUE(db_iterator.toLast());
    EXPECT_TRUE(db_iterator.isValid());
    EXPECT_EQ(db_iterator.getKey(), "key3");
    EXPECT_EQ(db_iterator.getValue(), "value3");
}

TEST_F(RocksDBIteratorTest, TestSeekToNonExistentKey)
{
    // Insert some elements to the database.
    rocksDb->Put(rocksdb::WriteOptions(), "key1", "value1");
    rocksDb->Put(rocksdb::WriteOptions(), "key2", "value2");

    // Create an iterator and go to a non-existent key.
    auto db_iterator {Utils::RocksDBIterator(rocksDb)};

    EXPECT_FALSE(db_iterator.goTo("non_existent_key"));
    EXPECT_FALSE(db_iterator.isValid());
}
