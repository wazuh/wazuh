/*
 * Wazuh - Shared Modules utils tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKS_DB_ITERATOR_TEST_HPP
#define _ROCKS_DB_ITERATOR_TEST_HPP

#include "rocksDBIterator.hpp"
#include "gtest/gtest.h"

/**
 * @brief Tests the RocksDBWrapper class
 *
 */
class RocksDBIteratorTest : public ::testing::Test
{
protected:
    RocksDBIteratorTest() = default;
    ~RocksDBIteratorTest() override = default;

    /**
     * @brief RocksDB object
     *
     */
    std::unique_ptr<rocksdb::DB> rocksDb;

    /**
     * @brief Initial conditions for tests
     *
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        rocksdb::Options options;
        options.create_if_missing = true;
        rocksdb::DB* dbRawPtr;
        const auto status {rocksdb::DB::Open(options, "test.db", &dbRawPtr)};
        if (!status.ok())
        {
            throw std::runtime_error("Failed to open RocksDB database");
        }

        rocksDb.reset(dbRawPtr);
    }

    /**
     * @brief Tear down routine for tests
     *
     */
    // cppcheck-suppress unusedFunction
    void TearDown() override
    {
        rocksDb->Close();
    }
};

#endif //_ROCKS_DB_ITERATOR_TEST_HPP
