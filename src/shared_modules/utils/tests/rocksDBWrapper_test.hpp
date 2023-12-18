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

#ifndef _ROCKS_DB_WRAPPER_TEST_HPP
#define _ROCKS_DB_WRAPPER_TEST_HPP

#include "rocksDBWrapper.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

const auto OUTPUT_FOLDER {std::filesystem::temp_directory_path() / "RocksDBWrapperTest"};

/**
 * @brief Tests the RocksDBWrapper class
 *
 */
class RocksDBWrapperTest : public ::testing::Test
{
protected:
    RocksDBWrapperTest() = default;
    ~RocksDBWrapperTest() override = default;

    /**
     * @brief RocksDBWrapper object
     *
     */
    std::unique_ptr<Utils::RocksDBWrapper> db_wrapper;

    const std::filesystem::path m_databaseFolder {OUTPUT_FOLDER / "test_db"}; ///< Database folder.

    /**
     * @brief Initial conditions for tests
     *
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        db_wrapper = std::make_unique<Utils::RocksDBWrapper>(m_databaseFolder);
    }

    /**
     * @brief Tear down routine for tests
     *
     */
    // cppcheck-suppress unusedFunction
    void TearDown() override
    {
        db_wrapper->deleteAll();
        db_wrapper.reset();
        std::filesystem::remove_all(OUTPUT_FOLDER);
    }
};

#endif //_ROCKS_DB_WRAPPER_TEST_HPP
