/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "components/rocksDbTokenStore.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

namespace
{

    constexpr auto DATABASE_PATH = "queue/content_token_store_test";
    constexpr auto TOPIC = "test.topic";

    class RocksDbTokenStoreTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            std::filesystem::remove_all(DATABASE_PATH);
            reopen();
        }

        void TearDown() override
        {
            m_store.reset();
            std::filesystem::remove_all(DATABASE_PATH);
        }

        /// Reopen the database, the way a process restart would.
        void reopen()
        {
            m_store.reset();
            m_store = RocksDbTokenStore::open(DATABASE_PATH, TOPIC);
        }

        std::shared_ptr<RocksDbTokenStore> m_store;
    };

} // namespace

TEST_F(RocksDbTokenStoreTest, OpenCreatesTheDatabaseAndItsColumn)
{
    EXPECT_TRUE(std::filesystem::exists(std::string {DATABASE_PATH} + "/updater_" + TOPIC + "_metadata"));
    // A first run reads as "no token", not as a failure.
    EXPECT_EQ(m_store->load(TOPIC), "");
}

TEST_F(RocksDbTokenStoreTest, RoundTripsAToken)
{
    EXPECT_TRUE(m_store->store(TOPIC, "1042"));
    EXPECT_EQ(m_store->load(TOPIC), "1042");
}

TEST_F(RocksDbTokenStoreTest, TheLastWriteWins)
{
    EXPECT_TRUE(m_store->store(TOPIC, "1"));
    EXPECT_TRUE(m_store->store(TOPIC, "2"));
    EXPECT_TRUE(m_store->store(TOPIC, "3"));
    EXPECT_EQ(m_store->load(TOPIC), "3");
}

TEST_F(RocksDbTokenStoreTest, ClearReadsBackAsNoToken)
{
    ASSERT_TRUE(m_store->store(TOPIC, "1042"));
    EXPECT_TRUE(m_store->clear(TOPIC));
    EXPECT_EQ(m_store->load(TOPIC), "");
}

TEST_F(RocksDbTokenStoreTest, SurvivesAReopen)
{
    ASSERT_TRUE(m_store->store(TOPIC, "2048"));
    reopen();
    EXPECT_EQ(m_store->load(TOPIC), "2048");
}

TEST_F(RocksDbTokenStoreTest, ClearSurvivesAReopen)
{
    ASSERT_TRUE(m_store->store(TOPIC, "2048"));
    ASSERT_TRUE(m_store->clear(TOPIC));
    reopen();
    EXPECT_EQ(m_store->load(TOPIC), "");
}

TEST_F(RocksDbTokenStoreTest, AMissingColumnReadsAsNoToken)
{
    // Reads back like an empty column — as "no token" — but means something removed the column.
    const auto barePath = std::string {DATABASE_PATH} + "_bare";
    {
        auto bare = std::make_shared<Utils::RocksDBWrapper>(barePath);
        ASSERT_FALSE(bare->columnExists(RocksDbTokenStore::COLUMN));

        RocksDbTokenStore store {bare};
        EXPECT_EQ(store.load(TOPIC), "");
    }
    std::filesystem::remove_all(barePath);
}
