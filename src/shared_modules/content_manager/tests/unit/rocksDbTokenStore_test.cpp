/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
        open();
    }

    void TearDown() override
    {
        m_store.reset();
        m_database.reset();
        std::filesystem::remove_all(DATABASE_PATH);
    }

    /// Reopen the database, the way a process restart would.
    void open()
    {
        m_store.reset();
        m_database.reset();
        m_database = std::make_shared<Utils::RocksDBWrapper>(DATABASE_PATH);
        if (!m_database->columnExists(Components::Columns::CURRENT_OFFSET))
        {
            m_database->createColumn(Components::Columns::CURRENT_OFFSET);
        }
        m_store = std::make_unique<RocksDbTokenStore>(m_database);
    }

    std::shared_ptr<Utils::RocksDBWrapper> m_database;
    std::unique_ptr<RocksDbTokenStore> m_store;
};

} // namespace

TEST_F(RocksDbTokenStoreTest, AnEmptyColumnReadsAsNoToken)
{
    // getLastKeyValue throws on an empty column; load() must absorb that rather than let a first
    // run look like a failure.
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

TEST_F(RocksDbTokenStoreTest, ClearReadsBackAsNoTokenRatherThanThrowing)
{
    ASSERT_TRUE(m_store->store(TOPIC, "1042"));
    EXPECT_TRUE(m_store->clear(TOPIC));

    // clear() APPENDS "0"; it does not delete. The column is an append-only log read with a
    // SeekToLast, and getLastKeyValue throws on an empty column — so a real delete would break
    // every subsequent load().
    EXPECT_EQ(m_store->load(TOPIC), "");
}

TEST_F(RocksDbTokenStoreTest, StoringAnEmptyTokenIsANoOpNotAFailure)
{
    ASSERT_TRUE(m_store->store(TOPIC, "7"));
    // Reported as success: "" would read back as "no token" anyway, so the caller must not treat
    // this as a persistence error and re-fetch a whole feed over it.
    EXPECT_TRUE(m_store->store(TOPIC, ""));
    EXPECT_EQ(m_store->load(TOPIC), "7");
}

TEST_F(RocksDbTokenStoreTest, SurvivesAReopen)
{
    ASSERT_TRUE(m_store->store(TOPIC, "2048"));

    open();

    // The on-disk format is the one already deployed — compact-timestamp keys in `current_offset` —
    // so an upgraded manager reads its existing cursor back unchanged, with no migration.
    EXPECT_EQ(m_store->load(TOPIC), "2048");
}

TEST_F(RocksDbTokenStoreTest, ClearSurvivesAReopen)
{
    ASSERT_TRUE(m_store->store(TOPIC, "2048"));
    ASSERT_TRUE(m_store->clear(TOPIC));

    open();

    EXPECT_EQ(m_store->load(TOPIC), "");
}

TEST_F(RocksDbTokenStoreTest, ANullDatabaseIsInertRatherThanFatal)
{
    RocksDbTokenStore store {nullptr};
    EXPECT_EQ(store.load(TOPIC), "");
    EXPECT_FALSE(store.store(TOPIC, "1"));
    EXPECT_FALSE(store.clear(TOPIC));
}

TEST_F(RocksDbTokenStoreTest, AMissingColumnReadsAsNoTokenRatherThanThrowing)
{
    // Distinct from the empty-column case above, and the reason both are tested: they read back
    // identically — as "no token", which silently costs a full re-download — but only one of them
    // is normal. An empty column is a first run; a missing one means something removed it.
    auto bare = std::make_shared<Utils::RocksDBWrapper>(std::string {DATABASE_PATH} + "_bare");
    ASSERT_FALSE(bare->columnExists(Components::Columns::CURRENT_OFFSET));

    RocksDbTokenStore store {bare};
    EXPECT_EQ(store.load(TOPIC), "");

    bare.reset();
    std::filesystem::remove_all(std::string {DATABASE_PATH} + "_bare");
}
