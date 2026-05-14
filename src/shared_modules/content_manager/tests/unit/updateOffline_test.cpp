/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 04, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "updateOffline_test.hpp"
#include "updaterContext.hpp"

/**
 * @brief Check that the offset is updated in the database.
 */
TEST_F(UpdateOfflineTest, updateValues)
{
    // Get the last offset and hash in the database.
    const auto lastOffset =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    const auto lastHash =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::DOWNLOADED_FILE_HASH).second.ToString();

    // Set the current offset and hash values different from the last offset.
    m_spUpdaterContext->currentOffset = 10;
    m_spUpdaterContext->spUpdaterBaseContext->downloadedFileHash = "newHash";

    // Execute the handleRequest method.
    EXPECT_NO_THROW(m_spUpdateOffline->handleRequest(m_spUpdaterContext));

    // Get the new last offset in the database.
    const auto newLastOffset =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    const auto newLastHash =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::DOWNLOADED_FILE_HASH).second.ToString();

    // Check that the last offset has been updated.
    EXPECT_NE(lastOffset, newLastOffset);
    EXPECT_EQ(newLastOffset, std::to_string(m_spUpdaterContext->currentOffset));

    // Check that the last hash has been updated.
    EXPECT_NE(lastHash, newLastHash);
    EXPECT_EQ(newLastHash, m_spUpdaterContext->spUpdaterBaseContext->downloadedFileHash);
}

/**
 * @brief Check that if a database has not been created, a throw is generated.
 */
TEST_F(UpdateOfflineTest, databaseNotCreated)
{
    // Delete the database.
    m_spUpdaterBaseContext->spRocksDB.reset();

    // Execute the handleRequest method.
    EXPECT_THROW(m_spUpdateOffline->handleRequest(m_spUpdaterContext), std::runtime_error);
}
