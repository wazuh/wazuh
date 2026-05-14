/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "updateCtiApiOffset_test.hpp"
#include "updaterContext.hpp"

/**
 * @brief Check that the offset is updated in the database.
 */
TEST_F(UpdateCtiApiOffsetTest, updateOffset)
{
    // Get the last offset in the database.
    const auto lastOffset =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();

    // Set the current offset to a value different from the last offset.
    m_spUpdaterContext->currentOffset = 10;

    // Execute the handleRequest method.
    EXPECT_NO_THROW(m_spUpdateCtiApiOffset->handleRequest(m_spUpdaterContext));

    // Get the new last offset in the database.
    const auto newLastOffset =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();

    // Check that the last offset has been updated.
    EXPECT_NE(lastOffset, newLastOffset);
    EXPECT_EQ(newLastOffset, std::to_string(m_spUpdaterContext->currentOffset));
}

/**
 * @brief Check that the offset is not updated in the database.
 */
TEST_F(UpdateCtiApiOffsetTest, notUpdateOffset)
{
    // Get the last offset in the database.
    const auto lastOffset =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();

    // Set the current offset to a value equal to the last offset.
    m_spUpdaterContext->currentOffset = std::stoi(lastOffset);

    // Execute the handleRequest method.
    EXPECT_NO_THROW(m_spUpdateCtiApiOffset->handleRequest(m_spUpdaterContext));

    // Get the new last offset in the database.
    const auto newLastOffset =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();

    // Check that the last offset has not been updated.
    EXPECT_EQ(lastOffset, newLastOffset);
    EXPECT_EQ(newLastOffset, std::to_string(m_spUpdaterContext->currentOffset));
}

/**
 * @brief Check if the database is empty.
 */
TEST_F(UpdateCtiApiOffsetTest, emptyDatabase)
{
    // Delete all the data in the database.
    m_spUpdaterBaseContext->spRocksDB->deleteAll();

    // Execute the handleRequest method.
    EXPECT_NO_THROW(m_spUpdateCtiApiOffset->handleRequest(m_spUpdaterContext));
}

/**
 * @brief Check that if a database has not been created, a throw is generated.
 */
TEST_F(UpdateCtiApiOffsetTest, databaseNotCreated)
{
    // Delete the database.
    m_spUpdaterBaseContext->spRocksDB.reset();

    // Execute the handleRequest method.
    EXPECT_THROW(m_spUpdateCtiApiOffset->handleRequest(m_spUpdaterContext), std::runtime_error);
}
