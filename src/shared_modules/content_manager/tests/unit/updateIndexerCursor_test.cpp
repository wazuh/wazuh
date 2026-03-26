/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "updateIndexerCursor_test.hpp"
#include "updaterContext.hpp"

/**
 * @brief Cursor "1042" is persisted to the database.
 */
TEST_F(UpdateIndexerCursorTest, PersistCursor)
{
    m_spUpdaterContext->data["cursor"] = "1042";

    EXPECT_NO_THROW(m_spUpdateIndexerCursor->handleRequest(m_spUpdaterContext));

    const auto stored =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    EXPECT_EQ(stored, "1042");
}

/**
 * @brief No "cursor" key in context.data → no throw, DB unchanged.
 */
TEST_F(UpdateIndexerCursorTest, SkipWhenCursorMissing)
{
    // Do not set context.data["cursor"].
    EXPECT_NO_THROW(m_spUpdateIndexerCursor->handleRequest(m_spUpdaterContext));

    const auto stored =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    EXPECT_EQ(stored, "0");
}

/**
 * @brief cursor = "" → no throw, DB unchanged.
 */
TEST_F(UpdateIndexerCursorTest, SkipWhenCursorEmpty)
{
    m_spUpdaterContext->data["cursor"] = "";

    EXPECT_NO_THROW(m_spUpdateIndexerCursor->handleRequest(m_spUpdaterContext));

    const auto stored =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    EXPECT_EQ(stored, "0");
}

/**
 * @brief spRocksDB = nullptr → std::runtime_error.
 */
TEST_F(UpdateIndexerCursorTest, ThrowWhenRocksDBNull)
{
    m_spUpdaterBaseContext->spRocksDB.reset();
    m_spUpdaterContext->data["cursor"] = "100";

    EXPECT_THROW(m_spUpdateIndexerCursor->handleRequest(m_spUpdaterContext), std::runtime_error);
}

/**
 * @brief Sequential writes: "500" then "1000" → final value "1000".
 */
TEST_F(UpdateIndexerCursorTest, OverwritePreviousCursor)
{
    m_spUpdaterContext->data["cursor"] = "500";
    EXPECT_NO_THROW(m_spUpdateIndexerCursor->handleRequest(m_spUpdaterContext));

    auto stored =
        m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    EXPECT_EQ(stored, "500");

    m_spUpdaterContext->data["cursor"] = "1000";
    EXPECT_NO_THROW(m_spUpdateIndexerCursor->handleRequest(m_spUpdaterContext));

    stored = m_spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    EXPECT_EQ(stored, "1000");
}
