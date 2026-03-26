/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_INDEXER_CURSOR_TEST_HPP
#define _UPDATE_INDEXER_CURSOR_TEST_HPP

#include "conditionSync.hpp"
#include "updateIndexerCursor.hpp"
#include "updaterContext.hpp"
#include "utils/rocksDBWrapper.hpp"
#include "utils/timeHelper.h"
#include "gtest/gtest.h"
#include <filesystem>

const auto CURSOR_DB_FOLDER {std::filesystem::temp_directory_path() / "cursor_test_db"};

/**
 * @brief Runs unit tests for UpdateIndexerCursor
 */
class UpdateIndexerCursorTest : public ::testing::Test
{
protected:
    UpdateIndexerCursorTest() = default;
    ~UpdateIndexerCursorTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext;
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext;
    std::shared_ptr<UpdateIndexerCursor> m_spUpdateIndexerCursor;

    std::shared_ptr<ConditionSync> m_spStopActionCondition {std::make_shared<ConditionSync>(false)};

    void SetUp() override
    {
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>(m_spStopActionCondition,
                                                                      [](nlohmann::json msg) -> FileProcessingResult {
                                                                          return {0, "", false};
                                                                      });
        m_spUpdaterBaseContext->spRocksDB = std::make_unique<Utils::RocksDBWrapper>(CURSOR_DB_FOLDER);
        m_spUpdaterBaseContext->spRocksDB->createColumn(Components::Columns::CURRENT_OFFSET);
        m_spUpdaterBaseContext->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)), "0", Components::Columns::CURRENT_OFFSET);

        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

        m_spUpdateIndexerCursor = std::make_shared<UpdateIndexerCursor>();
    }

    void TearDown() override
    {
        if (m_spUpdaterBaseContext->spRocksDB)
        {
            m_spUpdaterBaseContext->spRocksDB->deleteAll();
        }
        std::filesystem::remove_all(CURSOR_DB_FOLDER);
    }
};

#endif //_UPDATE_INDEXER_CURSOR_TEST_HPP
