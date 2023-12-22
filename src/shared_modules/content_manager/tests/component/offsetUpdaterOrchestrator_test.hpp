/*
 * Wazuh Content Manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OFFSET_UPDATER_ORCHESTRATOR_TEST_HPP
#define _OFFSET_UPDATER_ORCHESTRATOR_TEST_HPP

#include "utils/rocksDBWrapper.hpp"
#include "gtest/gtest.h"
#include <atomic>
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <memory>

/**
 * @brief Runs component tests for OffsetUpdaterOrchestrator class.
 *
 */
class OffsetUpdaterOrchestratorTest : public ::testing::Test
{
protected:
    OffsetUpdaterOrchestratorTest() = default;
    ~OffsetUpdaterOrchestratorTest() override = default;

    const std::atomic<bool> m_shouldRun {true}; ///< Interruption flag.
    const std::filesystem::path m_databaseFolder {
        std::filesystem::temp_directory_path() /
        "OffsetUpdaterOrchestratorTest_database"}; ///< Path used to store the RocksDB database.
    const std::filesystem::path m_outputFolder {
        std::filesystem::temp_directory_path() /
        "OffsetUpdaterOrchestratorTest_output"};               ///< Path used to store the output files.
    nlohmann::json m_parameters;                               ///< Parameters used to create the orchestration.
    std::shared_ptr<Utils::RocksDBWrapper> m_spRocksDBWrapper; ///< DB connector used on tests.

    /**
     * @brief Sets initial conditions for each test case.
     *
     */
    void SetUp() override;

    /**
     * @brief Tear down routine for each test case.
     *
     */
    void TearDown() override;
};

#endif //_OFFSET_UPDATER_ORCHESTRATOR_TEST_HPP
