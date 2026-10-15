/*
 * Wazuh Indexer Connector - Component tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CONNECTOR_TEST_HPP
#define _INDEXER_CONNECTOR_TEST_HPP

#include "fakeIndexer.hpp"
#include "gtest/gtest.h"
#include <functional>
#include <memory>
#include <vector>

/**
 * @brief Runs unit tests for IndexerConnector class.
 *
 */
class IndexerConnectorTest : public ::testing::Test
{
protected:
    IndexerConnectorTest() = default;
    ~IndexerConnectorTest() override = default;

    std::vector<std::unique_ptr<FakeIndexer>> m_indexerServers; ///< List of indexer servers.

    /**
     * @brief Setup routine for each test fixture.
     *
     */
    void SetUp() override;

    /**
     * @brief Teardown routine for each test fixture.
     *
     */
    void TearDown() override;

    /**
     * @brief Waits until the stop condition is true or the max sleep time is reached. In the latter, an exception is
     * thrown.
     *
     * @param stopCondition Wait stop condition function.
     * @param maxSleepTimeMs Max time to wait.
     */
    void waitUntil(const std::function<bool()>& stopCondition, const unsigned int& maxSleepTimeMs) const;
};

#endif // _INDEXER_CONNECTOR_TEST_HPP
