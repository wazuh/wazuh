/*
 * Wazuh databaseFeedManager
 * Copyright (C) 2015, Wazuh Inc.
 * September 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _MOCK_INDEXERCONNECTOR_HPP
#define _MOCK_INDEXERCONNECTOR_HPP

#include "gmock/gmock.h"
#include "gtest/gtest.h"

/**
 * @class MockIndexerConnector
 *
 * @brief Mock class for simulating a indexer connector object.
 *
 * The `MockIndexerConnector` class is designed to simulate the behavior of a content
 * register for testing purposes. It provides mock implementations of methods and
 * allows you to set expectations on method calls and their return values for testing.
 *
 * This class is used in unit tests only to verify interactions with a content
 * register without actually performing real operations on it.
 */
class MockIndexerConnector
{
public:
    MockIndexerConnector() = default;
    virtual ~MockIndexerConnector() = default;

    /**
     * @brief Mock method for publishing.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(void, publish, (const std::string& message), (const));

    /**
     * @brief Mock method for syncing.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(void, sync, (const std::string& agentId), (const));
};

#endif // _MOCK_INDEXERCONNECTOR_HPP
