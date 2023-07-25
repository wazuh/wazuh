/*
 * Wazuh router - Publisher tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "publisher_test.hpp"
#include "src/publisher.hpp"
#include <memory>

/*
 * @brief Tests the instantiation of the Publisher class
 */
TEST_F(PublisherTest, TestPublisherInstantiation)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    // Check that the Publisher class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH));
}

/*
 * @brief Tests the Publisher class with an invalid socket path. An exception is expected.
 */
TEST_F(PublisherTest, TestPublisherWithInvalidSocketPath)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto INVALID_SOCKET_PATH = "test";

    // Check that the Publisher class can not be instantiated
    EXPECT_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, INVALID_SOCKET_PATH), std::runtime_error);
}

/*
 * @brief Tests the Publisher class with empty endpoint name. An exception is expected.
 */
TEST_F(PublisherTest, TestPublisherWithEmptyEndpointName)
{
    constexpr auto EMPTY_ENDPOINT_NAME = "";
    constexpr auto EMPTY_SOCKET_PATH = "test/";

    // Check that the Publisher class can not be instantiated
    EXPECT_THROW(std::make_shared<Publisher>(EMPTY_ENDPOINT_NAME, EMPTY_SOCKET_PATH), std::runtime_error);
}

/*
 * @brief Tests the Publisher class with empty endpoint name and socket path. An exception is expected.
 */
TEST_F(PublisherTest, TestPublisherWithEmptyEndpointNameAndSocketPath)
{
    constexpr auto EMPTY_ENDPOINT_NAME = "";
    constexpr auto EMPTY_SOCKET_PATH = "";

    // Check that the Publisher class can not be instantiated
    EXPECT_THROW(std::make_shared<Publisher>(EMPTY_ENDPOINT_NAME, EMPTY_SOCKET_PATH), std::runtime_error);
}

/*
 * @brief Tests two Publishers with the same endpoint name and socket path.
 */
TEST_F(PublisherTest, TestTwoPublishersWithTheSameEndpointNameAndSocketPath)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    // Check that the first Publisher class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH));

    // Check that the second Publisher class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH));
}

/*
 * @brief Tests publish valid data.
 */
TEST_F(PublisherTest, TestPublishValidData)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    const std::vector<char> data = {'h', 'e', 'l', 'l', 'o', '!'};

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Check that the Publisher class can publish data
    EXPECT_NO_THROW(publisher->push(data));
}

/*
 * @brief Tests publish empty data.
 */
TEST_F(PublisherTest, TestPublishEmptyData)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    const std::vector<char> emptyData;

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Check that the Publisher class can publish empty data
    EXPECT_NO_THROW(publisher->push(emptyData));
}
