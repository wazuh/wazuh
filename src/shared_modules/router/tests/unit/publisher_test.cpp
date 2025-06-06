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

#include "socketClient.hpp"
#include "src/publisher.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

/**
 * @brief Runs unit tests for Publisher class
 */
class PublisherTest : public ::testing::Test
{
protected:
    PublisherTest() = default;
    ~PublisherTest() override = default;
};

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

    const auto publisher {std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH)};

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

    const auto publisher {std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH)};

    // Check that the Publisher class can publish empty data
    EXPECT_NO_THROW(publisher->push(emptyData));
}

/*
 * @brief Tests send data to socket without header P
 */
TEST_F(PublisherTest, TestPublishSocketWithoutP)
{
    const std::string ENDPOINT_NAME = "test";
    const std::string SOCKET_PATH = "test/";
    std::condition_variable cv;
    std::mutex cvMutex;

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
    auto socketClient = std::make_unique<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(SOCKET_PATH + ENDPOINT_NAME);

    nlohmann::json jsonMessage;
    jsonMessage["type"] = "subscribe";
    jsonMessage["subscriberId"] = "ID_0";
    auto jsonMessageString = jsonMessage.dump();

    int32_t onReadCallCount = 0;

    socketClient->connect(
        [&onReadCallCount, &cv](const char* body, uint32_t bodySize, const char*, uint32_t)
        {
            nlohmann::json result;
            EXPECT_NO_THROW(result = nlohmann::json::parse(body, body + bodySize));
            if (onReadCallCount == 0)
            {
                EXPECT_EQ(result.dump(), R"({"Result":"OK"})");
            }
            else
            {
                EXPECT_EQ(
                    result.dump(),
                    R"({"offset":57000,"paths":["GracefulShutdown.json"],"stageStatus":[{"stage":"download","status":"ok"}],"type":"offsets"})");
            }
            onReadCallCount++;
            cv.notify_all();
        },
        [&jsonMessageString, &socketClient]()
        { EXPECT_NO_THROW(socketClient->send(jsonMessageString.data(), jsonMessageString.size())); });

    {
        std::unique_lock<std::mutex> lk(cvMutex);
        std::cv_status result = cv.wait_for(lk, std::chrono::seconds(5));
        EXPECT_EQ(result, std::cv_status::no_timeout);
    }

    auto routerMessageJson = R"(
    {
        "type": "offsets",
        "offset": 57000,
        "paths":
        [
            "GracefulShutdown.json"
        ],
        "stageStatus":
        [
            {
                "stage": "download",
                "status": "ok"
            }
        ]
    }
    )"_json;
    const auto routerMessagePayload = routerMessageJson.dump();
    const auto routerMessage = std::vector<char>(routerMessagePayload.begin(), routerMessagePayload.end());
    publisher->call(routerMessage);

    {
        std::unique_lock<std::mutex> lk(cvMutex);
        std::cv_status result = cv.wait_for(lk, std::chrono::seconds(5));
        EXPECT_EQ(result, std::cv_status::no_timeout);
    }
    EXPECT_EQ(onReadCallCount, 2);
}

/*
 * @brief Tests send data to socket with header P
 */
TEST_F(PublisherTest, TestPublishSocketP)
{
    const std::string ENDPOINT_NAME = "test";
    const std::string SOCKET_PATH = "test/";
    std::condition_variable cv;
    std::mutex cvMutex;

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
    auto socketClient = std::make_unique<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(SOCKET_PATH + ENDPOINT_NAME);

    auto routerMessageJson = R"(
    {
        "type": "offsets",
        "offset": 57000,
        "paths":
        [
            "GracefulShutdown.json"
        ],
        "stageStatus":
        [
            {
                "stage": "download",
                "status": "ok"
            }
        ]
    }
    )"_json;
    const auto routerMessagePayload = routerMessageJson.dump();

    socketClient->connect([](const char* body, uint32_t bodySize, const char*, uint32_t) {},
                          [&cv, &routerMessagePayload, &socketClient]()
                          {
                              EXPECT_NO_THROW(
                                  socketClient->send(routerMessagePayload.data(), routerMessagePayload.size(), "P", 1));
                              cv.notify_all();
                          });

    {
        std::unique_lock<std::mutex> lk(cvMutex);
        std::cv_status result = cv.wait_for(lk, std::chrono::seconds(5));
        EXPECT_EQ(result, std::cv_status::no_timeout);
    }
}
