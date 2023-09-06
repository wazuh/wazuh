/*
 * Wazuh router - RemoteStateHelper tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 06, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remoteStateHelper_test.hpp"
#include "src/remoteStateHelper.hpp"
#include <external/nlohmann/json.hpp>

/*
 * @brief Tests semd a registration message with invalid MessageType
 */
TEST_F(RemoteStateHelperTest, TestSendInvalidMessageType)
{
    const auto invalidMessage = R"(
        {
            "EndpointName": "test-remote",
            "MessageType": "invalidMessageType"
        }
    )"_json;

    // It doesn't throw an exception, because it's already handled in the function
    EXPECT_NO_THROW(RemoteStateHelper::sendRegistrationMessage(invalidMessage));
}

/*
 * @brief Tests send a registration message without data
 */
TEST_F(RemoteStateHelperTest, TestSendEmptyMessage)
{
    const auto emptyMessage = R"({})"_json;

    // It doesn't throw an exception, because it's already handled in the function
    EXPECT_NO_THROW(RemoteStateHelper::sendRegistrationMessage(emptyMessage));
}

/*
 * @brief Tests send a registration message with valid MessageType
 */
TEST_F(RemoteStateHelperTest, TestSendValidMessageType)
{
    const auto message = R"(
        {
            "EndpointName": "test-remote",
            "MessageType": "InitProvider"
        }
    )"_json;

    EXPECT_NO_THROW(RemoteStateHelper::sendRegistrationMessage(message));
}

/*
 * @brief Tests send a registration message without EndpointName
 */
TEST_F(RemoteStateHelperTest, TestSendMessageWithoutEndpointName)
{
    const auto message = R"(
        {
            "MessageType": "InitProvider"
        }
    )"_json;

    // It doesn't throw an exception, because it's already handled in the function
    EXPECT_NO_THROW(RemoteStateHelper::sendRegistrationMessage(message));
}
