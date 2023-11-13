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

/**
 * @brief Tests sendInitProviderMessage method.
 *
 */
TEST_F(RemoteStateHelperTest, sendInitProviderMessageTest)
{
    auto endpointName {"test-remote"};
    EXPECT_NO_THROW(RemoteStateHelper::sendInitProviderMessage(endpointName));
}

/**
 * @brief Tests sendRemoveProviderMessage method.
 *
 */
TEST_F(RemoteStateHelperTest, sendRemoveProviderMessageTest)
{
    auto endpointName {"test-remote"};
    EXPECT_NO_THROW(RemoteStateHelper::sendRemoveProviderMessage(endpointName));
}

/**
 * @brief Tests sendRemoveSubscriberMessage method.
 *
 */
TEST_F(RemoteStateHelperTest, sendRemoveSubscriberMessageTest)
{
    auto endpointName {"test-remote"};
    auto subscriberId {"test-subscriber"};
    EXPECT_NO_THROW(RemoteStateHelper::sendRemoveSubscriberMessage(endpointName, subscriberId));
}
