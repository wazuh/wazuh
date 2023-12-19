/*
 * Wazuh router - RemoteSubscriptionManager tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 06, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remoteSubscriptionManager_test.hpp"
#include "src/remoteSubscriptionManager.hpp"
#include <external/nlohmann/json.hpp>

/**
 * @brief Tests sendInitProviderMessage method.
 *
 */
TEST_F(RemoteStateHelperTest, sendInitProviderMessageTest)
{
    auto endpointName {"test-remote"};
    // EXPECT_NO_THROW(RemoteStateHelper::sendInitProviderMessage(endpointName));
}

/**
 * @brief Tests sendRemoveSubscriberMessage method.
 *
 */
TEST_F(RemoteStateHelperTest, sendRemoveSubscriberMessageTest)
{
    auto endpointName {"test-remote"};
    auto subscriberId {"test-subscriber"};
    // EXPECT_NO_THROW(RemoteStateHelper::sendRemoveSubscriberMessage(endpointName, subscriberId));
}
