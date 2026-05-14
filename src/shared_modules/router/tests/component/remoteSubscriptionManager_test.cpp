/*
 * Wazuh router - RemoteSubscriptionManager tests
 * Copyright (C) 2015, Wazuh Inc.
 * December 19, 2023.
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
TEST_F(RemoteSubscriptionManagerTest, sendInitProviderMessageTest)
{
    auto endpointName {"test-remote"};
    RemoteSubscriptionManager remoteSubscriptionManager {};
    std::promise<void> promise;
    EXPECT_NO_THROW(remoteSubscriptionManager.sendInitProviderMessage(endpointName, [&]() { promise.set_value(); }));

    if (promise.get_future().wait_for(std::chrono::seconds(5)) == std::future_status::timeout)
    {
        FAIL() << "Timeout waiting for provider initialization";
    }
}
