/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "adaptivePayload.hpp"

#include <gtest/gtest.h>

TEST(AdaptivePayloadTest, StartsAtTheConfiguredMax)
{
    AdaptivePayload payload {1024 * 1024};
    EXPECT_EQ(1024u * 1024u, payload.effectiveBytes());
}

TEST(AdaptivePayloadTest, PayloadTooLargeHalvesWithoutAHardFloor)
{
    // No lower clamp: a server cap smaller than any fixed floor must still be
    // reachable, or the stream would retry the same too-big batch forever.
    AdaptivePayload payload {1000};
    payload.onPayloadTooLarge();
    EXPECT_EQ(500u, payload.effectiveBytes());
    payload.onPayloadTooLarge();
    EXPECT_EQ(250u, payload.effectiveBytes());

    for (int halvings = 0; halvings < 20; halvings++)
    {
        payload.onPayloadTooLarge();
    }

    EXPECT_EQ(1u, payload.effectiveBytes()); // Converges to one byte, never zero.
    payload.onPayloadTooLarge();
    EXPECT_EQ(1u, payload.effectiveBytes());
}

TEST(AdaptivePayloadTest, SuccessDoublesBackTowardTheMax)
{
    AdaptivePayload payload {1000};
    payload.onPayloadTooLarge();
    payload.onPayloadTooLarge();
    payload.onPayloadTooLarge(); // 125.
    payload.onSuccess();
    EXPECT_EQ(250u, payload.effectiveBytes());
    payload.onSuccess();
    EXPECT_EQ(500u, payload.effectiveBytes());
    payload.onSuccess();
    EXPECT_EQ(1000u, payload.effectiveBytes()); // Clamped at the max.
    payload.onSuccess();
    EXPECT_EQ(1000u, payload.effectiveBytes());
}

TEST(AdaptivePayloadTest, ZeroMaxIsTreatedAsOneByte)
{
    AdaptivePayload payload {0};
    EXPECT_EQ(1u, payload.effectiveBytes());
    payload.onPayloadTooLarge();
    EXPECT_EQ(1u, payload.effectiveBytes());
    payload.onSuccess();
    EXPECT_EQ(1u, payload.effectiveBytes());
}
