/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Validates the zero-copy Payload holder: bytes() is a view into a buffer kept
// alive by an opaque keep-alive, and release() (explicit) / destruction (RAII)
// drop that keep-alive -- freeing the buffer -- while never exposing a dangling
// view.
#include "auth/authTypes.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <string_view>

using remoted::auth::Payload;

TEST(Payload, DefaultIsEmpty)
{
    Payload payload;
    EXPECT_TRUE(payload.empty());
    EXPECT_EQ(payload.size(), 0U);
    EXPECT_TRUE(payload.bytes().empty());
}

TEST(Payload, ViewIsValidWhileKeepAliveHeld)
{
    auto buffer = std::make_shared<std::string>("hello-body");
    const Payload payload {std::string_view {*buffer}, buffer};

    EXPECT_FALSE(payload.empty());
    EXPECT_EQ(payload.size(), buffer->size());
    EXPECT_EQ(payload.bytes(), "hello-body");
}

TEST(Payload, KeepAlivePinsTheBuffer)
{
    auto buffer = std::make_shared<std::string>("data");
    std::weak_ptr<std::string> observer = buffer;

    const Payload payload {std::string_view {*buffer}, buffer};
    buffer.reset(); // the payload is now the only owner

    EXPECT_FALSE(observer.expired()); // ... so the buffer is still alive
    EXPECT_EQ(payload.bytes(), "data");
}

TEST(Payload, ReleaseDropsKeepAliveAndEmptiesView)
{
    auto buffer = std::make_shared<std::string>("data");
    std::weak_ptr<std::string> observer = buffer;

    const Payload payload {std::string_view {*buffer}, buffer};
    buffer.reset();

    payload.release();               // explicit early release
    EXPECT_TRUE(observer.expired()); // keep-alive dropped -> buffer freed
    EXPECT_TRUE(payload.empty());    // no dangling view is ever exposed
    EXPECT_TRUE(payload.bytes().empty());
}

TEST(Payload, ReleaseIsIdempotent)
{
    auto buffer = std::make_shared<std::string>("x");
    const Payload payload {std::string_view {*buffer}, buffer};

    payload.release();
    EXPECT_NO_THROW(payload.release()); // second call is a no-op
    EXPECT_TRUE(payload.empty());
}

TEST(Payload, DestructionReleasesKeepAlive)
{
    auto buffer = std::make_shared<std::string>("y");
    std::weak_ptr<std::string> observer = buffer;

    {
        const Payload payload {std::string_view {*buffer}, buffer};
        buffer.reset();
        EXPECT_FALSE(observer.expired()); // the payload holds it
    }

    EXPECT_TRUE(observer.expired()); // payload destroyed -> keep-alive dropped (RAII)
}
