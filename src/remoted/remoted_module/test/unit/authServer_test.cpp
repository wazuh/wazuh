/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Only the CRTP/pimpl shape and lifecycle are testable so far -- no HTTP
// library is wired in yet (see authServer.cpp), so there is no real listener
// to exercise a request against.
#include <gtest/gtest.h>

#include "authServer.hpp"

using namespace wazuh_auth;

namespace
{

    TEST(AuthServer, StartsNotRunning)
    {
        AuthServer server;
        EXPECT_FALSE(server.isRunning());
    }

    TEST(AuthServer, StartSetsRunningTrue)
    {
        AuthServer server;
        server.start(false);
        EXPECT_TRUE(server.isRunning());
    }

    TEST(AuthServer, StopSetsRunningFalse)
    {
        AuthServer server;
        server.start(false);
        server.stop();
        EXPECT_FALSE(server.isRunning());
    }

    TEST(AuthServer, StopWithoutStartIsSafe)
    {
        AuthServer server;
        server.stop();
        EXPECT_FALSE(server.isRunning());
    }

    TEST(AuthServer, ConfigureAndAddRouteDoNotThrowBeforeStart)
    {
        AuthServer server;
        server.configure(ServerConfig {}, TlsConfig {}, AuthConfig {});
        server.addRoute(Method::POST, "/stateless", [](const AuthenticatedRequest&) { return HttpResponse::ok(); });
        EXPECT_FALSE(server.isRunning());
    }

} // namespace
