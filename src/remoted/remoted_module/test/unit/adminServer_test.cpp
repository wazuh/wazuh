/*
 * Wazuh remoted module (C++ worker bridge) - local admin socket unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 15, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// End-to-end tests of the module's LOCAL admin socket (queue/sockets/remoted-module.sock),
// brought up by RemotedModuleFacade::start() through the same C-ABI black-box route
// remotedModule_test.cpp takes, and driven with a real httplib::Client over the UDS socket --
// the inverse of fakeVdServer.hpp, where a real httplib::Server stands in for a module client's
// peer. What these tests pin: the fixed socket path and 0660 mode, the GET / liveness probe,
// the GET /metrics dump carrying the module's metric families, exact-match routing (404/405),
// the warn-and-continue policy on a failed admin bind (the module -- and remoted with it --
// must never die for its metrics), and the socket being unlinked by a clean stop() with the
// whole plane coming back on a restart cycle.

#include "remoted_module.h"
#include "testLogRecorder.hpp" // the SHARED process-wide log sink (first-come; see the header)
#include "testTlsServer.hpp"   // generateTestCertificate + ScratchFileCleanup

#include <gtest/gtest.h>
#include <httplib.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace
{
    // Where the facade binds its admin server: FIXED and RELATIVE (remoted chroot()s into the
    // install dir; here it simply resolves against the test process's cwd, the same convention
    // remotedModule_test.cpp's default-TLS-path test relies on). Spelled out literally so a
    // change of the facade's constant is a conscious test change too.
    constexpr auto kAdminSocketPath {"queue/sockets/remoted-module.sock"};

    // A port the OS says is free, asked for right before the module binds it -- same rationale
    // as remotedModule_test.cpp: nothing here asserts on the port, it only has to be free.
    std::uint16_t findFreePort()
    {
        const int probe = ::socket(AF_INET, SOCK_STREAM, 0);
        if (probe < 0)
        {
            return 0;
        }

        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0; // let the kernel pick

        std::uint16_t port = 0;
        if (::bind(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
        {
            socklen_t length = sizeof(address);
            if (::getsockname(probe, reinterpret_cast<sockaddr*>(&address), &length) == 0)
            {
                port = ntohs(address.sin_port);
            }
        }

        ::close(probe);
        return port;
    }

    /// Whether a plain TCP connect to 127.0.0.1:port succeeds -- enough to prove the public
    /// HTTPS listener is accepting, without dragging the TLS/CMAC client machinery in here.
    bool publicListenerAccepts(std::uint16_t port)
    {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            return false;
        }

        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);

        const bool connected = ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
        ::close(fd);
        return connected;
    }
} // namespace

class AdminServerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // The facade binds a fixed relative path and the library creates no parent directories
        // (RF-9), so the test provides the installed manager's queue/sockets/ layout under cwd.
        std::filesystem::create_directories("queue/sockets");
        std::error_code ec;
        std::filesystem::remove(kAdminSocketPath, ec);
        remoted::test::LogRecorder::clear();
    }

    void TearDown() override
    {
        // Ensure the module is stopped even if a test asserted early; scrub the socket path so
        // no test inherits another's leftovers.
        remoted_module_stop();
        std::error_code ec;
        std::filesystem::remove(kAdminSocketPath, ec);
    }

    /**
     * @brief Starts the module with a throwaway TLS identity.
     *
     * remoted_module_start() is synchronous through startAdminServer(), so when this returns
     * the admin socket is either bound or definitively skipped (warn-and-continue) -- no
     * polling needed.
     *
     * @return The public HTTPS port the module bound (0 when the fixture itself failed).
     */
    std::uint16_t startModule()
    {
        // A second cycle regenerates the SAME pid-derived paths, so the previous cleanup must
        // run BEFORE the new files exist -- destroying it after would delete them again.
        m_certificateCleanup.reset();
        const auto certificate = remoted::test::generateTestCertificate("rmt_admin_utest");
        if (!certificate)
        {
            ADD_FAILURE() << "could not generate a throwaway TLS certificate";
            return 0;
        }
        m_certificateCleanup = std::make_unique<remoted::test::ScratchFileCleanup>(
            std::vector<std::string> {certificate->certPath, certificate->keyPath});

        remoted_module_config_t cfg {};
        cfg.port = findFreePort();
        EXPECT_NE(cfg.port, 0) << "could not obtain a free port to bind the module to";
        cfg.worker_node = false;
        std::snprintf(cfg.cluster_name, sizeof(cfg.cluster_name), "%s", "test-cluster");
        std::snprintf(cfg.certificate_path, sizeof(cfg.certificate_path), "%s", certificate->certPath.c_str());
        std::snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s", certificate->keyPath.c_str());

        remoted_module_start(remoted::test::testLogCallback, &cfg);
        return static_cast<std::uint16_t>(cfg.port);
    }

    /// A UDS HTTP client pointed at the admin socket, timeouts bounded so a broken server fails
    /// the test instead of hanging it. See vdClient.cpp for why set_address_family(AF_UNIX) is
    /// what actually makes httplib treat the path as a Unix socket.
    static std::unique_ptr<httplib::Client> makeAdminClient()
    {
        auto client = std::make_unique<httplib::Client>(kAdminSocketPath);
        client->set_address_family(AF_UNIX);
        client->set_connection_timeout(5, 0);
        client->set_read_timeout(5, 0);
        client->set_write_timeout(5, 0);
        return client;
    }

private:
    std::unique_ptr<remoted::test::ScratchFileCleanup> m_certificateCleanup;
};

// GET / answers the liveness probe inline, and the socket itself carries the contract: the
// fixed relative path and the explicit 0660 mode (bind applies the umask; the library chmods).
TEST_F(AdminServerTest, GetRootAnswersTheLivenessProbe)
{
    startModule();

    struct stat socketStat
    {
    };
    ASSERT_EQ(::stat(kAdminSocketPath, &socketStat), 0) << "admin socket was not bound at the fixed path";
    EXPECT_TRUE(S_ISSOCK(socketStat.st_mode));
    EXPECT_EQ(socketStat.st_mode & 0777U, 0660U);

    const auto client = makeAdminClient();
    const auto response = client->Get("/");
    ASSERT_TRUE(response) << "GET / failed: " << httplib::to_string(response.error());
    EXPECT_EQ(response->status, 200);
    EXPECT_NE(response->body.find(R"("status":"ok")"), std::string::npos) << response->body;
    EXPECT_NE(response->body.find(R"("module":"remoted_module")"), std::string::npos) << response->body;
    EXPECT_EQ(response->get_header_value("Content-Type"), "application/json");
    // The injected identity of a NEW server with no prior wire contract.
    EXPECT_EQ(response->get_header_value("Server"), "wazuh-remoted");
}

// GET /metrics dumps the module's whole registry: the E6a families (remoted.control.*,
// remoted.scanvd.*) exist from facade construction -- no traffic needed -- and the admin
// server's own transport diagnostics ride along as remoted.admin.server.* pulls (U10).
TEST_F(AdminServerTest, GetMetricsDumpsTheModuleFamilies)
{
    startModule();

    const auto client = makeAdminClient();
    const auto response = client->Get("/metrics");
    ASSERT_TRUE(response) << "GET /metrics failed: " << httplib::to_string(response.error());
    EXPECT_EQ(response->status, 200);
    EXPECT_EQ(response->get_header_value("Content-Type"), "application/json");
    EXPECT_NE(response->body.find(R"("name":"remoted")"), std::string::npos) << response->body;
    EXPECT_NE(response->body.find("remoted.control.startup"), std::string::npos) << response->body;
    EXPECT_NE(response->body.find("remoted.scanvd.requests.total"), std::string::npos) << response->body;
    EXPECT_NE(response->body.find("remoted.admin.server.sessions.live"), std::string::npos) << response->body;
}

// Routing is exact-match: an unknown path is a 404, and a known path with the wrong verb is a
// 405 (naming the allowed one) rather than a 404 -- the distinction the library promises.
TEST_F(AdminServerTest, UnknownRouteAnswers404AndWrongVerb405)
{
    startModule();

    const auto client = makeAdminClient();
    const auto unknown = client->Get("/stats");
    ASSERT_TRUE(unknown) << "GET /stats failed: " << httplib::to_string(unknown.error());
    EXPECT_EQ(unknown->status, 404);

    const auto wrongVerb = client->Post("/metrics", "", "application/json");
    ASSERT_TRUE(wrongVerb) << "POST /metrics failed: " << httplib::to_string(wrongVerb.error());
    EXPECT_EQ(wrongVerb->status, 405);
    EXPECT_EQ(wrongVerb->get_header_value("Allow"), "GET");
}

// The owner's policy on a failed admin bind: WARN and CONTINUE. A regular file squatting the
// fixed path makes the bind fail deterministically (the library refuses to unlink a non-socket:
// a typo'd path must not delete an operator's file), and the module -- public HTTPS listener
// included -- must come up regardless, with the squatter left untouched.
TEST_F(AdminServerTest, AdminBindFailureOnlyWarnsAndTheModuleKeepsServing)
{
    {
        std::ofstream squatter {kAdminSocketPath};
        squatter << "not a socket";
    }

    std::uint16_t port = 0;
    EXPECT_NO_THROW(port = startModule());

    EXPECT_TRUE(std::filesystem::is_regular_file(kAdminSocketPath));
    EXPECT_TRUE(publicListenerAccepts(port)) << "the public HTTPS listener must be unaffected";
    // The failure must be visible to the operator, as a WARN naming the admin server. (This
    // holds regardless of which suite installed the shared process-wide sink first: they all
    // pass the same testLogCallback -- see testLogRecorder.hpp.)
    EXPECT_TRUE(remoted::test::LogRecorder::waitForMessageContaining("remoted admin server failed to start"));

    // And the clean stop of a module whose admin plane never came up stays a clean stop.
    remoted_module_stop();
    EXPECT_TRUE(std::filesystem::is_regular_file(kAdminSocketPath));
}

// A clean stop() unlinks the socket (inode-guarded teardown) within the module's stop budget,
// and a restart cycle brings the whole admin plane back -- including the transport-diagnostics
// pulls, which are registered exactly once per process and must survive re-registration being
// skipped on the second start.
TEST_F(AdminServerTest, StopUnlinksTheSocketAndARestartBringsItBack)
{
    startModule();
    ASSERT_TRUE(std::filesystem::exists(kAdminSocketPath));

    remoted_module_stop();
    EXPECT_FALSE(std::filesystem::exists(kAdminSocketPath));

    startModule();
    const auto client = makeAdminClient();
    const auto response = client->Get("/metrics");
    ASSERT_TRUE(response) << "GET /metrics after restart failed: " << httplib::to_string(response.error());
    EXPECT_EQ(response->status, 200);
    EXPECT_NE(response->body.find("remoted.admin.server.sessions.live"), std::string::npos) << response->body;
}
