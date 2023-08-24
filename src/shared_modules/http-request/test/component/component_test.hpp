/*
 * Wazuh URLRequest test component
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _COMPONENT_TEST_H
#define _COMPONENT_TEST_H

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <memory>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#include "httplib.h"
#pragma GCC diagnostic pop

#include "HTTPRequest.hpp"

/**
 * @brief This class is a simple HTTP server that provides a simple interface to perform HTTP requests.
 */
namespace
{
class FakeServer final
{
private:
    httplib::Server m_server;
    std::thread m_thread;

public:
    FakeServer()
        : m_thread(&FakeServer::run, this)
    {
        // Wait until server is ready
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    ~FakeServer()
    {
        m_server.stop();
        m_thread.join();
    }

    /**
     * @brief This method is used to start the server.
     */
    void run()
    {
        m_server.Get("/",
                     [](const httplib::Request& /*req*/, httplib::Response& res)
                     { res.set_content("Hello World!", "text/json"); });

        m_server.Get("/redirect",
                     [](const httplib::Request& /*req*/, httplib::Response& res)
                     { res.set_redirect("http://localhost:44441/", 301); });

        m_server.Post(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Put(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Delete(R"(/(\d+))",
                        [](const httplib::Request& req, httplib::Response& res)
                        { res.set_content(req.matches[1], "text/json"); });

        m_server.set_keep_alive_max_count(1);
        m_server.listen("localhost", 44441);
    }
};
} // namespace

/**
 * @brief Class to test HTTPRequest class.
 */
class ComponentTest : public ::testing::Test
{
protected:
    /**
     * @brief This variable is used as a flag to indicate if all the callbacks have been called.
     */
    bool m_callbackComplete = false;
    virtual ~ComponentTest() = default;
    /**
     * @brief This method is called before each test to initialize the test environment.
     */
    void SetUp() override
    {
        m_callbackComplete = false;
    }

    /**
     * @brief This variable is used to store the server instance.
     */
    inline static std::unique_ptr<FakeServer> fakeFileServer;

    /**
     * @brief This method is called before each test to initialize the test environment.
     */
    static void SetUpTestSuite()
    {
        if (!fakeFileServer)
        {
            fakeFileServer = std::make_unique<FakeServer>();
        }
    }

    /**
     * @brief This method is called after each test to cleanup the test environment.
     */
    static void TearDownTestSuite()
    {
        fakeFileServer.reset();
    }
};

/**
 * @brief Class to test HTTPRequest class.
 */
class ComponentTestInterface : public ComponentTest
{
protected:
    ComponentTestInterface() = default;
    virtual ~ComponentTestInterface() = default;
};

/**
 * @brief Class to test HTTPRequest class.
 */
class ComponentTestInternalParameters : public ComponentTest
{
protected:
    ComponentTestInternalParameters() = default;
    virtual ~ComponentTestInternalParameters() = default;
};

#endif // _COMPONENT_TEST_H
