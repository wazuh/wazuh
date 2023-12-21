/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socketDBWrapper_test.hpp"
#include "json.hpp"
#include "socketDBWrapper.hpp"

// temp header
#include "wazuhDBQueryBuilder.hpp"
#include <chrono>
#include <thread>

TEST_F(SocketDBWrapperTest, EmptyTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {""};

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    // The exception captured here is the timeout
    EXPECT_THROW(socketDBWrapper.query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, ErrorTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(err Things happened)"};

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    EXPECT_THROW(socketDBWrapper.query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, UnknownTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(unk Things happened)"};

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    EXPECT_THROW(socketDBWrapper.query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, IgnoreTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(ign Things happened)"};

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    EXPECT_THROW(socketDBWrapper.query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, DueTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(due {"field": "value1"})",
                                            R"(due {"field": "value2"})",
                                            R"(due {"field": "value3"})",
                                            R"(ok {"status":"SUCCESS"})"};

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    EXPECT_NO_THROW(socketDBWrapper.query(m_query, output));

    ASSERT_EQ(output[0].at("field"), "value1");
    ASSERT_EQ(output[1].at("field"), "value2");
    ASSERT_EQ(output[2].at("field"), "value3");
}

TEST_F(SocketDBWrapperTest, InvalidTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(Invalid)"};

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    EXPECT_THROW(socketDBWrapper.query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, TimeoutTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(ok [{"field": "value"}])"};
    m_sleepTime = DB_WRAPPER_QUERY_WAIT_TIME + 10;

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    EXPECT_THROW(socketDBWrapper.query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, OkTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(ok [{"field": "value"}])"};

    nlohmann::json output;
    SocketDBWrapper socketDBWrapper(TEST_SOCKET);
    EXPECT_NO_THROW(socketDBWrapper.query(m_query, output));

    ASSERT_EQ(output[0].at("field"), "value");
}

TEST_F(SocketDBWrapperTestNoSetUp, NoSocketTest)
{
    std::unique_ptr<SocketDBWrapper> socketDBWrapper;
    EXPECT_NO_THROW(socketDBWrapper = std::make_unique<SocketDBWrapper>(TEST_SOCKET));
    std::this_thread::sleep_for(std::chrono::seconds(2));
    EXPECT_NO_THROW(socketDBWrapper.reset());
}

TEST_F(SocketDBWrapperTestNoSetUp, NoSocketTestNoSleep)
{
    std::unique_ptr<SocketDBWrapper> socketDBWrapper;
    EXPECT_NO_THROW(socketDBWrapper = std::make_unique<SocketDBWrapper>(TEST_SOCKET));
    EXPECT_NO_THROW(socketDBWrapper.reset());
}
