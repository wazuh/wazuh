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
#include <chrono>
#include <thread>

TEST_F(SocketDBWrapperTest, EmptyTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {" "};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, ErrorTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(err Things happened)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, UnknownTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(unk Things happened)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, IgnoreTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(ign Things happened)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, DueTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(due {"field": "value1"})",
                                            R"(due {"field": "value2"})",
                                            R"(due {"field": "value3"})",
                                            R"(ok {"status":"SUCCESS"})"};

    nlohmann::json output;
    EXPECT_NO_THROW(SocketDBWrapper::instance().query(m_query, output));

    ASSERT_EQ(output[0].at("field"), "value1");
    ASSERT_EQ(output[1].at("field"), "value2");
    ASSERT_EQ(output[2].at("field"), "value3");
}

TEST_F(SocketDBWrapperTest, InvalidTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(Invalid)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query, output), std::exception);
}

TEST_F(SocketDBWrapperTest, OkTest)
{
    m_query = "SELECT * FROM test_table;";
    m_responses = std::vector<std::string> {R"(ok [{"field": "value"}])"};

    nlohmann::json output;
    EXPECT_NO_THROW(SocketDBWrapper::instance().query(m_query, output));

    ASSERT_EQ(output[0].at("field"), "value");
}

TEST_F(SocketDBWrapperTestNoSetUp, NoSocketTest)
{
    SocketDBWrapper::instance();
    std::this_thread::sleep_for(std::chrono::seconds(2));
    EXPECT_NO_THROW(SocketDBWrapper::instance().teardown());
}

TEST_F(SocketDBWrapperTestNoSetUp, NoSocketTestNoSleep)
{
    SocketDBWrapper::instance();
    EXPECT_NO_THROW(SocketDBWrapper::instance().teardown());
}
