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
    m_query = {"SELECT * FROM test_table;"};
    m_responses = std::vector<std::string> {" "};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {}), std::exception);
}

TEST_F(SocketDBWrapperTest, ErrorTest)
{
    m_query = {"SELECT * FROM test_table;"};
    m_responses = std::vector<std::string> {R"(err Things happened)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {}), std::exception);
}

TEST_F(SocketDBWrapperTest, UnknownTest)
{
    m_query = {"SELECT * FROM test_table;"};
    m_responses = std::vector<std::string> {R"(unk Things happened)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {}), std::exception);
}

TEST_F(SocketDBWrapperTest, IgnoreTest)
{
    m_query = {"SELECT * FROM test_table;"};
    m_responses = std::vector<std::string> {R"(ign Things happened)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {}), std::exception);
}

TEST_F(SocketDBWrapperTest, DueTest)
{
    m_query = {"global get-all-agents context last_id -1",
               "global get-all-agents context last_id 1",
               "global get-all-agents context last_id 2",
               "global get-all-agents context last_id 3"};
    m_responses = std::vector<std::string> {
        R"(due [{"id": 1}])", R"(due [{"id": 2}])", R"(due [{"id": 3}])", R"(ok [{"id": 4}])"};

    nlohmann::json output;
    EXPECT_NO_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {"last_id", "id"}));

    ASSERT_EQ(output[0].at("id"), 1);
    ASSERT_EQ(output[1].at("id"), 2);
    ASSERT_EQ(output[2].at("id"), 3);
    ASSERT_EQ(output[3].at("id"), 4);
}

TEST_F(SocketDBWrapperTest, DueTestString)
{
    m_query = {"global get-all-agents context last_id -1",
               "global get-all-agents context last_id 1",
               "global get-all-agents context last_id 2",
               "global get-all-agents context last_id 3"};
    m_responses = std::vector<std::string> {
        R"(due [{"id": "1"}])", R"(due [{"id": "2"}])", R"(due [{"id": "3"}])", R"(ok [{"id": "4"}])"};

    nlohmann::json output;
    EXPECT_NO_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {"last_id", "id"}));

    ASSERT_EQ(output[0].at("id"), "1");
    ASSERT_EQ(output[1].at("id"), "2");
    ASSERT_EQ(output[2].at("id"), "3");
    ASSERT_EQ(output[3].at("id"), "4");
}

TEST_F(SocketDBWrapperTest, InvalidTest)
{
    m_query = {"SELECT * FROM test_table;"};
    m_responses = std::vector<std::string> {R"(Invalid)"};

    nlohmann::json output;
    EXPECT_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {}), std::exception);
}

TEST_F(SocketDBWrapperTest, OkTest)
{
    m_query = {"SELECT * FROM test_table;"};
    m_responses = std::vector<std::string> {R"(ok [{"field": "value"}])"};

    nlohmann::json output;
    EXPECT_NO_THROW(SocketDBWrapper::instance().query(m_query.front(), output, {}));

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
