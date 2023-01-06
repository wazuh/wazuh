/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <any>
#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <json/json.hpp>

#include <baseTypes.hpp>
#include <kvdb/kvdbManager.hpp>
#include <opBuilderKVDB.hpp>

namespace
{
using namespace base;
using namespace builder::internals::builders;

using json::Json;
using std::string;
using std::vector;

class opBuilderKVDBDeleteTest : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_1 = "TEST_DB_1";
    static constexpr auto DB_NAME_2 = "TEST_DB_2";
    static constexpr auto DB_REF_NAME = "$test_db_name";
    static constexpr auto DB_DIR = "/tmp/";

    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager =
        std::make_shared<kvdb_manager::KVDBManager>(opBuilderKVDBDeleteTest::DB_DIR);

    virtual void SetUp() {}

    virtual void TearDown() {}
};

// Build ok
TEST_F(opBuilderKVDBDeleteTest, buildKVDBDeleteWithValue)
{
    auto tuple = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME_1});

    ASSERT_NO_THROW(KVDBDelete(tuple, opBuilderKVDBDeleteTest::kvdbManager));
}

TEST_F(opBuilderKVDBDeleteTest, buildKVDBDeleteWithReference)
{
    auto tuple = std::make_tuple<string, string, vector<string>>("/output", "", {DB_REF_NAME});

    ASSERT_NO_THROW(KVDBDelete(tuple, opBuilderKVDBDeleteTest::kvdbManager));
}

TEST_F(opBuilderKVDBDeleteTest, buildKVDBDeleteWrongAmountOfParametersError)
{
    auto tuple = std::make_tuple<string, string, vector<string>>("/output", "", {});

    ASSERT_THROW(KVDBDelete(tuple, opBuilderKVDBDeleteTest::kvdbManager), std::runtime_error);

    tuple = std::make_tuple<string, string, vector<string>>("/output", "", {DB_REF_NAME, "unexpected_key"});

    ASSERT_THROW(KVDBDelete(tuple, opBuilderKVDBDeleteTest::kvdbManager), std::runtime_error);

    tuple = std::make_tuple<string, string, vector<string>>(
        "/output", "", {DB_REF_NAME, "unexpected_key", "unexpected_value"});

    ASSERT_THROW(KVDBDelete(tuple, opBuilderKVDBDeleteTest::kvdbManager), std::runtime_error);
}

TEST_F(opBuilderKVDBDeleteTest, DeleteSuccessCases)
{

    auto event = std::make_shared<Json>(R"({})");
    auto expectedEvent = std::make_shared<Json>(R"({})");
    expectedEvent->setBool(true, "/output");

    {
        auto res = kvdbManager->getHandler(DB_NAME_1, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    }

    auto parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME_1});
    const auto op1 = getOpBuilderKVDBDelete(kvdbManager)(parameters);

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);

    {
        auto res = kvdbManager->getHandler(DB_NAME_1, false);
        ASSERT_TRUE(std::holds_alternative<base::Error>(res));
    }

    auto eventTemplate = std::string(R"({"test_db_name": ")") + DB_NAME_2 + R"("})";
    event = std::make_shared<Json>(eventTemplate.c_str());
    expectedEvent = std::make_shared<Json>(eventTemplate.c_str());
    expectedEvent->setBool(true, "/output");

    {
        auto res = kvdbManager->getHandler(DB_NAME_2, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    }

    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_REF_NAME});
    const auto op2 = getOpBuilderKVDBDelete(kvdbManager)(parameters);

    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);

    {
        auto res = kvdbManager->getHandler(DB_NAME_2, false);
        ASSERT_TRUE(std::holds_alternative<base::Error>(res));
    }
}

} // namespace
