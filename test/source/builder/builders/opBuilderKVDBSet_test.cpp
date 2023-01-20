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

class opBuilderKVDBSetTest : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME = "TEST_DB";
    static constexpr auto DB_DIR = "/tmp/";

    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager =
        std::make_shared<kvdb_manager::KVDBManager>(opBuilderKVDBSetTest::DB_DIR);

    virtual void SetUp() {}

    virtual void TearDown() { kvdbManager->unloadDB(DB_NAME); }
};

// Build ok
TEST_F(opBuilderKVDBSetTest, buildKVDBSetWithValues)
{
    auto tuple = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, "key", "value"});

    ASSERT_NO_THROW(KVDBSet(tuple, opBuilderKVDBSetTest::kvdbManager));
}

TEST_F(opBuilderKVDBSetTest, buildKVDBSetWithReferences)
{
    auto tuple = std::make_tuple<string, string, vector<string>>("/output", "", {"$SOME_DB_NAME", "$key", "$value"});

    ASSERT_THROW(KVDBSet(tuple, opBuilderKVDBSetTest::kvdbManager), std::runtime_error);
}

TEST_F(opBuilderKVDBSetTest, buildKVDBSetWrongAmountOfParametersError)
{
    auto tuple = std::make_tuple<string, string, vector<string>>("/output", "", {});

    ASSERT_THROW(KVDBSet(tuple, opBuilderKVDBSetTest::kvdbManager), std::runtime_error);

    tuple = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME});

    ASSERT_THROW(KVDBSet(tuple, opBuilderKVDBSetTest::kvdbManager), std::runtime_error);

    tuple = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, "key"});

    ASSERT_THROW(KVDBSet(tuple, opBuilderKVDBSetTest::kvdbManager), std::runtime_error);

    tuple = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, "key", "value", "unexpected"});

    ASSERT_THROW(KVDBSet(tuple, opBuilderKVDBSetTest::kvdbManager), std::runtime_error);
}

TEST_F(opBuilderKVDBSetTest, SetSuccessCases)
{
    Json eventTemplate {R"({
        "databaseName": "some_db_name",
        "fieldString": "value",
        "fieldIntNumber": 1,
        "fieldDoubleNumber": 69.007,
        "fieldObject": {"field": "value"},
        "fieldArray": ["value"],
        "fieldNull": null,
        "fieldTrue": true,
        "fieldFalse": false
    })"};

    auto event = std::make_shared<Json>(eventTemplate);
    auto expectedEvent = std::make_shared<Json>(eventTemplate);
    expectedEvent->setBool(true, "/output");

    string dbOp1 {DB_NAME};
    string keyOp1 {"some_key"};
    string valueOp1 {"some_value"};
    auto parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp1, valueOp1});
    const auto op1 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp2 {DB_NAME};
    string keyOp2 {"fieldString"};
    string valueOp2 {"$fieldString"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp2, valueOp2});
    const auto op2 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp3 {DB_NAME};
    string keyOp3 {"fieldIntNumber"};
    string valueOp3 {"$fieldIntNumber"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp3, valueOp3});
    const auto op3 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp4 {DB_NAME};
    string keyOp4 {"fieldObject"};
    string valueOp4 {"$fieldObject"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp4, valueOp4});
    const auto op4 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp5 {DB_NAME};
    string keyOp5 {"fieldArray"};
    string valueOp5 {"$fieldArray"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp5, valueOp5});
    const auto op5 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp6 {DB_NAME};
    string keyOp6 {"fieldNull"};
    string valueOp6 {"$fieldNull"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp6, valueOp6});
    const auto op6 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp7 {DB_NAME};
    string keyOp7 {"fieldDoubleNumber"};
    string valueOp7 {"$fieldDoubleNumber"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp7, valueOp7});
    const auto op7 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp8 {DB_NAME};
    string keyOp8 {"fieldTrue"};
    string valueOp8 {"$fieldTrue"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp8, valueOp8});
    const auto op8 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    string dbOp9 {DB_NAME};
    string keyOp9 {"fieldFalse"};
    string valueOp9 {"$fieldFalse"};
    parameters = std::make_tuple<string, string, vector<string>>("/output", "", {DB_NAME, keyOp9, valueOp9});
    const auto op9 = getOpBuilderKVDBSet(kvdbManager)(parameters);

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    auto rawValue = kvdbManager->getRawValue(DB_NAME, keyOp1);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(), fmt::format(R"("{}")", valueOp1).c_str());

    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp2);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(),
                 expectedEvent->getJson(Json::formatJsonPath(keyOp2)).value().str().c_str());

    // TODO: fix this
    result = op3->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp3);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(),
                 expectedEvent->getJson(Json::formatJsonPath(keyOp3)).value().str().c_str());

    result = op4->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp4);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(),
                 expectedEvent->getJson(Json::formatJsonPath(keyOp4)).value().str().c_str());

    result = op5->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp5);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(),
                 expectedEvent->getJson(Json::formatJsonPath(keyOp5)).value().str().c_str());

    result = op6->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp6);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(), "null");

    // TODO: fix this
    result = op7->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp7);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(),
                 expectedEvent->getJson(Json::formatJsonPath(keyOp7)).value().str().c_str());

    result = op8->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp8);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(),
                 expectedEvent->getJson(Json::formatJsonPath(keyOp8)).value().str().c_str());

    result = op9->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
    rawValue = kvdbManager->getRawValue(DB_NAME, keyOp9);
    if (const auto err = std::get_if<base::Error>(&rawValue))
    {
        throw std::runtime_error(err->message);
    }
    ASSERT_STREQ(std::get<string>(rawValue).c_str(),
                 expectedEvent->getJson(Json::formatJsonPath(keyOp9)).value().str().c_str());
}

} // namespace
