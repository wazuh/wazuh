#include <wdb/wdb.hpp>

#include <gtest/gtest.h>

using namespace wazuhdb;

TEST(wdb_connector, init)
{
    ASSERT_NO_THROW(WazuhDB());
    ASSERT_NO_THROW(WazuhDB("/dummy/path"));
}

TEST(wdb_connector, connectErrorInexistentSocket)
{
    auto wdb = WazuhDB("/dummy/path");
    ASSERT_THROW(wdb.connect(), std::runtime_error);
}

TEST(wdb_connector, connectErrorNotSocket)
{
    auto wdb = WazuhDB("/");
    ASSERT_THROW(wdb.connect(), std::runtime_error);
}

TEST(wdb_parserResult, okWithPayload)
{
    WazuhDB wdb {};


    auto retval = wdb.parseResult("ok test payload");
    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_TRUE(std::get<1>(retval).has_value());
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), "test payload");
}
//
//TEST(wdb_connector, parseResultDUE)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("due test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::DUE);
//}
//
//TEST(wdb_connector, parseResultERROR)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("err test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::ERROR);
//}
//
//TEST(wdb_connector, parseResultIGNORE)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("ign test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::IGNORE);
//}
//
//TEST(wdb_connector, parseResultUNKNOWN)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("xyz test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::UNKNOWN);
//}
//
