#include <wdb/wdb.hpp>

#include <gtest/gtest.h>

using namespace wazuhdb;

TEST(wdb_connector, init)
{
    ASSERT_NO_THROW(WazuhDB());
    ASSERT_NO_THROW(WazuhDB("/dummy/path"));
}

//TEST(wdb_connector, parseResultOK)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("ok test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::OK);
//}
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
