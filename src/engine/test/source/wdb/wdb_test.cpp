#include <wdb/wdb.hpp>

#include <gtest/gtest.h>

using namespace wazuhdb;

TEST(wdb_connector, init)
{
    ASSERT_NO_THROW(WazuhDB());
    ASSERT_NO_THROW(WazuhDB("/dummy/path"));
}

TEST(wdb_connector, parseResult)
{
    WazuhDB wdb {};
    char* payload = nullptr;
    char* message = strdup("ok test payload");

    auto retval = wdb.parseResult(message, &payload);
    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::OK);
}
