#include <wdb/wdb.hpp>

#include <thread>

#include <gtest/gtest.h>
#include <logging/logging.hpp>

#include "socketAuxiliarFunctions.hpp"
#include "unixSocketInterface.hpp"

using namespace wazuhdb;

constexpr const char* TEST_MESSAGE = "Test Message to be queried";
constexpr const char* TEST_RESPONSE = "Test Response to be received";
constexpr const char* TEST_DUMMY_PATH = "/dummy/path";

TEST(wdb_connector, Init)
{
    ASSERT_NO_THROW(WazuhDB());
    ASSERT_NO_THROW(WazuhDB(TEST_DUMMY_PATH));
}

TEST(wdb_connector, ConnectErrorInexistentSocket)
{
    auto wdb = WazuhDB(TEST_DUMMY_PATH);
    ASSERT_THROW(wdb.connect(), std::runtime_error);
}

TEST(wdb_connector, ConnectErrorNotSocket)
{
    auto wdb = WazuhDB("/");
    ASSERT_THROW(wdb.connect(), std::runtime_error);
}

TEST(wdb_connector, Connect)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    auto wdb = WazuhDB(TEST_SOCKET_PATH);
    ASSERT_NO_THROW(wdb.connect());

    close(serverSocketFD);
}

TEST(wdb_connector, connectManyTimes)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    auto wdb = WazuhDB(TEST_SOCKET_PATH);
    ASSERT_NO_THROW(wdb.connect());
    const int clientRemoteI = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemoteI, 0);
    ASSERT_NO_THROW(wdb.connect());
    const int clientRemoteII = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemoteII, 0);
    ASSERT_NO_THROW(wdb.connect());
    const int clientRemoteIII = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemoteIII, 0);

    close(serverSocketFD);
    close(clientRemoteI);
    close(clientRemoteII);
    close(clientRemoteIII);
}

TEST(wdb_query, EmptyString)
{
    auto wdb = WazuhDB();

    // Disable warning logs for this test
    const auto logLevel = fmtlog::getLogLevel();
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Error));

    ASSERT_STREQ(wdb.query("").c_str(), "");

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level
}

TEST(wdb_query, TooLongString)
{

    char msg[socketinterface::MSG_MAX_SIZE + 2] {};

    memset(msg, 'x', socketinterface::MSG_MAX_SIZE + 1);

    auto wdb = WazuhDB();

    // Disable warning logs for this test
    const auto logLevel = fmtlog::getLogLevel();
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Error));

    ASSERT_STREQ(wdb.query(msg).c_str(), "");

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level
}

TEST(wdb_query, ConnectAndQuery)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    auto wdb = WazuhDB(TEST_SOCKET_PATH);
    ASSERT_NO_THROW(wdb.connect());

    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    socketinterface::sendMsg(clientRemote, TEST_RESPONSE);

    ASSERT_STREQ(wdb.query(TEST_MESSAGE).c_str(), TEST_RESPONSE);
    ASSERT_STREQ(socketinterface::recvString(clientRemote).c_str(), TEST_MESSAGE);

    close(clientRemote);
    close(serverSocketFD);
}

// TODO: This does not work, but it should.
TEST(wdb_query, SendQueryWithoutConnect)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    auto wdb = WazuhDB(TEST_SOCKET_PATH);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        socketinterface::recvString(clientRemote).c_str();
        socketinterface::sendMsg(clientRemote, TEST_RESPONSE);
        close(clientRemote);
    });

    ASSERT_STREQ(wdb.query(TEST_MESSAGE).c_str(), TEST_RESPONSE);

    t.join();
    close(serverSocketFD);
}

TEST(wdb_parserResult, OkWithPayload)
{
    WazuhDB wdb {};

    auto retval = wdb.parseResult("ok test payload");
    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_TRUE(std::get<1>(retval).has_value());
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), "test payload");
}

//
// TEST(wdb_connector, parseResultDUE)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("due test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::DUE);
//}
//
// TEST(wdb_connector, parseResultERROR)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("err test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::ERROR);
//}
//
// TEST(wdb_connector, parseResultIGNORE)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("ign test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::IGNORE);
//}
//
// TEST(wdb_connector, parseResultUNKNOWN)
//{
//    WazuhDB wdb {};
//    char* payload = nullptr;
//    char* message = strdup("xyz test payload");
//
//    auto retval = wdb.parseResult(message, &payload);
//    ASSERT_EQ(retval, wazuhdb::QueryResultCodes::UNKNOWN);
//}
//
