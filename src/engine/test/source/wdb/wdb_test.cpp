#include <wdb/wdb.hpp>

#include <thread>

#include <gtest/gtest.h>
#include <logging/logging.hpp>

#include "socketAuxiliarFunctions.hpp"
#include "unixSocketInterface.hpp"

using namespace wazuhdb;

constexpr const char* TEST_MESSAGE = "Test Message to be queried";
constexpr const char* TEST_PAYLOAD = "Test Query Response Payload";
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

    // Disable warning logs for this test
    const auto logLevel = fmtlog::getLogLevel();
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Error));

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

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level

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

TEST(wdb_query, SendQueryConexionClosed)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    auto wdb = WazuhDB(TEST_SOCKET_PATH);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        close(clientRemote);
    });

    ASSERT_THROW(wdb.query(TEST_MESSAGE), socketinterface::RecoverableError);
    t.join();

    close(serverSocketFD);
}


TEST(wdb_tryQuery, SendQueryOK_firstAttemp)
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

    ASSERT_STREQ(wdb.tryQuery(TEST_MESSAGE, 5).c_str(), TEST_RESPONSE);

    t.join();
    close(serverSocketFD);
}

TEST(wdb_tryQuery, SendQueryOK_retry)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    auto wdb = WazuhDB(TEST_SOCKET_PATH);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        close(clientRemote);
        const int clientRemoteRetry = testAcceptConnection(serverSocketFD);
        socketinterface::recvString(clientRemoteRetry).c_str();
        socketinterface::sendMsg(clientRemoteRetry, TEST_RESPONSE);
        close(clientRemoteRetry);
    });

    // Disable logs for this test
    const auto logLevel = fmtlog::getLogLevel();
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Error));

    ASSERT_STREQ(wdb.tryQuery(TEST_MESSAGE, 5).c_str(), TEST_RESPONSE);

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level

    t.join();
    close(serverSocketFD);
}

TEST(wdb_tryQuery, SendQueryIrrecoverable)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    auto wdb = WazuhDB(TEST_SOCKET_PATH);

    std::thread t([&]() {
        const int clientRemote = testAcceptConnection(serverSocketFD);
        close(serverSocketFD);
        unlink(TEST_SOCKET_PATH.data());
        close(clientRemote);
    });

    // Disable logs for this test
    const auto logLevel = fmtlog::getLogLevel();
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));

    // Empty string on error
    ASSERT_STREQ(wdb.tryQuery(TEST_MESSAGE, 5).c_str(), "");

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level

    t.join();

}

TEST(wdb_parseResult, ParseResultOk)
{
    const auto message {"ok"};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST(wdb_parseResult, ParseResultOkWithPayload)
{
    const auto message {std::string("ok") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST(wdb_parseResult, ParseResultDue)
{
    const auto message {"due"};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::DUE);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST(wdb_parseResult, ParseResultDueWithPayload)
{
    const auto message {std::string("due") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::DUE);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST(wdb_parseResult, ParseResultError)
{
    const auto message {"err"};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::ERROR);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST(wdb_parseResult, ParseResultErrorWithPayload)
{
    const auto message {std::string("err") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::ERROR);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST(wdb_parseResult, ParseResultIgnore)
{
    const auto message {"ign"};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::IGNORE);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST(wdb_parseResult, ParseResultIgnoreWithPayload)
{
    const auto message {std::string("ign") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::IGNORE);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST(wdb_parseResult, ParseResultUnknown)
{
    const auto message {"xyz"};

    WazuhDB wdb {};

    // Disable logs for this test
    const auto logLevel = fmtlog::getLogLevel();
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));

    auto retval = wdb.parseResult(message);

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST(wdb_parseResult, ParseResultUnknownWithPayload)
{
    const auto message {std::string("xyz") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};

    // Disable logs for this test
    const auto logLevel = fmtlog::getLogLevel();
    fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));

    auto retval = wdb.parseResult(message);

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));

    fmtlog::setLogLevel(fmtlog::LogLevel(logLevel)); // Restore log level
}
