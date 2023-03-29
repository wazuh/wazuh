#include <wdb/wdb.hpp>

#include <thread>

#include <gtest/gtest.h>
#include <testsCommon.hpp>

#include "socketAuxiliarFunctions.hpp"

using namespace wazuhdb;

constexpr const char* TEST_MESSAGE {"Test Message to be queried"};
constexpr const char* TEST_PAYLOAD {"Test Query Response Payload"};
constexpr const char* TEST_RESPONSE {"Test Response to be received"};
constexpr const char* TEST_DUMMY_PATH {"/dummy/path"};

class wdb_connector : public ::testing::Test
{
protected:
    void SetUp() override { initLogging(); }

    void TearDown() override {}
};

class wdb_query : public ::testing::Test
{
protected:
    void SetUp() override { initLogging(); }

    void TearDown() override {}
};

class wdb_tryQuery : public ::testing::Test
{
protected:
    void SetUp() override { initLogging(); }

    void TearDown() override {}
};

class wdb_parseResult : public ::testing::Test
{
protected:
    void SetUp() override { initLogging(); }

    void TearDown() override {}
};

class wdb_tryQueryAndParseResult : public ::testing::Test
{
protected:
    void SetUp() override { initLogging(); }

    void TearDown() override {}
};

TEST_F(wdb_connector, Init)
{
    ASSERT_NO_THROW(WazuhDB());
    ASSERT_NO_THROW(WazuhDB(TEST_DUMMY_PATH));
}

TEST_F(wdb_connector, ConnectErrorInexistentSocket)
{
    auto wdb {WazuhDB(TEST_DUMMY_PATH)};
    ASSERT_THROW(wdb.connect(), std::runtime_error);
}

TEST_F(wdb_connector, ConnectErrorNotSocket)
{
    auto wdb {WazuhDB("/")};
    ASSERT_THROW(wdb.connect(), std::runtime_error);
}

TEST_F(wdb_connector, Connect)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};
    ASSERT_NO_THROW(wdb.connect());

    close(serverSocketFD);
}

TEST_F(wdb_connector, connectManyTimes)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};
    ASSERT_NO_THROW(wdb.connect());
    const int clientRemoteI {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemoteI, 0);
    ASSERT_NO_THROW(wdb.connect());
    const int clientRemoteII {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemoteII, 0);
    ASSERT_NO_THROW(wdb.connect());
    const int clientRemoteIII {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemoteIII, 0);

    close(serverSocketFD);
    close(clientRemoteI);
    close(clientRemoteII);
    close(clientRemoteIII);
}

TEST_F(wdb_query, EmptyString)
{
    auto wdb {WazuhDB()};

    ASSERT_STREQ(wdb.query("").c_str(), "");
}

TEST_F(wdb_query, TooLongString)
{

    auto wdb {WazuhDB()};

    std::vector<char> msg {};
    msg.resize(wdb.getQueryMaxSize() + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    ASSERT_STREQ(wdb.query(msg.data()).c_str(), "");
}

TEST_F(wdb_query, ConnectAndQuery)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};
    ASSERT_NO_THROW(wdb.connect());

    const int clientRemote {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemote, 0);

    testSendMsg(clientRemote, TEST_RESPONSE);

    ASSERT_STREQ(wdb.query(TEST_MESSAGE).c_str(), TEST_RESPONSE);
    ASSERT_STREQ(testRecvString(clientRemote, SOCK_STREAM).c_str(), TEST_MESSAGE);

    close(clientRemote);
    close(serverSocketFD);
}

TEST_F(wdb_query, SendQueryWithoutConnect)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            testRecvString(clientRemote, SOCK_STREAM).c_str();
            testSendMsg(clientRemote, TEST_RESPONSE);
            close(clientRemote);
        });

    ASSERT_STREQ(wdb.query(TEST_MESSAGE).c_str(), TEST_RESPONSE);

    t.join();
    close(serverSocketFD);
}

TEST_F(wdb_query, SendQueryConexionClosed)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            close(clientRemote);
        });

    ASSERT_THROW(wdb.query(TEST_MESSAGE), base::utils::socketInterface::RecoverableError);
    t.join();

    close(serverSocketFD);
}

TEST_F(wdb_tryQuery, SendQueryOK_firstAttemp)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    const int attempts {5};

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            testRecvString(clientRemote, SOCK_STREAM).c_str();
            testSendMsg(clientRemote, TEST_RESPONSE);
            close(clientRemote);
        });

    ASSERT_STREQ(wdb.tryQuery(TEST_MESSAGE, attempts).c_str(), TEST_RESPONSE);

    t.join();
    close(serverSocketFD);
}

TEST_F(wdb_tryQuery, SendQueryOK_retry)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            close(clientRemote);
            const int clientRemoteRetry {testAcceptConnection(serverSocketFD)};
            testRecvString(clientRemoteRetry, SOCK_STREAM).c_str();
            testSendMsg(clientRemoteRetry, TEST_RESPONSE);
            close(clientRemoteRetry);
        });

    ASSERT_STREQ(wdb.tryQuery(TEST_MESSAGE, 5).c_str(), TEST_RESPONSE);

    t.join();
    close(serverSocketFD);
}

TEST_F(wdb_tryQuery, SendQueryIrrecoverable)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            close(serverSocketFD);
            unlink(TEST_STREAM_SOCK_PATH.data());
            close(clientRemote);
        });

    // Empty string on error
    ASSERT_STREQ(wdb.tryQuery(TEST_MESSAGE, 5).c_str(), "");

    t.join();
}

TEST_F(wdb_parseResult, ParseResultOk)
{
    const auto message {"ok"};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultOkWithPayload)
{
    const auto message {std::string("ok") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultDue)
{
    const auto message {"due"};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::DUE);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultDueWithPayload)
{
    const auto message {std::string("due") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::DUE);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultError)
{
    const auto message {"err"};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::ERROR);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultErrorWithPayload)
{
    const auto message {std::string("err") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::ERROR);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultIgnore)
{
    const auto message {"ign"};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::IGNORE);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultIgnoreWithPayload)
{
    const auto message {std::string("ign") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};
    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::IGNORE);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultUnknown)
{
    const auto message {"xyz"};

    WazuhDB wdb {};

    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultUnknownWithPayload)
{
    const auto message {std::string("xyz") + " " + TEST_PAYLOAD};

    WazuhDB wdb {};

    auto retval {wdb.parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_tryQueryAndParseResult, SendQueryOK_firstAttemp_wopayload)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            testRecvString(clientRemote, SOCK_STREAM).c_str();
            testSendMsg(clientRemote, "ok");
            close(clientRemote);
        });

    auto retval {wdb.tryQueryAndParseResult(TEST_MESSAGE, 5)};
    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_FALSE(std::get<1>(retval));

    t.join();
    close(serverSocketFD);
}

TEST_F(wdb_tryQueryAndParseResult, SendQueryOK_retry_wpayload)
{

    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            close(clientRemote);
            const int clientRemoteRetry {testAcceptConnection(serverSocketFD)};
            testRecvString(clientRemoteRetry, SOCK_STREAM).c_str();
            testSendMsg(clientRemoteRetry, "ok payload");
            close(clientRemoteRetry);
        });

    auto retval {wdb.tryQueryAndParseResult(TEST_MESSAGE, 5)};
    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), "payload");

    t.join();
    close(serverSocketFD);
}

TEST_F(wdb_tryQueryAndParseResult, SendQueryIrrecoverable)
{
    // Create server
    const int serverSocketFD {testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    auto wdb {WazuhDB(TEST_STREAM_SOCK_PATH)};

    std::thread t(
        [&]()
        {
            const int clientRemote {testAcceptConnection(serverSocketFD)};
            close(serverSocketFD);
            unlink(TEST_STREAM_SOCK_PATH.data());
            close(clientRemote);
        });

    // Empty string on error
    auto retval {wdb.tryQueryAndParseResult(TEST_MESSAGE, 5)};
    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));

    t.join();
}
