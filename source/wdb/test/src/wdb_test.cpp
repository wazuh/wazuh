#include <wdb/wdbManager.hpp>

#include <thread>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>

using namespace wazuhdb;
using namespace sockiface::mocks;

constexpr const char* TEST_MESSAGE {"Test Message to be queried"};
constexpr const char* TEST_PAYLOAD {"Test Query Response Payload"};
constexpr const char* TEST_RESPONSE {"Test"};
constexpr const char* TEST_DUMMY_PATH {"/dummy/path"};

std::tuple<std::shared_ptr<IWDBHandler>, std::shared_ptr<MockSockHandler>> getWDBHandler()
{
    auto sockFactoryPtr = std::make_shared<MockSockFactory>();
    auto sockHandlerPtr = std::make_shared<MockSockHandler>();
    auto& sockFactory = *sockFactoryPtr;
    EXPECT_CALL(sockFactory, getHandler(sockiface::ISockHandler::Protocol::STREAM, TEST_DUMMY_PATH))
        .WillOnce(testing::Return(sockHandlerPtr));
    WDBManager wdbManager(TEST_DUMMY_PATH, sockFactoryPtr);
    return {wdbManager.connection(), sockHandlerPtr};
}

class wdb_connector : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class wdb_query : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class wdb_tryQuery : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class wdb_parseResult : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

class wdb_tryQueryAndParseResult : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override {}
};

TEST_F(wdb_connector, Init)
{
    ASSERT_NO_THROW(getWDBHandler());
}

TEST_F(wdb_connector, ConnectError)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, socketConnect())
        .WillOnce(testing::Throw(std::runtime_error("Error connecting to socket")));
    ASSERT_THROW(wdb->connect(), std::runtime_error);
}

TEST_F(wdb_connector, Connect)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, socketConnect()).Times(1);
    ASSERT_NO_THROW(wdb->connect());
}

TEST_F(wdb_connector, connectManyTimes)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, socketConnect()).Times(3);
    ASSERT_NO_THROW(wdb->connect());
    ASSERT_NO_THROW(wdb->connect());
    ASSERT_NO_THROW(wdb->connect());
}

TEST_F(wdb_query, EmptyString)
{
    auto [wdb, _] = getWDBHandler();

    ASSERT_STREQ(wdb->query("").c_str(), "");
}

TEST_F(wdb_query, TooLongString)
{
    auto maxMsgSize = 1;
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize())
        .WillOnce(testing::Return(maxMsgSize))
        .WillOnce(testing::Return(maxMsgSize));

    std::vector<char> msg {};
    msg.resize(maxMsgSize + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    ASSERT_STREQ(wdb->query(msg.data()).c_str(), "");
}

TEST_F(wdb_query, SendAndResponse)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize()).WillOnce(testing::Return(1024));
    EXPECT_CALL(*MockSockHandler, sendMsg(testing::_))
        .WillOnce(testing::Return(successSendMsgRes()));
    EXPECT_CALL(*MockSockHandler, recvMsg()).WillOnce(testing::Return(recvMsgRes("Test")));

    ASSERT_STREQ(wdb->query(TEST_MESSAGE).c_str(), TEST_RESPONSE);
}

TEST_F(wdb_query, SendAndRecoverableError)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize()).WillOnce(testing::Return(1024));
    EXPECT_CALL(*MockSockHandler, sendMsg(testing::_))
        .WillOnce(testing::Throw(sockiface::ISockHandler::RecoverableError("Error sending message")));

    ASSERT_THROW(wdb->query(TEST_MESSAGE), sockiface::ISockHandler::RecoverableError);
}

TEST_F(wdb_tryQuery, RecoverAndSend)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, socketConnect()).Times(1);
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize()).WillOnce(testing::Return(1024)).WillOnce(testing::Return(1024));
    EXPECT_CALL(*MockSockHandler, sendMsg(testing::_))
        .WillOnce(testing::Throw(sockiface::ISockHandler::RecoverableError("Error sending message")))
        .WillOnce(testing::Return(successSendMsgRes()));
    EXPECT_CALL(*MockSockHandler, recvMsg()).WillOnce(testing::Return(recvMsgRes("Test")));

    ASSERT_STREQ(wdb->tryQuery(TEST_MESSAGE, 2).c_str(), TEST_RESPONSE);
}

TEST_F(wdb_tryQuery, SendAndIrrecoverableError)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize()).WillOnce(testing::Return(1024));
    EXPECT_CALL(*MockSockHandler, sendMsg(testing::_))
        .WillOnce(testing::Throw(std::runtime_error("Error sending message")));
    EXPECT_CALL(*MockSockHandler, socketDisconnect()).Times(1);

    // Empty string on error
    ASSERT_STREQ(wdb->tryQuery(TEST_MESSAGE, 1).c_str(), "");
}

TEST_F(wdb_parseResult, ParseResultOk)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {"ok"};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultOkWithPayload)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {std::string("ok") + " " + TEST_PAYLOAD};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultDue)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {"due"};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::DUE);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultDueWithPayload)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {std::string("due") + " " + TEST_PAYLOAD};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::DUE);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultError)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {"err"};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::ERROR);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultErrorWithPayload)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {std::string("err") + " " + TEST_PAYLOAD};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::ERROR);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultIgnore)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {"ign"};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::IGNORE);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultIgnoreWithPayload)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {std::string("ign") + " " + TEST_PAYLOAD};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::IGNORE);
    ASSERT_TRUE(std::get<1>(retval));
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), TEST_PAYLOAD);
}

TEST_F(wdb_parseResult, ParseResultUnknown)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {"xyz"};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_parseResult, ParseResultUnknownWithPayload)
{
    auto [wdb, _] = getWDBHandler();
    const auto message {std::string("xyz") + " " + TEST_PAYLOAD};

    auto retval {wdb->parseResult(message)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_tryQueryAndParseResult, SendQueryOK_firstAttemp_wopayload)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize()).WillOnce(testing::Return(1024));
    EXPECT_CALL(*MockSockHandler, sendMsg(testing::_))
        .WillOnce(testing::Return(successSendMsgRes()));
    EXPECT_CALL(*MockSockHandler, recvMsg()).WillOnce(testing::Return(recvMsgRes("ok")));

    auto retval {wdb->tryQueryAndParseResult(TEST_MESSAGE, 1)};

    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_FALSE(std::get<1>(retval));
}

TEST_F(wdb_tryQueryAndParseResult, SendQueryOK_retry_wpayload)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize()).WillOnce(testing::Return(1024)).WillOnce(testing::Return(1024));
    EXPECT_CALL(*MockSockHandler, sendMsg(testing::_))
        .WillOnce(testing::Throw(sockiface::ISockHandler::RecoverableError("test error")))
        .WillOnce(testing::Return(successSendMsgRes()));
    EXPECT_CALL(*MockSockHandler, recvMsg()).WillOnce(testing::Return(recvMsgRes("ok payload")));
    EXPECT_CALL(*MockSockHandler, socketConnect()).Times(1);

    auto retval {wdb->tryQueryAndParseResult(TEST_MESSAGE, 5)};
    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::OK);
    ASSERT_STREQ(std::get<1>(retval).value().c_str(), "payload");
}

TEST_F(wdb_tryQueryAndParseResult, SendQueryIrrecoverable)
{
    auto [wdb, MockSockHandler] = getWDBHandler();
    EXPECT_CALL(*MockSockHandler, getMaxMsgSize()).WillOnce(testing::Return(1024));
    EXPECT_CALL(*MockSockHandler, sendMsg(testing::_))
        .WillOnce(testing::Throw(std::runtime_error("test error")));
    EXPECT_CALL(*MockSockHandler, socketDisconnect()).Times(1);

    // Empty string on error
    auto retval {wdb->tryQueryAndParseResult(TEST_MESSAGE, 2)};
    ASSERT_EQ(std::get<0>(retval), QueryResultCodes::UNKNOWN);
    ASSERT_FALSE(std::get<1>(retval));
}
