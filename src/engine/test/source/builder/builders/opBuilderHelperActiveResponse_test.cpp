/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>
#include <wdb/wdb.hpp>

#include <logging/logging.hpp>

#include "opBuilderHelperActiveResponse.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace builder::internals::builders;
using namespace builder::internals::builders::ar;

using std::make_shared;
using std::make_tuple;
using std::string;
using std::vector;

const string targetField {"/result"};
const string arCreateHFName {"ar_create"};
const string arSendHFName {"ar_send"};

auto commandName {"dummy-command-name"};
auto location {"ALL"};
auto timeout {"100"};
auto extraArgsRef {"$_extra_args"};
const vector<string> arCreateCommonArguments {
    commandName, location, timeout, extraArgsRef};

TEST(opBuilderSendARTestSuite, Builder)
{
    auto tuple {make_tuple(targetField, arSendHFName, vector<string> {"query params"})};

    ASSERT_NO_THROW(opBuilderHelperSendAR(tuple));
}

TEST(opBuilderSendARTestSuite, BuilderNoParameterError)
{
    auto tuple {make_tuple(targetField, arSendHFName, vector<string> {})};

    ASSERT_THROW(opBuilderHelperSendAR(tuple), std::runtime_error);
}

TEST(opBuilderSendARTestSuite, Send)
{
    auto tuple {make_tuple(targetField, arSendHFName, vector<string> {"test\n123"})};
    auto op {opBuilderHelperSendAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {make_shared<json::Json>(R"({"agent_id": "007"})")};
    auto result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField));

    // Check received command on the AR's queue
    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "test\n123");

    close(serverSocketFD);
    unlink(AR_QUEUE_PATH);
}

TEST(opBuilderSendARTestSuite, SendFromReference)
{
    auto tuple {
        make_tuple(targetField, arSendHFName, vector<string> {"$wdb.query_params"})};
    auto op {opBuilderHelperSendAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto serverSocketFD = testBindUnixSocket(AR_QUEUE_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    auto event {
        make_shared<json::Json>(R"({"wdb": {"query_params": "reference_test"}})")};
    auto result {op(event)};
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->isBool(targetField));
    ASSERT_TRUE(result.payload()->getBool(targetField));

    // Check received command on the AR's queue
    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).c_str(), "reference_test");

    close(serverSocketFD);
    unlink(AR_QUEUE_PATH);
}

TEST(opBuilderSendARTestSuite, SendEmptyReferencedValueError)
{
    auto tuple {
        make_tuple(targetField, arSendHFName, vector<string> {"$wdb.query_params"})};
    auto op {opBuilderHelperSendAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {make_shared<json::Json>(R"({"wdb": {"query_params": ""}})")};
    auto result {op(event)};
    ASSERT_FALSE(result);
}

TEST(opBuilderSendARTestSuite, SendEmptyReferenceError)
{
    auto tuple {
        make_tuple(targetField, arSendHFName, vector<string> {"$wdb.query_params"})};
    auto op {opBuilderHelperSendAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event {make_shared<json::Json>(R"({"wdb": {"NO_query_params": "123"}})")};
    auto result {op(event)};
    ASSERT_FALSE(result);
}

string getExpectedResult(string commandName,
                         string location,
                         base::Event originalEvent,
                         string timeout = "",
                         string extraArgs = "")
{
    auto isAll {"ALL" == location};
    auto isLocal {"LOCAL" == location};
    auto isID {!location.empty()
               && std::find_if(location.begin(),
                               location.end(),
                               [](unsigned char c) { return !std::isdigit(c); })
                      == location.end()};
    string locationValue {};
    if (isAll)
    {
        locationValue = "all";
    }
    else if (isLocal)
    {
        locationValue = originalEvent->getString(AGENT_ID_PATH).value_or("");
    }
    else
    {
        locationValue = location;
    }

    string expectedResult {};

    auto firstLocationParam {isLocal ? 'R' : 'N'};
    auto secondLocationParam {isAll | isID ? 'S' : 'N'};

    expectedResult =
        string("(local_source) [] N") + firstLocationParam + secondLocationParam + " "
        + locationValue + " {\"version\":" + ar::SUPPORTED_VERSION + ",\"command\":\""
        + commandName + (timeout.empty() ? "0" : timeout)
        + "\",\"parameters\":{\"extra_args\":[" + extraArgs + "],\"alert\":"
        + originalEvent->str() + "},\"origin\":{\"module\":\"wazuh-engine\",\"name\":\""
        + ar::ORIGIN_NAME + "\"}}";

    return expectedResult;
}

class opBuilderHelperCreateARTestSuite : public ::testing::Test
{
protected:
    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

TEST_F(opBuilderHelperCreateARTestSuite, buildMinimal)
{
    const vector<string> arguments {commandName, location};

    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};

    ASSERT_NO_THROW(opBuilderHelperCreateAR(tuple));
}

TEST_F(opBuilderHelperCreateARTestSuite, buildWithTimeout)
{
    const vector<string> arguments {commandName, location, timeout};

    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};

    ASSERT_NO_THROW(opBuilderHelperCreateAR(tuple));
}

TEST_F(opBuilderHelperCreateARTestSuite, buildWithoutTimeoutWithExtraArgs)
{
    const vector<string> arguments {commandName, location, "", extraArgsRef};

    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};

    ASSERT_NO_THROW(opBuilderHelperCreateAR(tuple));
}

TEST_F(opBuilderHelperCreateARTestSuite, buildFull)
{
    const auto tuple {make_tuple(targetField, arCreateHFName, arCreateCommonArguments)};

    ASSERT_NO_THROW(opBuilderHelperCreateAR(tuple));
}

TEST_F(opBuilderHelperCreateARTestSuite, checkWrongParametersQttyLess)
{
    const vector<string> arguments {commandName};

    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};

    ASSERT_THROW(opBuilderHelperCreateAR(tuple), std::runtime_error);
}

TEST_F(opBuilderHelperCreateARTestSuite, checkWrongParametersQttyMore)
{
    const vector<string> arguments {
        commandName, "dummy-location", timeout, extraArgsRef, "unexpected-arg"};

    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};

    ASSERT_THROW(opBuilderHelperCreateAR(tuple), std::runtime_error);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithoutTimeoutWithoutExtraArgs)
{
    const vector<string> arguments {commandName, location};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {
        getExpectedResult(commandName, location, make_shared<json::Json>(originalEvent))};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithTimeoutWithoutExtraArgs)
{
    const vector<string> arguments {commandName, location, timeout};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult(
        commandName, location, make_shared<json::Json>(originalEvent), timeout)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithTimeoutWithEmptyExtraArgs)
{
    const vector<string> arguments {arCreateCommonArguments};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": []})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult(
        commandName, location, make_shared<json::Json>(originalEvent), timeout)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithoutTimeoutWithEmptyExtraArgs)
{
    const vector<string> arguments {commandName, location, "", extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": []})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {
        getExpectedResult(commandName, location, make_shared<json::Json>(originalEvent))};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithUnexistentExtraArgsReferenceError)
{
    const vector<string> arguments {commandName, location, "", extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithoutTimeoutWithExtraArgs)
{
    const vector<string> arguments {commandName, location, "", extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": ["test-arg","2"]})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult(commandName,
                                            location,
                                            make_shared<json::Json>(originalEvent),
                                            "",
                                            R"("test-arg","2")")};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithErroneousExtraArgsTypeErrorI)
{
    const vector<string> arguments {commandName, location, "", extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": "test-arg"})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithErroneousExtraArgsTypeErrorII)
{
    const vector<string> arguments {commandName, location, "", extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": 10})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithErroneousExtraArgsTypeErrorIII)
{
    const vector<string> arguments {commandName, location, "", extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": {"sub_field":[]}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventWithTimeoutWithExtraArgs)
{
    const auto tuple {make_tuple(targetField, arCreateHFName, arCreateCommonArguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": ["test-arg","2"]})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult(commandName,
                                            location,
                                            make_shared<json::Json>(originalEvent),
                                            timeout,
                                            R"("test-arg","2")")};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventExtraArgsNotStringsError)
{
    const auto tuple {make_tuple(targetField, arCreateHFName, arCreateCommonArguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "_extra_args": ["test-arg",2]})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventLocalLocationWithoutAgentIDError)
{
    const vector<string> arguments {commandName, "LOCAL"};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventUnexpectedLocationErrorI)
{
    const vector<string> arguments {commandName, "DUMMY"};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventUnexpectedLocationErrorII)
{
    const vector<string> arguments {commandName, "10X"};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventUnexpectedLocationErrorIII)
{
    const vector<string> arguments {commandName, "X10"};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventUnexpectedLocationErrorIV)
{
    const vector<string> arguments {commandName, "1X0"};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventLocalLocation)
{
    auto location {"LOCAL"};
    const vector<string> arguments {commandName, location};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "agent": {"id": "404"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {
        getExpectedResult(commandName, location, make_shared<json::Json>(originalEvent))};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventSpecificLocation)
{
    auto location {"404"};
    const vector<string> arguments {commandName, location};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {
        getExpectedResult(commandName, location, make_shared<json::Json>(originalEvent))};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventCommandNameFromReference)
{
    auto commandName {"$cmd"};
    const vector<string> arguments {commandName, location};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "cmd": "dummy-cmd"})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {
        getExpectedResult("dummy-cmd", location, make_shared<json::Json>(originalEvent))};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventCommandNameFromUnexistantReferenceError)
{
    auto commandName {"$cmd"};
    const vector<string> arguments {commandName, location};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventLocationFromReference)
{
    auto location {"$location"};
    const vector<string> arguments {commandName, location};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "location": "ALL"})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {
        getExpectedResult(commandName, "ALL", make_shared<json::Json>(originalEvent))};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventLocationFromUnexistantReferenceError)
{
    auto location {"$location"};
    const vector<string> arguments {commandName, location};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventTimeoutFromReference)
{
    const auto timeout {"$tout"};
    const vector<string> arguments {commandName, location, timeout};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "tout": "100"})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult(
        commandName, location, make_shared<json::Json>(originalEvent), "100")};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventInvalidTimeoutValueError)
{
    auto timeout {"dummy"};
    const vector<string> arguments {commandName, location, timeout};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventInvalidTimeoutFromReferenceValueError)
{
    auto timeout {"$tout"};
    const vector<string> arguments {commandName, location, timeout};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"someField": "123", "obj": {"sub_field": "/"}, "tout": "dummy"})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventTimeoutFromUnexistantReferenceError)
{
    auto timeout {"$tout"};
    const vector<string> arguments {commandName, location, timeout};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {R"({"someField": "123", "obj": {"sub_field": "/"}})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_FALSE(resultField);
}

TEST_F(opBuilderHelperCreateARTestSuite, eventAllParametersFromReferencesI)
{
    auto commandName {"$cmd"};
    auto location {"$loc"};
    auto timeout {"$tout"};
    const vector<string> arguments {commandName, location, timeout, extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"tout": "123", "loc": "ALL", "cmd": "dummy-cmd", "other-field": 69, "_extra_args": ["test-arg","2"]})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult("dummy-cmd",
                                            "ALL",
                                            make_shared<json::Json>(originalEvent),
                                            "123",
                                            R"("test-arg","2")")};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventAllParametersFromReferencesII)
{
    auto commandName {"$cmd"};
    auto location {"$loc"};
    auto timeout {"$tout"};
    const vector<string> arguments {commandName, location, timeout, extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"agent":{"id":"404"},"tout":"123","loc":"LOCAL","cmd":"dummy-cmd","other-field":69,"_extra_args":["test-arg","2"]})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult("dummy-cmd",
                                            "LOCAL",
                                            make_shared<json::Json>(originalEvent),
                                            "123",
                                            R"("test-arg","2")")};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}

TEST_F(opBuilderHelperCreateARTestSuite, eventAllParametersFromReferencesIII)
{
    auto commandName {"$cmd"};
    auto location {"$loc"};
    auto timeout {"$tout"};
    const vector<string> arguments {commandName, location, timeout, extraArgsRef};
    const auto tuple {make_tuple(targetField, arCreateHFName, arguments)};
    auto op {opBuilderHelperCreateAR(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto originalEvent {
        R"({"tout":"123","loc":"404","cmd":"dummy-cmd","other-field":69,"_extra_args":["test-arg","2"]})"};
    auto event {make_shared<json::Json>(originalEvent)};
    auto result {op(event)};

    auto expectedPayload {getExpectedResult("dummy-cmd",
                                            "404",
                                            make_shared<json::Json>(originalEvent),
                                            "123",
                                            R"("test-arg","2")")};

    auto resultField {result.payload()->getString(targetField)};

    ASSERT_TRUE(resultField);

    ASSERT_STREQ(result.payload()->getString(targetField).value_or("").c_str(),
                 expectedPayload.c_str());
}
