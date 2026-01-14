/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 1, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "msgDispatcher_test.h"
#include "msgDispatcher.h"
#include <chrono>
#include <thread>

using Key = int;
using Value = std::string;
using RawValue = std::pair<void*, size_t>;
using DecodedValue = std::pair<Key, Value>;

class DecoderWrapper
{
public:
    DecoderWrapper() {}
    ~DecoderWrapper() {}
    MOCK_METHOD(DecodedValue, decode, (const RawValue&), ());
    MOCK_METHOD(void, callback, (const Value&));
};

void MsgDispatcherTest::SetUp() {};

void MsgDispatcherTest::TearDown() {};

using ::testing::Return;
using namespace Utils;

using TestMsgDispatcher = MsgDispatcher<Key, Value, RawValue, DecoderWrapper>;

TEST_F(MsgDispatcherTest, MsgDispatcherPushAndRundown)
{
    const Key key1 {100};
    const Key key2 {200};
    const Key key3 {300};
    const auto input1 {RawValue {reinterpret_cast<void*>(0x65654), 5000}};
    const auto input2 {RawValue {reinterpret_cast<void*>(0x65244), 4000}};
    const auto input3 {RawValue {reinterpret_cast<void*>(0x68878), 6546}};

    const auto decoded1 {DecodedValue(key1, "value 0")};
    const auto decoded2 {DecodedValue(key2, "value 1")};
    const auto decoded3 {DecodedValue(key3, "value 2")};
    TestMsgDispatcher dispatcher;
    EXPECT_CALL(dispatcher, decode(input1)).WillOnce(Return(decoded1));
    EXPECT_CALL(dispatcher, decode(input2)).WillOnce(Return(decoded2));
    EXPECT_CALL(dispatcher, decode(input3)).WillOnce(Return(decoded3));

    EXPECT_CALL(dispatcher, callback(decoded1.second)).Times(1);
    EXPECT_CALL(dispatcher, callback(decoded2.second)).Times(1);
    EXPECT_CALL(dispatcher, callback(decoded3.second)).Times(0);
    EXPECT_NO_THROW(dispatcher.addCallback(key1, [&dispatcher](const Value& value) { dispatcher.callback(value); }));
    EXPECT_NO_THROW(dispatcher.addCallback(key2, [&dispatcher](const Value& value) { dispatcher.callback(value); }));

    dispatcher.push(input1);
    dispatcher.push(input2);
    dispatcher.push(input3);
    dispatcher.rundown();
    EXPECT_TRUE(dispatcher.cancelled());
    EXPECT_EQ(0ul, dispatcher.size());
    dispatcher.push(input1);
    dispatcher.push(input2);
    dispatcher.push(input3);
}

TEST_F(MsgDispatcherTest, MsgDispatcherPushSync)
{
    const Key key1 {100};
    const Key key2 {200};
    const Key key3 {300};
    const auto input1 {RawValue {reinterpret_cast<void*>(0x65654), 5000}};
    const auto input2 {RawValue {reinterpret_cast<void*>(0x65244), 4000}};
    const auto input3 {RawValue {reinterpret_cast<void*>(0x68878), 6546}};

    const auto decoded1 {DecodedValue(key1, "value 0")};
    const auto decoded2 {DecodedValue(key2, "value 1")};
    const auto decoded3 {DecodedValue(key3, "value 2")};
    TestMsgDispatcher dispatcher;
    EXPECT_CALL(dispatcher, decode(input1)).WillOnce(Return(decoded1));
    EXPECT_CALL(dispatcher, decode(input2)).WillOnce(Return(decoded2));
    EXPECT_CALL(dispatcher, decode(input3)).WillOnce(Return(decoded3));

    EXPECT_CALL(dispatcher, callback(decoded1.second)).Times(1);
    EXPECT_CALL(dispatcher, callback(decoded2.second)).Times(1);
    EXPECT_CALL(dispatcher, callback(decoded3.second)).Times(0);
    EXPECT_NO_THROW(dispatcher.addCallback(key1, [&dispatcher](const Value& value) { dispatcher.callback(value); }));
    EXPECT_NO_THROW(dispatcher.addCallback(key2, [&dispatcher](const Value& value) { dispatcher.callback(value); }));

    dispatcher.dispatch(input1);
    dispatcher.dispatch(input2);
    dispatcher.dispatch(input3);
}

TEST_F(MsgDispatcherTest, MsgDispatcherAddCallbackTwice)
{
    const Key key1 {100};
    const Key key2 {200};
    TestMsgDispatcher dispatcher;
    EXPECT_NO_THROW(dispatcher.addCallback(key1, [&dispatcher](const Value& value) { dispatcher.callback(value); }));
    EXPECT_NO_THROW(dispatcher.addCallback(key2, [&dispatcher](const Value& value) { dispatcher.callback(value); }));
    EXPECT_NO_THROW(dispatcher.addCallback(key2, [&dispatcher](const Value& value) { dispatcher.callback(value); }));
}

TEST_F(MsgDispatcherTest, MsgDispatcherRemoveCallback)
{
    const Key key1 {100};
    const Key key2 {200};
    const Key key3 {300};
    const auto input1 {RawValue {reinterpret_cast<void*>(0x65654), 5000}};
    const auto input2 {RawValue {reinterpret_cast<void*>(0x65244), 4000}};
    const auto input3 {RawValue {reinterpret_cast<void*>(0x68878), 6546}};

    const auto decoded1 {DecodedValue(key1, "value 0")};
    const auto decoded2 {DecodedValue(key2, "value 1")};
    const auto decoded3 {DecodedValue(key3, "value 2")};
    TestMsgDispatcher dispatcher;
    EXPECT_CALL(dispatcher, decode(input1)).WillRepeatedly(Return(decoded1));
    EXPECT_CALL(dispatcher, decode(input2)).WillOnce(Return(decoded2));
    EXPECT_CALL(dispatcher, decode(input3)).WillOnce(Return(decoded3));

    EXPECT_CALL(dispatcher, callback(decoded1.second)).Times(1);
    EXPECT_CALL(dispatcher, callback(decoded2.second)).Times(1);
    EXPECT_CALL(dispatcher, callback(decoded3.second)).Times(0);
    EXPECT_NO_THROW(dispatcher.addCallback(key1, [&dispatcher](const Value& value) { dispatcher.callback(value); }));
    EXPECT_NO_THROW(dispatcher.addCallback(key2, [&dispatcher](const Value& value) { dispatcher.callback(value); }));

    dispatcher.dispatch(input1);
    dispatcher.dispatch(input2);
    dispatcher.dispatch(input3);
    dispatcher.removeCallback(key1);
    dispatcher.dispatch(input1);
}
