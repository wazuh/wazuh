/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "rsyncImplementationTest.h"
#include "rsyncImplementation.h"
#include "rsync_exception.h"
#include "rsync.hpp"
#include "../mocks/dbsyncmock.h"

using ::testing::_;

void RSyncImplementationTest::SetUp()
{
};

void RSyncImplementationTest::TearDown()
{
};

const auto g_startConfigStmt =
    R"({"table":"entry_path",
        "first_query":
            {
                "column_list":["path"],
                "row_filter":"WHERE path is null",
                "distinct_opt":false,
                "order_by_opt":"path ASC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["path"],
                "row_filter":"WHERE path is null",
                "distinct_opt":false,
                "order_by_opt":"path DESC",
                "count_opt":1
            },
        "component":"test_id",
        "index":"path",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["path, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"_json;

const auto g_commonConfig = R"({
                        "decoder_type":"JSON_RANGE",
                        "table":"test",
                        "component":"test_component",
                        "index":"test_index_field",
                        "checksum_field":"checksum",
                        "no_data_query_json":{
                            "row_filter":"",
                            "column_list":[
                                ""
                            ],
                            "distinct_opt":"",
                            "order_by_opt":""
                        },
                        "count_range_query_json":{
                            "row_filter":"",
                            "count_field_name":"count_field",
                            "column_list":[
                                ""
                            ],
                            "distinct_opt":"",
                            "order_by_opt":""
                        },
                        "row_data_query_json":{
                            "row_filter":"",
                            "column_list":[
                                ""
                            ],
                            "distinct_opt":"",
                            "order_by_opt":""
                        },
                        "range_checksum_query_json":{
                            "row_filter":"",
                            "column_list":[
                                ""
                            ],
                            "distinct_opt":"",
                            "order_by_opt":""
                        }
                    })"_json;


TEST_F(RSyncImplementationTest, InvalidHandlerInRegister)
{
    EXPECT_THROW(RSync::RSyncImplementation::instance().registerSyncId(reinterpret_cast<RSYNC_HANDLE>(1), "", nullptr, nullptr, {}), RSync::rsync_error);
}

TEST_F(RSyncImplementationTest, InvalidConfigurationParse)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };
    const auto config { R"({"decoder_type"===="JSON_RANGE"})" };

    EXPECT_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", nullptr, nlohmann::json::parse(config), {}), nlohmann::detail::exception);
    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

TEST_F(RSyncImplementationTest, InvalidDecoder)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };
    const auto config { R"({"decoder_type":"JSON_RANGE_INVALID"})" };

    EXPECT_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", nullptr, nlohmann::json::parse(config), {}), std::out_of_range);
    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

TEST_F(RSyncImplementationTest, ValidDecoder)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };
    const auto config { R"({"decoder_type":"JSON_RANGE", "component":"test_decoder"})" };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", nullptr, nlohmann::json::parse(config), {}));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

TEST_F(RSyncImplementationTest, ValidDecoderPushedNoData)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };
    const auto config { R"({"decoder_type":"JSON_RANGE", "component":"test_decoder","table":"test","no_data_query_json":{"row_filter":"","column_list":"","distinct_opt":"","order_by_opt":""}})" };
    auto mockDbSync { std::make_shared<MockDBSync>() };

    EXPECT_CALL(*mockDbSync, select(_, _)).Times(3);
    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", mockDbSync, nlohmann::json::parse(config), {}));

    std::string buffer{R"(test_id no_data {"begin":"1","end":"2","id":1})"};

    const auto first{reinterpret_cast<const unsigned char*>(buffer.data())};
    const auto last{first + buffer.size()};
    const std::vector<unsigned char> data{first, last};

    std::function<void(const std::string&)> callbackWrapper
    {
        [&](const std::string & payload)
        {
            EXPECT_FALSE(payload.empty());
        }
    };

    SyncCallbackData callbackData
    {
        [&callbackWrapper](const std::string & payload)
        {
            callbackWrapper(payload);
        }
    };


    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().startRSync(handle, mockDbSync, g_startConfigStmt, callbackData));
    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().push(handle, data));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

TEST_F(RSyncImplementationTest, ValidDecoderPushedChecksumFail)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };
    const auto expectedResult
    {
        R"({"component":"test_component","data":{"attributes":{"test field":"test","test_index_field":"11"},"index":"11","timestamp":""},"type":"state"})"
    };

    auto mockDbSync { std::make_shared<MockDBSync>() };

    EXPECT_CALL(*mockDbSync, select(_, _)).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["checksum"] = "test_checksum";
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["count_field"] = 2;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["test_index_field"] = "11";
        data["test field"] = "test";
        callback(ReturnTypeCallback::GENERIC, data);
    }));

    const auto callbackWrapper
    {
        [&expectedResult](const std::string & payload)
        {
            EXPECT_EQ(0, payload.compare(expectedResult));
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", mockDbSync, g_commonConfig, callbackWrapper));

    std::string buffer{R"(test_id checksum_fail {"begin":"1","end":"2","id":1})"};

    const auto first{reinterpret_cast<const unsigned char*>(buffer.data())};
    const auto last{first + buffer.size()};
    const std::vector<unsigned char> data{first, last};

    std::function<void(const std::string&)> callbackWrapper2
    {
        [&](const std::string & payload)
        {
            EXPECT_FALSE(payload.empty());
        }
    };

    SyncCallbackData callbackData
    {
        [&callbackWrapper2](const std::string & payload)
        {
            callbackWrapper2(payload);
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().startRSync(handle, mockDbSync, g_startConfigStmt, callbackData));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().push(handle, data));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

TEST_F(RSyncImplementationTest, ValidDecoderPushedChecksumFailToSplit)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };

    const auto expectedResult1
    {
        R"({"component":"test_component","data":{"begin":"1","checksum":"287befc49446efc633d2c224c627515c1919a2bb","end":"1","id":1,"tail":"2"},"type":"integrity_check_left"})"
    };
    const auto expectedResult2
    {
        R"({"component":"test_component","data":{"begin":"2","checksum":"287befc49446efc633d2c224c627515c1919a2bb","end":"2","id":1},"type":"integrity_check_right"})"
    };

    const auto config { R"({
                            "decoder_type":"JSON_RANGE",
                            "table":"test",
                            "component":"test_component",
                            "index":"test_index_field",
                            "last_event":"test_last_event_field",
                            "checksum_field":"checksum",
                            "no_data_query_json":{
                                "row_filter":"",
                                "column_list":[
                                    ""
                                ],
                                "distinct_opt":"",
                                "order_by_opt":""
                            },
                            "count_range_query_json":{
                                "row_filter":"",
                                "count_field_name":"count_field",
                                "column_list":[
                                    ""
                                ],
                                "distinct_opt":"",
                                "order_by_opt":""
                            },
                            "row_data_query_json":{
                                "row_filter":"",
                                "column_list":[
                                    ""
                                ],
                                "distinct_opt":"",
                                "order_by_opt":""
                            },
                            "range_checksum_query_json":{
                                "row_filter":"",
                                "column_list":[
                                    ""
                                ],
                                "distinct_opt":"",
                                "order_by_opt":""
                            }
                        })" };

    auto mockDbSync { std::make_shared<MockDBSync>() };

    EXPECT_CALL(*mockDbSync, select(_, _)).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["checksum"] = "test_checksum";
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["count_field"] = 2;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::DoAll(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["test_index_field"] = "1";
        data["test_last_event_field"] = "22";
        data["checksum"] = "aecf1235445354";
        callback(ReturnTypeCallback::GENERIC, data);
    }), testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["test_index_field"] = "2";
        data["test_last_event_field"] = "23";
        data["checksum"] = "aecf1235445354";
        callback(ReturnTypeCallback::GENERIC, data);
    })));

    std::atomic<uint64_t> messageCounter { 0 };
    constexpr auto TOTAL_EXPECTED_MESSAGES { 2ull };

    const auto checkExpected
    {
        [&](const std::string & payload) -> ::testing::AssertionResult
        {
            auto retVal { ::testing::AssertionFailure() };

            if (0 == payload.compare(expectedResult1) || 0 == payload.compare(expectedResult2))
            {
                retVal = ::testing::AssertionSuccess();
                ++messageCounter;
            }

            return retVal;
        }
    };

    const auto callbackWrapper
    {
        [&](const std::string & payload)
        {
            EXPECT_PRED1(checkExpected, payload);
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", mockDbSync, nlohmann::json::parse(config), callbackWrapper));

    std::string buffer{R"(test_id checksum_fail {"begin":"1","end":"2","id":1})"};

    const auto first{reinterpret_cast<const unsigned char*>(buffer.data())};
    const auto last{first + buffer.size()};
    const std::vector<unsigned char> data{first, last};

    std::function<void(const std::string&)> callbackWrapper2
    {
        [&](const std::string & payload)
        {
            EXPECT_FALSE(payload.empty());
        }
    };

    SyncCallbackData callbackData
    {
        [&callbackWrapper2](const std::string & payload)
        {
            callbackWrapper2(payload);
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().startRSync(handle, mockDbSync, g_startConfigStmt, callbackData));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().push(handle, data));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());

    EXPECT_EQ(TOTAL_EXPECTED_MESSAGES, messageCounter.load());
}

TEST_F(RSyncImplementationTest, ValidDecoderPushedChecksumInvalidOperation)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };

    const auto config { R"({"decoder_type":"JSON_RANGE",
                            "table":"test",
                            "component":"test_component",
                            "index":"test_index_field",
                            "last_event":"test_last_event_field",
                            "checksum_field":"checksum",
                            "no_data_query_json":{
                                "row_filter":"",
                                "column_list":"",
                                "distinct_opt":"",
                                "order_by_opt":""
                            },
                            "count_range_query_json":{
                                "row_filter":"",
                                "count_field_name":"count_field",
                                "column_list":"",
                                "distinct_opt":"",
                                "order_by_opt":""
                            },
                            "row_data_query_json":{
                                "row_filter":"",
                                "column_list":"",
                                "distinct_opt":"",
                                "order_by_opt":""
                            },
                            "range_checksum_query_json":{
                                "row_filter":"",
                                "column_list":"",
                                "distinct_opt":"",
                                "order_by_opt":""
                            }
                        })" };

    auto mockDbSync { std::make_shared<MockDBSync>() };

    EXPECT_CALL(*mockDbSync, select(_, _)).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["checksum"] = "test_checksum";
        callback(ReturnTypeCallback::GENERIC, data);
    }));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", mockDbSync, nlohmann::json::parse(config), nullptr));

    std::string buffer{R"(test_id checksum_fails {"begin":"1","end":"2","id":1})"};

    const auto first{reinterpret_cast<const unsigned char*>(buffer.data())};
    const auto last{first + buffer.size()};
    const std::vector<unsigned char> data{first, last};

    std::function<void(const std::string&)> callbackWrapper2
    {
        [&](const std::string & payload)
        {
            EXPECT_FALSE(payload.empty());
        }
    };

    SyncCallbackData callbackData
    {
        [&callbackWrapper2](const std::string & payload)
        {
            callbackWrapper2(payload);
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().startRSync(handle, mockDbSync, g_startConfigStmt, callbackData));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().push(handle, data));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

TEST_F(RSyncImplementationTest, ValidDecoderPushedChecksumNoData)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };

    const auto config { R"({
        "decoder_type":"JSON_RANGE",
        "table":"test",
        "component":"test_component",
        "index":"test_index_field",
        "last_event":"test_last_event_field",
        "checksum_field":"checksum",
        "no_data_query_json":{
            "row_filter":"",
            "column_list":"",
            "distinct_opt":"",
            "order_by_opt":""
        },
        "count_range_query_json":{
            "row_filter":"",
            "count_field_name":"count_field",
            "column_list":"",
            "distinct_opt":"",
            "order_by_opt":""
        },
        "row_data_query_json":{
            "row_filter":"",
            "column_list":"",
            "distinct_opt":"",
            "order_by_opt":""
        },
        "range_checksum_query_json":{
            "row_filter":"",
            "column_list":"",
            "distinct_opt":"",
            "order_by_opt":""
        }
    })" };

    auto mockDbSync { std::make_shared<MockDBSync>() };

    EXPECT_CALL(*mockDbSync, select(_, _)).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["checksum"] = "test_checksum";
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["count_field"] = 0;
        callback(ReturnTypeCallback::GENERIC, data);
    }));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", mockDbSync, nlohmann::json::parse(config), nullptr));

    std::string buffer{R"(test_id checksum_fail {"begin":"1","end":"2","id":1})"};

    const auto first{reinterpret_cast<const unsigned char*>(buffer.data())};
    const auto last{first + buffer.size()};
    const std::vector<unsigned char> data{first, last};

    std::function<void(const std::string&)> callbackWrapper2
    {
        [&](const std::string & payload)
        {
            EXPECT_FALSE(payload.empty());
        }
    };

    SyncCallbackData callbackData
    {
        [&callbackWrapper2](const std::string & payload)
        {
            callbackWrapper2(payload);
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().startRSync(handle, mockDbSync, g_startConfigStmt, callbackData));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().push(handle, data));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());

    EXPECT_ANY_THROW(RSync::RSyncImplementation::instance().push(handle, data));
}

TEST_F(RSyncImplementationTest, InvalidPushData)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };

    auto mockDbSync { std::make_shared<MockDBSync>() };

    EXPECT_CALL(*mockDbSync, select(_, _)).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["checksum"] = "test_checksum";
        callback(ReturnTypeCallback::GENERIC, data);
    }));

    std::function<void(const std::string&)> callbackWrapper2
    {
        [&](const std::string & payload)
        {
            EXPECT_FALSE(payload.empty());
        }
    };

    SyncCallbackData callbackData
    {
        [&callbackWrapper2](const std::string & payload)
        {
            callbackWrapper2(payload);
        }
    };

    std::string buffer{R"(test_id)"};

    const auto first{reinterpret_cast<const unsigned char*>(buffer.data())};
    const auto last{first + buffer.size()};
    const std::vector<unsigned char> data{first, last};

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().startRSync(handle, mockDbSync, g_startConfigStmt, callbackData));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().push(handle, data));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

TEST(RSyncRegistrationController, ValidRegistrationFlow)
{
    RegistrationController regController;
    EXPECT_NO_THROW(regController.initComponentByHandle(RSYNC_HANDLE(1), "test_component"));
    EXPECT_EQ(regController.isComponentRegistered("test_component"), true);
    EXPECT_EQ(regController.isComponentRegistered("test_component_false"), false);
    EXPECT_NO_THROW(regController.removeComponentByHandle(RSYNC_HANDLE(1)));
    EXPECT_EQ(regController.isComponentRegistered("test_component"), false);
}

TEST_F(RSyncImplementationTest, ValidDecoderPushedChecksumFailInvalidSize)
{
    const auto handle { RSync::RSyncImplementation::instance().create() };
    const auto expectedResult
    {
        R"({"component":"test_component","data":{"attributes":{"test field":"test","test_index_field":"11"},"index":"11","timestamp":""},"type":"state"})"
    };

    auto mockDbSync { std::make_shared<MockDBSync>() };

    EXPECT_CALL(*mockDbSync, select(_, _)).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data = R"({"path":"test_path", "checksum":"test_checksum"})"_json;
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["checksum"] = "test_checksum";
        callback(ReturnTypeCallback::GENERIC, data);
    })).WillOnce(testing::Invoke([](nlohmann::json & data, ResultCallbackData callback)
    {
        data["count_field"] = 1;
        callback(ReturnTypeCallback::GENERIC, data);
    }));

    const auto callbackWrapper
    {
        [&expectedResult](const std::string & payload)
        {
            EXPECT_EQ(0, payload.compare(expectedResult));
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().registerSyncId(handle, "test_id", mockDbSync, g_commonConfig, callbackWrapper));

    std::string buffer{R"(test_id checksum_fail {"begin":"1","end":"2","id":1})"};

    const auto first{reinterpret_cast<const unsigned char*>(buffer.data())};
    const auto last{first + buffer.size()};
    const std::vector<unsigned char> data{first, last};

    std::function<void(const std::string&)> callbackWrapper2
    {
        [&](const std::string & payload)
        {
            EXPECT_FALSE(payload.empty());
        }
    };

    SyncCallbackData callbackData
    {
        [&callbackWrapper2](const std::string & payload)
        {
            callbackWrapper2(payload);
        }
    };

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().startRSync(handle, mockDbSync, g_startConfigStmt, callbackData));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().push(handle, data));

    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_NO_THROW(RSync::RSyncImplementation::instance().release());
}

