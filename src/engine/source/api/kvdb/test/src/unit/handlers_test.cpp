#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/kvdb/handlers.hpp>
#include <base/json.hpp>
#include <eMessages/kvdb.pb.h>
#include <kvdb/mockKvdbHandler.hpp>
#include <kvdb/mockKvdbManager.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::kvdb;
using namespace api::kvdb::handlers;
using namespace ::kvdb::mocks;

using KvdbHandlerTest = BaseHandlerTest<::kvdbManager::IKVDBManager, MockKVDBManager>;

TEST_P(KvdbHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<::kvdbManager::IKVDBManager, MockKVDBManager>;

INSTANTIATE_TEST_SUITE_P(
    Api,
    KvdbHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * ManagerGet
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::managerGet_Request protoReq;
                return createRequest<eEngine::kvdb::managerGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerGet(kvdb); },
            []()
            {
                eEngine::kvdb::managerGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.add_dbs("");
                return userResponse<eEngine::kvdb::managerGet_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, listDBs(testing::_)).WillOnce(testing::Return(std::vector<std::string> {""})); }),
        /***********************************************************************
         * ManagerPost
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::managerPost_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::managerPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerPost(kvdb); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(false));
                EXPECT_CALL(mock, createDB(testing::_)).WillOnce(testing::Return(base::noError()));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::kvdb::managerPost_Request protoReq;
                return createRequest<eEngine::kvdb::managerPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerPost(kvdb); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /name"); },
            [](auto& mock) {}),
        // Database exists
        HandlerT(
            []()
            {
                eEngine::kvdb::managerPost_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::managerPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerPost(kvdb); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("The Database already exists."); },
            [](auto& mock) { EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true)); }),
        // Failure creating data base
        HandlerT(
            []()
            {
                eEngine::kvdb::managerPost_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::managerPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerPost(kvdb); },
            []() {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "The database could not be created. Error: error");
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(false));
                EXPECT_CALL(mock, createDB(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
            }),
        /***********************************************************************
         * ManagerDelete
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::managerDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDelete(kvdb); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, deleteDB(testing::_)).WillOnce(testing::Return(base::noError()));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDelete_Request protoReq;
                return createRequest<eEngine::kvdb::managerDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDelete(kvdb); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /name"); },
            [](auto& mock) {}),
        // Database not exists
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::managerDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDelete(kvdb); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("The KVDB 'name' does not exist."); },
            [](auto& mock) { EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(false)); }),
        // Failure deleting data base
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::managerDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDelete(kvdb); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, deleteDB(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
            }),
        /***********************************************************************
         * ManagerDump
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDump_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_page(1);
                protoReq.set_records(1);
                return createRequest<eEngine::kvdb::managerDump_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDump(kvdb, "any_scope"); },
            []()
            {
                eEngine::kvdb::managerDump_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                auto* entry1 = protoRes.add_entries();
                entry1->set_key("key1");
                entry1->mutable_value()->set_number_value(1);
                return userResponse<eEngine::kvdb::managerDump_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                const std::list<std::pair<std::string, std::string>> mockList = {{"key1", "1"}};
                EXPECT_CALL(*mockKvdbHanlder, dump(testing::_, testing::_)).WillOnce(testing::Return(mockList));
            }),
        // Invalid page
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDump_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_page(0);
                protoReq.set_records(1);
                return createRequest<eEngine::kvdb::managerDump_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDump(kvdb, "any_scope"); },
            []()
            { return userErrorResponse<eEngine::kvdb::managerDump_Response>("Field /page must be greater than 0"); },
            [](auto& mock) {}),
        // Invalid record
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDump_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_page(1);
                protoReq.set_records(0);
                return createRequest<eEngine::kvdb::managerDump_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDump(kvdb, "any_scope"); },
            []()
            { return userErrorResponse<eEngine::kvdb::managerDump_Response>("Field /records must be greater than 0"); },
            [](auto& mock) {}),
        // Dump error
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDump_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_page(1);
                protoReq.set_records(1);
                return createRequest<eEngine::kvdb::managerDump_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDump(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::kvdb::managerDump_Response>("error"); },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, dump(testing::_, testing::_))
                    .WillOnce(testing::Return(base::Error {"error"}));
            }),
        // Invalid value
        HandlerT(
            []()
            {
                eEngine::kvdb::managerDump_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_page(1);
                protoReq.set_records(1);
                return createRequest<eEngine::kvdb::managerDump_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return managerDump(kvdb, "any_scope"); },
            []()
            {
                return userErrorResponse<eEngine::kvdb::managerDump_Response>(
                    "INVALID_ARGUMENT:Unexpected token.\nvalue1\n^. For key 'key1' and value value1");
            },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                const std::list<std::pair<std::string, std::string>> mockList = {{"key1", "value1"}};
                EXPECT_CALL(*mockKvdbHanlder, dump(testing::_, testing::_)).WillOnce(testing::Return(mockList));
            }),
        /***********************************************************************
         * DBGet
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::dbGet_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbGet(kvdb, "any_scope"); },
            []()
            {
                eEngine::kvdb::dbGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.mutable_value()->set_number_value(1);
                return userResponse<eEngine::kvdb::dbGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, get(testing::_)).WillOnce(testing::Return("1"));
            }),
        // Missing name
        HandlerT(
            []()
            {
                eEngine::kvdb::dbGet_Request protoReq;
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbGet(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::kvdb::dbGet_Response>("Missing /name"); },
            [](auto& mock) {}),
        // Missing key
        HandlerT(
            []()
            {
                eEngine::kvdb::dbGet_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::dbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbGet(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::kvdb::dbGet_Response>("Missing /key"); },
            [](auto& mock) {}),
        // DB does not exist
        HandlerT(
            []()
            {
                eEngine::kvdb::dbGet_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbGet(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::kvdb::dbGet_Response>("The KVDB 'name' does not exist."); },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(false));
            }),
        // Get error
        HandlerT(
            []()
            {
                eEngine::kvdb::dbGet_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbGet(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::kvdb::dbGet_Response>("error"); },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, get(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
            }),
        // Invalid argument
        HandlerT(
            []()
            {
                eEngine::kvdb::dbGet_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbGet(kvdb, "any_scope"); },
            []()
            {
                return userErrorResponse<eEngine::kvdb::dbGet_Response>(
                    "INVALID_ARGUMENT:Unexpected token.\nhello\n^. For value hello");
            },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, get(testing::_)).WillOnce(testing::Return("hello"));
            }),
        /***********************************************************************
         * DBDelete
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::dbDelete_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbDelete(kvdb, "any_scope"); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, remove(testing::_)).WillOnce(testing::Return(base::noError()));
            }),
        // Missing name
        HandlerT(
            []()
            {
                eEngine::kvdb::dbDelete_Request protoReq;
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbDelete(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /name"); },
            [](auto& mock) {}),
        // Missing key
        HandlerT(
            []()
            {
                eEngine::kvdb::dbDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::kvdb::dbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbDelete(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /key"); },
            [](auto& mock) {}),
        // DB does not exist
        HandlerT(
            []()
            {
                eEngine::kvdb::dbDelete_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbDelete(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("The KVDB 'name' does not exist."); },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(false));
            }),
        // Error removing DB
        HandlerT(
            []()
            {
                eEngine::kvdb::dbDelete_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_key("key1");
                return createRequest<eEngine::kvdb::dbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbDelete(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, remove(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
            }),
        /***********************************************************************
         * DBPut
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::dbPut_Request protoReq;
                protoReq.set_name("name");
                auto* entry1 = protoReq.mutable_entry();
                entry1->set_key("key1");
                entry1->mutable_value()->set_number_value(1);
                return createRequest<eEngine::kvdb::dbPut_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbPut(kvdb, "any_scope"); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, set(testing::_, testing::Matcher<const std::string&>(testing::Eq("1"))))
                    .WillOnce(testing::Return(base::noError()));
            }),
        // Missing name
        HandlerT(
            []()
            {
                eEngine::kvdb::dbPut_Request protoReq;
                auto* entry1 = protoReq.mutable_entry();
                entry1->set_key("key1");
                entry1->mutable_value()->set_number_value(1);
                return createRequest<eEngine::kvdb::dbPut_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbPut(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /name"); },
            [](auto& mock) {}),
        // Missing entry key
        HandlerT(
            []()
            {
                eEngine::kvdb::dbPut_Request protoReq;
                protoReq.set_name("name");
                auto* entry1 = protoReq.mutable_entry();
                entry1->mutable_value()->set_number_value(1);
                return createRequest<eEngine::kvdb::dbPut_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbPut(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /entry/key"); },
            [](auto& mock) {}),
        // Missing entry value
        HandlerT(
            []()
            {
                eEngine::kvdb::dbPut_Request protoReq;
                protoReq.set_name("name");
                auto* entry1 = protoReq.mutable_entry();
                entry1->set_key("key1");
                return createRequest<eEngine::kvdb::dbPut_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbPut(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /entry/value"); },
            [](auto& mock) {}),
        // Invalid entry/key
        HandlerT(
            []()
            {
                eEngine::kvdb::dbPut_Request protoReq;
                protoReq.set_name("name");
                auto* entry1 = protoReq.mutable_entry();
                entry1->set_key("");
                entry1->mutable_value()->set_string_value("hello");
                return createRequest<eEngine::kvdb::dbPut_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbPut(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Field /key is empty"); },
            [](auto& mock) {}),
        // DB does not exist
        HandlerT(
            []()
            {
                eEngine::kvdb::dbPut_Request protoReq;
                protoReq.set_name("name");
                auto* entry1 = protoReq.mutable_entry();
                entry1->set_key("key1");
                entry1->mutable_value()->set_number_value(1);
                return createRequest<eEngine::kvdb::dbPut_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbPut(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("The KVDB 'name' does not exist."); },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(false));
            }),
        // Error setting
        HandlerT(
            []()
            {
                eEngine::kvdb::dbPut_Request protoReq;
                protoReq.set_name("name");
                auto* entry1 = protoReq.mutable_entry();
                entry1->set_key("key1");
                entry1->mutable_value()->set_number_value(1);
                return createRequest<eEngine::kvdb::dbPut_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbPut(kvdb, "any_scope"); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                EXPECT_CALL(*mockKvdbHanlder, set(testing::_, testing::Matcher<const std::string&>(testing::Eq("1"))))
                    .WillOnce(testing::Return(base::Error {"error"}));
            }),
        /***********************************************************************
         * DBSearch
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::kvdb::dbSearch_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_prefix("prefix");
                protoReq.set_page(1);
                protoReq.set_records(1);
                return createRequest<eEngine::kvdb::dbSearch_Request>(protoReq);
            },
            [](const std::shared_ptr<::kvdbManager::IKVDBManager>& kvdb) { return dbSearch(kvdb, "any_scope"); },
            []()
            {
                eEngine::kvdb::dbSearch_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                auto* entry1 = protoRes.add_entries();
                entry1->set_key("key1");
                entry1->mutable_value()->set_number_value(1);
                return userResponse<eEngine::kvdb::dbSearch_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto mockKvdbHanlder = std::make_shared<MockKVDBHandler>();
                EXPECT_CALL(mock, existsDB(testing::_)).WillOnce(testing::Return(true));
                EXPECT_CALL(mock, getKVDBHandler(testing::_, testing::_)).WillOnce(testing::Return(mockKvdbHanlder));
                const std::list<std::pair<std::string, std::string>> mockList = {{"key1", "1"}};
                EXPECT_CALL(*mockKvdbHanlder, search(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(mockList));
            })));
