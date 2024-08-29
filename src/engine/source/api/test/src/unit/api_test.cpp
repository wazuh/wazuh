#include <gtest/gtest.h>

#include <api/api.hpp>
#include <base/logging.hpp>

using namespace api;

wpResponse testHandler(const wpRequest& request)
{
    return wpResponse(json::Json(R"({"response": "OK"})"), 0);
}

wpResponse testHandlerExeption(const wpRequest& request)
{
    throw std::runtime_error("test exception");
    return wpResponse(json::Json(R"({"response": "OK"})"), 0);
}

class ApiTest : public testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    Api m_api;

    void SetUp() override
    {
        logging::testInit();
        m_api.registerHandler("testCommand", Api::convertToHandlerAsync(testHandler));
        m_api.registerHandler("testCommandException", Api::convertToHandlerAsync(testHandlerExeption));
    }
};

TEST_P(ApiTest, ProcessRequest)
{
    const std::string& message = std::get<0>(GetParam());
    const std::string& expectedResponse = std::get<1>(GetParam());

    auto response = std::make_shared<std::string>();
    auto callbackFn = [&response](const std::string& res)
    {
        *response = res;
    };

    m_api.processRequest(message, callbackFn);
    EXPECT_EQ(*response, expectedResponse);
}

INSTANTIATE_TEST_SUITE_P(
    ApiTestInstantiation,
    ApiTest,
    testing::Values(
        std::make_tuple(wpRequest::create("testCommand", "test_moudule", json::Json(R"({})")).toStr(),
                        R"({"data":{"response":"OK"},"error":0})"),
        std::make_tuple(R"({"command": "testCommand", "parameters":)", wpResponse::invalidJsonRequest().toString()),
        std::make_tuple(
            R"({"version":1,"command":123,"parameters":{},"origin":{"module":"wazuh-engine","name":"test_moudule"}})",
            R"({"data":{},"error":4,"message":"Invalid request: The request must have a 'command' field containing a string value"})"),
        std::make_tuple(wpRequest::create("no_exist_cmd", "test_moudule", json::Json(R"({})")).toStr(),
                        R"({"data":{},"error":5,"message":"Command \"no_exist_cmd\" not found"})"),
        std::make_tuple(wpRequest::create("testCommandException", "test_moudule", json::Json(R"({})")).toStr(),
                        wpResponse::unknownError().toString())));
