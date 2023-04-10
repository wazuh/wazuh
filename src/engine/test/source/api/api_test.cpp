#include <gtest/gtest.h>

#include <api/api.hpp>


using namespace api;

wpResponse testHandler(const wpRequest& request) {
    return wpResponse(json::Json(R"({"response": "OK"})"), 0);
}

wpResponse testHandlerExeption(const wpRequest& request) {
    throw std::runtime_error("test exception");
    return wpResponse(json::Json(R"({"response": "OK"})"), 0);
}

class ApiTest : public testing::Test {
protected:
    Api m_api;

    void SetUp() override {
        m_api.registerHandler("testCommand", testHandler);
        m_api.registerHandler("testCommandException", testHandlerExeption);

    }
};

TEST_F(ApiTest, ProcessRequest_ValidRequest) {

    wpRequest request = wpRequest::create("testCommand", "test_moudule", json::Json(R"({})"));

    std::string expectedResponse = R"({"data":{"response":"OK"},"error":0})";
    std::string response = m_api.processRequest(request.toStr());

    EXPECT_EQ(response, expectedResponse);
}

TEST_F(ApiTest, ProcessRequest_MalformedJson) {
    std::string message = R"({"command": "testCommand", "parameters":})";
    std::string expectedResponse = wpResponse::invalidJsonRequest().toString();
    std::string response = m_api.processRequest(message);

    EXPECT_EQ(response, expectedResponse);
}

TEST_F(ApiTest, ProcessRequest_InvalidSchema) {
    std::string message = R"({"version":1,"command":123,"parameters":{},"origin":{"module":"wazuh-engine","name":"test_moudule"}})";
    std::string expectedResponse = R"({"data":{},"error":4,"message":"Invalid request: The request must have a \"command\" field containing a string value"})";
    std::string response = m_api.processRequest(message);

    EXPECT_EQ(response, expectedResponse);
}

TEST_F(ApiTest, ProcessRequest_UnregisteredCommand) {
    wpRequest request = wpRequest::create("no_exist_cmd", "test_moudule", json::Json(R"({})"));
    std::string expectedResponse = R"({"data":{},"error":5,"message":"Command \"no_exist_cmd\" not found"})";
    std::string response = m_api.processRequest(request.toStr());

    EXPECT_EQ(response, expectedResponse);
}

TEST_F(ApiTest, ProcessRequest_HandlerException) {
    wpRequest request = wpRequest::create("testCommandException", "test_moudule", json::Json(R"({})"));
    std::string expectedResponse = wpResponse::unknownError().toString();
    std::string response = m_api.processRequest(request.toStr());

    EXPECT_EQ(response, expectedResponse);
}
