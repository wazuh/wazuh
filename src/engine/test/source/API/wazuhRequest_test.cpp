
#include <gtest/gtest.h>

#include <API/wazuhRequest.hpp>
#include <API/wazuhResponse.hpp>
#include <API/registry.hpp>
#include <json/json.hpp>


TEST(WazuhRequest, test_231)
{

    // Registry
    api::Registry registry;

    registry.registerCommand("loop", [](const json::Json &json) -> api::WazuhResponse {
        return api::WazuhResponse { json, 0, "OK" };
    });

    registry.registerCommand("ping", [](const json::Json &json) -> api::WazuhResponse {
        json::Json data { "\"pong\"" };
        return api::WazuhResponse { data, 0, "OK" };
    });


    // WazuhRequest
    api::WazuhRequest wazuhRequest_1 { api::WazuhRequest::create("loop", json::Json(R"({"test_123": "test_456"})")) };
    api::WazuhRequest wazuhRequest_2 { api::WazuhRequest::create("ping", json::Json("{}")) };

    // Validate
    std::string error_1 = wazuhRequest_1.getParameters().value_or(json::Json("\"hola\"")).str();

    ASSERT_TRUE(wazuhRequest_1.isValid());
    ASSERT_TRUE(wazuhRequest_2.isValid());
    ASSERT_EQ(wazuhRequest_1.getCommand().value(), "loop");
    ASSERT_EQ(wazuhRequest_2.getCommand().value(), "ping");
    ASSERT_EQ(wazuhRequest_1.getParameters().value(), json::Json(R"({"test_123": "test_456"})"));
    ASSERT_EQ(wazuhRequest_2.getParameters().value(), json::Json("{}"));

    // Get callback in registry
    auto cmd = registry.getCallback(wazuhRequest_1.getCommand().value());

    // Execute callback
    auto response = cmd(wazuhRequest_1.getParameters().value());
    auto resStr = response.toString();
    ASSERT_EQ(response.toString(), R"({"data":{"test_123":"test_456"},"error":0,"message":"OK"})");

    cmd = registry.getCallback(wazuhRequest_2.getCommand().value());
    response = cmd(wazuhRequest_2.getParameters().value());
    ASSERT_EQ(response.toString(), R"({"data":"pong","error":0,"message":"OK"})");

    // Command not found
    api::WazuhRequest wazuhRequest_3 { api::WazuhRequest::create("not_found", json::Json("{}")) };
    ASSERT_TRUE(wazuhRequest_3.isValid());
    ASSERT_EQ(wazuhRequest_3.getCommand().value(), "not_found");

    cmd = registry.getCallback(wazuhRequest_3.getCommand().value());
    response = cmd(wazuhRequest_3.getParameters().value());
    ASSERT_EQ(response.toString(), R"({"data":null,"error":-1,"message":"Command not found"})");
}
