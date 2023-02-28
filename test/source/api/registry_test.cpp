
#include <gtest/gtest.h>

#include <api/registry.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

using namespace base::utils::wazuhProtocol;

TEST(Registry, exec)
{

    // Registry
    api::Registry registry;

    // Get callback in registry
    auto cmdTest = registry.getHandler("test");

    // Execute 2 times the callback fn
    auto response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    auto response2 = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), response2.toString());

}

TEST(Registry, addComand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);
    auto response = cmdTest(WazuhRequest::create(command, "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    auto cmdNotFound = response.toString();
    ASSERT_EQ(response.toString(), R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    // Add command
    registry.registerHandler(command,
                             [](WazuhRequest) -> WazuhResponse
                             { return WazuhResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 0, "OK"); });

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{"testArgKey":"testArgValue"},"error":0,"message":"OK"})");

    // Check the new command against the old one
    ASSERT_NE(cmdNotFound, response.toString());
}

TEST(Registry, addNullCommand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);
    auto response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    auto cmdNotFound = response.toString();
    ASSERT_EQ(response.toString(), R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    // Add command
    bool res = registry.registerHandler(command, nullptr);
    ASSERT_FALSE(res); // Fail

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    // Check the new command against the old one
    ASSERT_EQ(cmdNotFound, response.toString());
}

TEST(Registry, AddDuplicateCommand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);
    auto response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    // Add command for the first time
    bool res = registry.registerHandler(
        command,
        [](WazuhRequest) -> WazuhResponse
        { return WazuhResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 1, "OK cmd1"); });

    ASSERT_TRUE(res); // OK
    // Get callback in registry
    cmdTest = registry.getHandler(command);
    response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");

    // Add command
    res = registry.registerHandler(
        command,
        [](WazuhRequest) -> WazuhResponse
        { return WazuhResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 1, "OK cmd2"); });

    ASSERT_FALSE(res); // Fail

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");
}

TEST(Registry, AddMultipleCommands)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};
    std::string command2 {"test2"};

    // Get callback in registry
    auto cmdTest = registry.getHandler(command);
    auto response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{},"error":5,"message":"Command \"test\" not found"})");

    // Add command for the first time
    bool res = registry.registerHandler(
        command,
        [](WazuhRequest) -> WazuhResponse
        { return WazuhResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 1, "OK cmd1"); });

    ASSERT_TRUE(res); // OK

    // Add command for the first time
    res = registry.registerHandler(
        command2,
        [](WazuhRequest) -> WazuhResponse
        { return WazuhResponse(json::Json {R"({"testArgKey": "testArgValue"})"}, 2, "OK cmd2"); });

    ASSERT_TRUE(res); // OK

    // Get callback in registry
    cmdTest = registry.getHandler(command);
    response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");

    // Get callback in registry
    cmdTest = registry.getHandler(command2);
    response = cmdTest(WazuhRequest::create("test", "gtest", json::Json {R"({"testArgKey": "testArgValue"})"}));
    ASSERT_EQ(response.toString(), R"({"data":{"testArgKey":"testArgValue"},"error":2,"message":"OK cmd2"})");
}
