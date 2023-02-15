
#include <gtest/gtest.h>

#include <api/registry.hpp>
#include <json/json.hpp>

TEST(Registry, empty)
{

    // Registry
    api::Registry registry;

    // Get callback in registry
    auto cmdTest = registry.getCallback("test");

    // Execute 2 times the callback fn
    auto response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{},"error":-1,"message":"Command \"test\" not found"})");

    auto response2 = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(), response2.toString());

    auto cmdTestEmpty = registry.getCallback("");
    auto response3 = cmdTestEmpty(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response3.toString(),
              R"({"data":{},"error":-1,"message":"Command \"\" not found"})");
}

TEST(Registry, addComand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    // Get callback in registry
    auto cmdTest = registry.getCallback(command);
    auto response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    auto cmdNotFound = response.toString();
    ASSERT_EQ(response.toString(),
              R"({"data":{},"error":-1,"message":"Command \"test\" not found"})");

    // Add command
    registry.registerCommand(command,
                             [](const json::Json& json) -> base::utils::wazuhProtocol::WazuhResponse {
                                 return base::utils::wazuhProtocol::WazuhResponse {json, 0, "OK"};
                             });

    // Get callback in registry
    cmdTest = registry.getCallback(command);
    response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{"testArgKey":"testArgValue"},"error":0,"message":"OK"})");

    // Check the new command against the old one
    ASSERT_NE(cmdNotFound, response.toString());
}

TEST(Registry, addComandEmpty)
{

    // Registry
    api::Registry registry;
    std::string command {""};

    // Get callback in registry (Not )
    auto cmdTest = registry.getCallback(command);
    auto response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    auto cmdNotFound = response.toString();
    ASSERT_EQ(response.toString(),
              R"({"data":{},"error":-1,"message":"Command \"\" not found"})");

    // Attempt to add command
    bool res = registry.registerCommand(command,
                                        [](const json::Json& json) -> base::utils::wazuhProtocol::WazuhResponse {
                                            return base::utils::wazuhProtocol::WazuhResponse {json, 0, "OK"};
                                        });

    ASSERT_FALSE(res); // Fail

    // Get callback in registry (Not found)
    cmdTest = registry.getCallback(command);
    response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    // Check the new command against the old one
    ASSERT_EQ(cmdNotFound, response.toString());
}

TEST(Registry, addNullCommand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    // Get callback in registry
    auto cmdTest = registry.getCallback(command);
    auto response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    auto cmdNotFound = response.toString();
    ASSERT_EQ(response.toString(),
              R"({"data":{},"error":-1,"message":"Command \"test\" not found"})");

    // Add command
    bool res = registry.registerCommand(command, nullptr);
    ASSERT_FALSE(res); // Fail

    // Get callback in registry
    cmdTest = registry.getCallback(command);
    response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    // Check the new command against the old one
    ASSERT_EQ(cmdNotFound, response.toString());
}

TEST(Registry, AddduplicateCommand)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};

    // Get callback in registry
    auto cmdTest = registry.getCallback(command);
    auto response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{},"error":-1,"message":"Command \"test\" not found"})");

    // Add command for the first time
    bool res =
        registry.registerCommand(command,
                                 [](const json::Json& json) -> base::utils::wazuhProtocol::WazuhResponse {
                                     return base::utils::wazuhProtocol::WazuhResponse {json, 1, "OK cmd1"};
                                 });
    ASSERT_TRUE(res); // OK
    // Get callback in registry
    cmdTest = registry.getCallback(command);
    response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");

    // Add command
    res = registry.registerCommand(command,
                                   [](const json::Json& json) -> base::utils::wazuhProtocol::WazuhResponse {
                                       return base::utils::wazuhProtocol::WazuhResponse {json, 2, "OK cmd2"};
                                   });
    ASSERT_FALSE(res); // Fail

    // Get callback in registry
    cmdTest = registry.getCallback(command);
    response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");
}

TEST(Registry, AddMultipleCommands)
{

    // Registry
    api::Registry registry;
    std::string command {"test"};
    std::string command2 {"test2"};

    // Get callback in registry
    auto cmdTest = registry.getCallback(command);
    auto response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{},"error":-1,"message":"Command \"test\" not found"})");

    // Add command for the first time
    bool res =
        registry.registerCommand(command,
                                 [](const json::Json& json) -> base::utils::wazuhProtocol::WazuhResponse {
                                     return base::utils::wazuhProtocol::WazuhResponse {json, 1, "OK cmd1"};
                                 });
    ASSERT_TRUE(res); // OK

    // Add command for the first time
    res = registry.registerCommand(command2,
                                   [](const json::Json& json) -> base::utils::wazuhProtocol::WazuhResponse {
                                       return base::utils::wazuhProtocol::WazuhResponse {json, 2, "OK cmd2"};
                                   });
    ASSERT_TRUE(res); // OK

    // Get callback in registry
    cmdTest = registry.getCallback(command);
    response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{"testArgKey":"testArgValue"},"error":1,"message":"OK cmd1"})");

    // Get callback in registry
    cmdTest = registry.getCallback(command2);
    response = cmdTest(json::Json {R"({"testArgKey": "testArgValue"})"});
    ASSERT_EQ(response.toString(),
              R"({"data":{"testArgKey":"testArgValue"},"error":2,"message":"OK cmd2"})");
}
