#include "cmds/cmdApiKvdb.hpp"

#include <fstream>
#include <iostream>

#include <fmt/format.h>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

#include "apiclnt/connection.hpp"
#include "base/utils/getExceptionStack.hpp"

namespace cmd
{

namespace
{

constexpr auto API_KVDB_CMD_SUFIX {"_kvdb"};
constexpr auto API_KVDB_CREATE_SUBCOMMAND {"create"};
constexpr auto API_KVDB_DELETE_SUBCOMMAND {"delete"};
constexpr auto API_KVDB_DUMP_SUBCOMMAND {"dump"};
constexpr auto API_KVDB_GET_SUBCOMMAND {"get"};
constexpr auto API_KVDB_INSERT_SUBCOMMAND {"insert"};
constexpr auto API_KVDB_LIST_SUBCOMMAND {"list"};
constexpr auto API_KVDB_REMOVE_SUBCOMMAND {"remove"};

std::optional<api::WazuhResponse> getResponse(const std::string& socketPath,
                                              const api::WazuhRequest& req)
{

    try
    {
        const auto responseStr {apiclnt::connection(socketPath, req.toStr())};
        return api::WazuhResponse::fromStr(responseStr);
    }
    catch (const std::exception& e)
    {
        std::cerr << fmt::format("Engine 'kvdb' command: '{}' method: {}.",
                                 req.getCommand().value_or("Unknown command"),
                                 e.what())
                  << std::endl;
        return std::nullopt;
    }
}

void kvdbCreate(const std::string& socketPath,
                const std::string& kvdbName,
                const std::string& kvdbInputFilePath)
{
    const auto command = std::string {API_KVDB_CREATE_SUBCOMMAND} + API_KVDB_CMD_SUFIX;
    // create request
    json::Json data {};
    data.setObject();
    // TODO: This is not needed now but should be the command
    data.setString(API_KVDB_CREATE_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(kvdbInputFilePath, "/path");

    auto req = api::WazuhRequest::create(command, "api", data);

    // send request
    const auto response {getResponse(socketPath, req)};

    if (!response)
    {
        return;
    }

    if (!response.value().message().has_value())
    {
        std::cerr << fmt::format("Unexpected response from command: '{}'.", command);
        return;
    }
    std::cout << response.value().message().value() << std::endl;
}

void kvdbDelete(const std::string& socketPath, const std::string& kvdbName, bool loaded)
{
    const auto command = std::string {API_KVDB_DELETE_SUBCOMMAND} + API_KVDB_CMD_SUFIX;
    // create request
    json::Json data {};
    data.setObject();
    // TODO: This is not needed now but should be the command
    data.setString(API_KVDB_DELETE_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");

    const auto req = api::WazuhRequest::create(command, "api", data);

    // send request
    const auto response {getResponse(socketPath, req)};

    if (!response)
    {
        return;
    }

    if (!response.value().message().has_value())
    {
        std::cerr << fmt::format("Unexpected response from command: '{}'. \n", command);
        return;
    }
    std::cout << response.value().message().value() << std::endl;
}

void kvdbDump(const std::string& socketPath, const std::string& kvdbName)
{
    const auto command = std::string {API_KVDB_DUMP_SUBCOMMAND} + API_KVDB_CMD_SUFIX;
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_DUMP_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");

    const auto req = api::WazuhRequest::create(command, "api", data);

    // send request
    const auto response {getResponse(socketPath, req)};
    if (!response)
    {
        return;
    }

    if (!response.value().message().has_value())
    {
        std::cerr << fmt::format("Unexpected response from command: '{}'.", command);
        return;
    }
    if (!response.value().data().isArray())
    {
        std::cerr << response.value().message().value() << std::endl;
        return;
    }
    std::cout << response.value().data().str() << std::endl;
}

void kvdbGetValue(const std::string& socketPath,
                  const std::string& kvdbName,
                  const std::string& key)
{
    const auto command = std::string {API_KVDB_GET_SUBCOMMAND} + API_KVDB_CMD_SUFIX;
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_GET_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(key, "/key");

    const auto req = api::WazuhRequest::create(command, "api", data);

    // send request
    const auto response {getResponse(socketPath, req)};
    if (!response)
    {
        return;
    }

    if (response.value().message().has_value())
    {
        std::cout << response.value().message().value() << std::endl;
    }

    const auto& resData = response.value().data();
    if (resData.exists("/value") && resData.exists("/key") && resData.isString("/key"))
    {
        const auto dataKey = resData.getString("/key").value();
        const auto dataVal = resData.str("/value").value();
        std::cout << fmt::format("Key: {}\nValue: {}\n", dataKey, dataVal);
    }

    return;
}

void kvdbInsertKeyValue(const std::string& socketPath,
                        const std::string& kvdbName,
                        const std::string& key,
                        const std::string& keyValue)
{
    const auto command = std::string {API_KVDB_INSERT_SUBCOMMAND} + API_KVDB_CMD_SUFIX;
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_INSERT_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(key, "/key");

    // check if value is a json
    try
    {
        json::Json value {keyValue.c_str()};
        data.set("/value", value);
    }
    catch (const std::exception& e)
    {
        // If not, set it as a string
        data.setString(keyValue, "/value");
    }

    auto req = api::WazuhRequest::create(command, "api", data);

    // send request
    const auto response {getResponse(socketPath, req)};
    if (!response)
    {
        return;
    }

    if (!response.value().message().has_value())
    {
        std::cerr << fmt::format("Unexpected response from command: '{}'.\n", command);
        return;
    }
    std::cout << response.value().message().value() << std::endl;

    return;
}

void kvdbList(const std::string& socketPath, const std::string& kvdbName, bool loaded)
{
    const auto command = std::string {API_KVDB_LIST_SUBCOMMAND} + API_KVDB_CMD_SUFIX;
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_LIST_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setBool(loaded, "/mustBeLoaded");

    const auto req = api::WazuhRequest::create(command, "api", data);

    // send request
    const auto response {getResponse(socketPath, req)};
    if (!response)
    {
        return;
    }

    const auto kvdbList = response.value().data().getArray();

    if (!kvdbList.has_value())
    {
        std::cerr << fmt::format("unexpected response from command: '{}'.\n", command);
        return;
    }

    const auto qttyKVDB = kvdbList.value().size();

    const std::string msg {fmt::format("Databases found: {}", qttyKVDB)};
    std::cout << msg << std::endl;

    size_t i = 0;
    for (const auto& kvdb : *kvdbList)
    {
        if (!kvdb.getString().has_value())
        {
            std::cerr << fmt::format(
                "unexpected response from command: '{}'. Element: {} is not a string.\n",
                command,
                kvdb.str());
            continue;
        }

        const std::string msg {
            fmt::format("{}/{} - {}", ++i, qttyKVDB, kvdb.getString().value())};
        std::cout << msg << std::endl;
    }
}

void kvdbRemoveKV(const std::string& socketPath,
                  const std::string& kvdbName,
                  const std::string& key)
{
    const auto command = std::string {API_KVDB_REMOVE_SUBCOMMAND} + API_KVDB_CMD_SUFIX;
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_REMOVE_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(key, "/key");

    const auto req = api::WazuhRequest::create(command, "api", data);

    // send request
    const auto response {getResponse(socketPath, req)};
    if (!response)
    {
        return;
    }

    if (!response.value().message().has_value())
    {
        std::cerr << fmt::format("Unexpected response from command: '{}'.\n", command);
        return;
    }
    std::cout << response.value().message().value() << std::endl;

    return;
}

} // namespace

void kvdb(const std::string& kvdbName,
          const std::string& socketPath,
          const std::string& action,
          const std::string& kvdbInputFilePath,
          bool loaded,
          const std::string& kvdbKey,
          const std::string& kvdbKeyValue)
{

    if (action == API_KVDB_CREATE_SUBCOMMAND)
    {
        kvdbCreate(socketPath, kvdbName, kvdbInputFilePath);
    }
    else if (action == API_KVDB_DELETE_SUBCOMMAND)
    {
        kvdbDelete(socketPath, kvdbName, loaded);
    }
    else if (action == API_KVDB_DUMP_SUBCOMMAND)
    {
        kvdbDump(socketPath, kvdbName);
    }
    else if (action == API_KVDB_GET_SUBCOMMAND)
    {
        kvdbGetValue(socketPath, kvdbName, kvdbKey);
    }
    else if (action == API_KVDB_INSERT_SUBCOMMAND)
    {
        kvdbInsertKeyValue(socketPath, kvdbName, kvdbKey, kvdbKeyValue);
    }
    else if (action == API_KVDB_LIST_SUBCOMMAND)
    {
        kvdbList(socketPath, kvdbName, loaded);
    }
    else if (action == API_KVDB_REMOVE_SUBCOMMAND)
    {
        kvdbRemoveKV(socketPath, kvdbName, kvdbKey);
    }

    return;
}

} // namespace cmd
