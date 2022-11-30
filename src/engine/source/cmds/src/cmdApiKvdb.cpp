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

constexpr auto API_KVDB_COMMAND {"_kvdb"};
constexpr auto API_KVDB_CREATE_SUBCOMMAND {"create"};
constexpr auto API_KVDB_DELETE_SUBCOMMAND {"delete"};
constexpr auto API_KVDB_DUMP_SUBCOMMAND {"dump"};
constexpr auto API_KVDB_GET_SUBCOMMAND {"get"};
constexpr auto API_KVDB_INSERT_SUBCOMMAND {"insert"};
constexpr auto API_KVDB_LIST_SUBCOMMAND {"list"};
constexpr auto API_KVDB_REMOVE_SUBCOMMAND {"remove"};

void createKvdb(const std::string& socketPath,
                const std::string& kvdb_name,
                const std::string& kvdbInputFilePath)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_CREATE_SUBCOMMAND, "/action");
    data.setString(kvdb_name, "/name");
    data.setString(kvdbInputFilePath, "/path");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_CREATE_SUBCOMMAND) + API_KVDB_COMMAND, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 200)
    {
        std::cerr << "Error creating KVDB: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    std::cout << " KVDB name:" << kvdb_name << " created." << std::endl;
}

void deleteKvdb(const std::string& socketPath, const std::string& name, bool loaded)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_DELETE_SUBCOMMAND, "/action");
    data.setString(name, "/name");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_DELETE_SUBCOMMAND) + API_KVDB_COMMAND, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 200)
    {
        std::cerr << "Error deleting KVDB: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    std::cout << " KVDB name:" << name << " deleted." << std::endl;
}

void dumpKvdb(const std::string& socketPath, const std::string& name)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_DUMP_SUBCOMMAND, "/action");
    data.setString(name, "/name");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_DUMP_SUBCOMMAND) + API_KVDB_COMMAND, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 200)
    {
        std::cerr << "Error getting dump of KVDBs: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    auto kvdbContent = response.str("/data");
    if (!kvdbContent.has_value())
    {
        std::cout << "KVDB is empty" << std::endl;
        return;
    }

    std::cout << "KVDB content:" << std::endl;
    std::cout << kvdbContent.value() << std::endl;
}

void getKvdb(const std::string& socketPath,
             const std::string& name,
             const std::string& key)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_GET_SUBCOMMAND, "/action");
    data.setString(name, "/name");
    data.setString(key, "/key");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_GET_SUBCOMMAND) + API_KVDB_COMMAND, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 200)
    {
        std::cerr << "Error getting key value from KVDBs: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    auto resultKey = response.getString("/data/key").value();
    auto resultVal = response.getString("/data/value").value();

    std::string outputMessage =
        fmt::format("Value [{}] on key [{}] from DB [{}]", resultVal, resultKey, name);
    std::cout << outputMessage << std::endl;
    return;
}

void insertKvdb(const std::string& socketPath,
                const std::string& name,
                const std::string& key,
                const std::string& keyValue)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_INSERT_SUBCOMMAND, "/action");
    data.setString(name, "/name");
    data.setString(key, "/key");
    data.setString(keyValue, "/value");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_INSERT_SUBCOMMAND) + API_KVDB_COMMAND, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 200)
    {
        std::cerr << "Error inserting key value on KVDBs: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    std::string outputMessage {fmt::format("Key [{}] inserted on [{}]", key, name)};
    if ("" != keyValue)
    {
        outputMessage =
            fmt::format("Key value [{},{}] inserted on [{}]", key, keyValue, name);
    }

    std::cout << outputMessage << std::endl;
    return;
}

void listKvdbs(const std::string& socketPath, const std::string& name, bool loaded)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_LIST_SUBCOMMAND, "/action");
    data.setString(name, "/name");
    data.setBool(loaded, "/mustBeLoaded");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_LIST_SUBCOMMAND) + API_KVDB_COMMAND, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 200)
    {
        std::cerr << "Error getting list of KVDBs: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    auto kvdbList = response.getArray("/data");
    if (!kvdbList.has_value())
    {
        std::cout << "No KVDB found" << std::endl;
        return;
    }

    size_t qttyKVDB = kvdbList.value().size();
    std::cout << qttyKVDB << " KVDB" << (qttyKVDB > 1 ? "s" : "") << " available"
              << std::endl;
    size_t i = 0;
    for (const auto& kvdb : *kvdbList)
    {
        std::cout << ++i << "/" << qttyKVDB
                  << " name: " << kvdb.getString().value_or("** Unexpected Error **")
                  << std::endl;
    }
}

void removeKvdb(const std::string& socketPath,
                const std::string& name,
                const std::string& key)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_REMOVE_SUBCOMMAND, "/action");
    data.setString(name, "/name");
    data.setString(key, "/key");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_REMOVE_SUBCOMMAND) + API_KVDB_COMMAND, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 200)
    {
        std::cerr << "Error deleting key on KVDB: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    std::cout << fmt::format("Key [{}] deleted on [{}]", key, name) << std::endl;
    return;
}

} // namespace

void kvdb(const std::string& kvdbPath,
          const std::string& kvdbName,
          const std::string& socketPath,
          const std::string& action,
          const std::string& kvdbInputFilePath,
          bool loaded,
          const std::string& kvdbKey,
          const std::string& kvdbKeyValue)
{

    if (action == API_KVDB_CREATE_SUBCOMMAND)
    {
        createKvdb(socketPath, kvdbName, kvdbInputFilePath);
    }
    else if (action == API_KVDB_DELETE_SUBCOMMAND)
    {
        deleteKvdb(socketPath, kvdbName, loaded);
    }
    else if (action == API_KVDB_DUMP_SUBCOMMAND)
    {
        dumpKvdb(socketPath, kvdbName);
    }
    else if (action == API_KVDB_GET_SUBCOMMAND)
    {
        getKvdb(socketPath, kvdbName, kvdbKey);
    }
    else if (action == API_KVDB_INSERT_SUBCOMMAND)
    {
        insertKvdb(socketPath, kvdbName, kvdbKey, kvdbKeyValue);
    }
    else if (action == API_KVDB_LIST_SUBCOMMAND)
    {
        listKvdbs(socketPath, kvdbName, loaded);
    }
    else if (action == API_KVDB_REMOVE_SUBCOMMAND)
    {
        removeKvdb(socketPath, kvdbName, kvdbKey);
    }

    return;
}

} // namespace cmd
