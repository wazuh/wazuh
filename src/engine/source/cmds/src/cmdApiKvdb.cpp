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

static void kvdbCreate(const std::string& socketPath,
                       const std::string& kvdbName,
                       const std::string& kvdbInputFilePath)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_CREATE_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(kvdbInputFilePath, "/path");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_CREATE_SUBCOMMAND) + API_KVDB_CMD_SUFIX, "api", data);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine \"kvdb\" command: \"{}\" method: {}.", __func__, e.what());
        return;
    }

    if (response.getInt("/error").value_or(kvdb_manager::API_ERROR_CODE)
        != kvdb_manager::API_SUCCESS_CODE)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    const std::string msg {fmt::format("KVDB \"{}\" successfully created", kvdbName)};
    std::cout << msg << std::endl;
}

static void
kvdbDelete(const std::string& socketPath, const std::string& kvdbName, bool loaded)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_DELETE_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");

    const auto req = api::WazuhRequest::create(
        std::string(API_KVDB_DELETE_SUBCOMMAND) + API_KVDB_CMD_SUFIX, "api", data);

    // send request
    json::Json response {};
    try
    {
        const std::string responseStr {apiclnt::connection(socketPath, req.toStr())};
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    if (response.getInt("/error").value_or(kvdb_manager::API_ERROR_CODE)
        != kvdb_manager::API_SUCCESS_CODE)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    const std::string msg {fmt::format("KVDB \"{}\" successfully deleted", kvdbName)};
    std::cout << msg << std::endl;
}

static void kvdbDump(const std::string& socketPath, const std::string& kvdbName)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_DUMP_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");

    const auto req = api::WazuhRequest::create(
        std::string(API_KVDB_DUMP_SUBCOMMAND) + API_KVDB_CMD_SUFIX, "api", data);

    // send request
    json::Json response {};
    try
    {
        const auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine \"kvdb\" command: \"{}\" method: {}.", __func__, e.what());
        return;
    }

    if (response.getInt("/error").value_or(kvdb_manager::API_ERROR_CODE)
        != kvdb_manager::API_SUCCESS_CODE)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    auto kvdbContent = response.str("/data");
    if (kvdbContent.has_value())
    {
        const std::string msg {
            fmt::format("KVDB \"{}\" content:\n{}", kvdbName, kvdbContent.value())};
        std::cout << msg << std::endl;
    }
    else
    {
        const std::string msg {fmt::format("KVDB \"{}\" is empty", kvdbName)};
        std::cout << msg << std::endl;
    }

    return;
}

static void kvdbGetValue(const std::string& socketPath,
                         const std::string& kvdbName,
                         const std::string& key)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_GET_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(key, "/key");

    const auto req = api::WazuhRequest::create(
        std::string(API_KVDB_GET_SUBCOMMAND) + API_KVDB_CMD_SUFIX, "api", data);

    // send request
    json::Json response {};
    try
    {
        const auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine \"kvdb\" command: \"{}\" method: {}.", __func__, e.what());
        return;
    }

    if (response.getInt("/error").value_or(kvdb_manager::API_ERROR_CODE)
        != kvdb_manager::API_SUCCESS_CODE)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    const auto resultKey = response.getString("/data/key");
    if (!resultKey)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: Key could not be found "
                        "in the response.",
                        __func__);
        return;
    }
    const auto resultVal = response.getString("/data/value");
    if (!resultVal)
    {
        WAZUH_LOG_ERROR(
            "Engine \"kvdb\" command: \"{}\" method: Value could not be found "
            "in the response.",
            __func__);
        return;
    }

    const std::string msg {fmt::format("KVDB: {}\n- Key: {}\n- Value: {}",
                                       kvdbName,
                                       resultKey.value(),
                                       resultVal.value())};
    std::cout << msg << std::endl;

    return;
}

static void kvdbInsertKeyValue(const std::string& socketPath,
                               const std::string& kvdbName,
                               const std::string& key,
                               const std::string& keyValue)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_INSERT_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(key, "/key");
    data.setString(keyValue, "/value");

    auto req = api::WazuhRequest::create(
        std::string(API_KVDB_INSERT_SUBCOMMAND) + API_KVDB_CMD_SUFIX, "api", data);

    WAZUH_LOG_DEBUG("Engine \"kvdb\" command: \"{}\" method: KVDB \"{}\": Key=\"{}\" "
                    "Value={}.",
                    __func__,
                    kvdbName,
                    key,
                    keyValue);

    // send request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine \"kvdb\" command: \"{}\" method: {}.", __func__, e.what());
        return;
    }

    if (response.getInt("/error").value_or(kvdb_manager::API_ERROR_CODE)
        != kvdb_manager::API_SUCCESS_CODE)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    const std::string msg {
        fmt::format("KVDB \"{}\": Key-Value successfully inserted", kvdbName)};
    std::cout << msg << std::endl;

    return;
}

static void
kvdbList(const std::string& socketPath, const std::string& kvdbName, bool loaded)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_LIST_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setBool(loaded, "/mustBeLoaded");

    const auto req = api::WazuhRequest::create(
        std::string(API_KVDB_LIST_SUBCOMMAND) + API_KVDB_CMD_SUFIX, "api", data);

    // send request
    json::Json response {};
    try
    {
        const auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine \"kvdb\" command: \"{}\" method: {}.", __func__, e.what());
        return;
    }

    if (response.getInt("/error").value_or(kvdb_manager::API_ERROR_CODE)
        != kvdb_manager::API_SUCCESS_CODE)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    const auto kvdbList = response.getArray("/data");
    if (!kvdbList.has_value())
    {
        const std::string msg {"No KVDB is available"};
        std::cout << msg << std::endl;
        return;
    }

    const size_t qttyKVDB = kvdbList.value().size();

    const std::string msg {fmt::format("Databases available: {}", qttyKVDB)};
    std::cout << msg << std::endl;

    size_t i = 0;
    for (const auto& kvdb : *kvdbList)
    {
        if (!kvdb.getString().has_value())
        {
            WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: Database name could "
                            "not be obtained.",
                            __func__);
            continue;
        }

        const std::string msg {
            fmt::format("{}/{} - {}", ++i, qttyKVDB, kvdb.getString().value())};
        std::cout << msg << std::endl;
    }
}

static void kvdbRemoveKV(const std::string& socketPath,
                         const std::string& kvdbName,
                         const std::string& key)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString(API_KVDB_REMOVE_SUBCOMMAND, "/action");
    data.setString(kvdbName, "/name");
    data.setString(key, "/key");

    const auto req = api::WazuhRequest::create(
        std::string(API_KVDB_REMOVE_SUBCOMMAND) + API_KVDB_CMD_SUFIX, "api", data);

    // send request
    json::Json response {};
    try
    {
        const auto responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR(
            "Engine \"kvdb\" command: \"{}\" method: {}.", __func__, e.what());
        return;
    }

    if (response.getInt("/error").value_or(kvdb_manager::API_ERROR_CODE)
        != kvdb_manager::API_SUCCESS_CODE)
    {
        WAZUH_LOG_ERROR("Engine \"kvdb\" command: \"{}\" method: {}.",
                        __func__,
                        response.getString("/message").value_or("Unknown error"));
        return;
    }

    const std::string msg {fmt::format("KVDB \"{}\": Key \"{}\" deleted", kvdbName, key)};
    std::cout << msg << std::endl;

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
