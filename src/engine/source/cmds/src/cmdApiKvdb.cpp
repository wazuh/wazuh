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

constexpr auto API_KVDB_COMMAND {"kvdb"};

void createKvdb(const std::string& socketPath, const std::string& kvdb_name, const std::string& kvdbInputFilePath)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString("create", "/action");
    data.setString(kvdb_name, "/name");
    data.setString(kvdbInputFilePath, "/path");

    std::string finalCommand = "create_kvdb";

    auto req = api::WazuhRequest::create(finalCommand, "api", data);

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

void deleteKvdb(const std::string& socketPath, const std::string& name)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString("delete", "/action");
    data.setString(name, "/name");

    std::string finalCommand = "delete_kvdb";

    auto req = api::WazuhRequest::create(finalCommand, "api", data);

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

void dumpKvdb(const std::string& socketPath, const std::string& name) {}

void getKvdb(const std::string& socketPath, const std::string& name) {}

void insertKvdb(const std::string& socketPath, const std::string& name) {}

void listKvdbs(const std::string& socketPath, const std::string& name)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString("list", "/action");
    data.setString(name, "/name");

    std::string finalCommand = "list_kvdb";

    auto req = api::WazuhRequest::create(finalCommand, "api", data);

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
    std::cout << qttyKVDB << " KVDB" << (qttyKVDB > 1 ? "s" : "") << " available" << std::endl;
    size_t i = 0;
    for (const auto& kvdb : *kvdbList)
    {
        std::cout << ++i << "/" << qttyKVDB << " name: "
                  << kvdb.getString().value_or("** Unexpected Error **") << std::endl;
    }

}

void removeKvdb(const std::string& socketPath, const std::string& name) {}
}

void kvdb(const std::string& kvdbPath,
          const std::string& kvdbName,
          const std::string& socketPath,
          const std::string& action,
          const std::string& kvdbInputFilePath)
{

    if (action == "create")
    {
        createKvdb(socketPath,kvdbName,kvdbInputFilePath);
    }
    else if (action == "delete")
    {
        deleteKvdb(socketPath, kvdbName);
    }
    else if (action == "dump")
    {
        dumpKvdb(socketPath,kvdbName);
    }
    else if (action == "get")
    {
        getKvdb(socketPath, kvdbName);
    }
    else if (action == "insert")
    {
        insertKvdb(socketPath, kvdbName);
    }
    else if (action == "list")
    {
        listKvdbs(socketPath, kvdbName);
    }
    else if (action == "remove")
    {
        removeKvdb(socketPath,kvdbName);
    }

    return;
}

} // namespace cmd
