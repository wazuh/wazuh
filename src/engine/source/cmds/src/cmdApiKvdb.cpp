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

void listKvdbs(const std::string& socketPath)
{
    // create request
    json::Json data {};
    data.setObject();
    data.setString("list", "/action");

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
    if (!kvdbList)
    {
        std::cerr << "Error getting list of KVDBs: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }
    else if (kvdbList.value().empty())
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

}

void kvdb(const std::string& kvdbPath,
          const std::string& kvdbName,
          const std::string& socketPath,
          const std::string& action)
{

    if(action == "list")
    {
        listKvdbs(socketPath);
    }

    return;
}

} // namespace cmd
