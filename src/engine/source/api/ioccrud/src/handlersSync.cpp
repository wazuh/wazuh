
#include <api/ioccrud/handlers.hpp>

#include <fstream>
#include <random>
#include <sstream>
#include <unordered_set>

#include <fmt/format.h>

#include <eMessages/ioc.pb.h>
#include <eMessages/engine.pb.h>
#include <kvdbioc/helpers.hpp>
#include <base/utils/generator.hpp>


namespace api::ioccrud::handlers
{

namespace eIoc = com::wazuh::api::engine::ioc;
namespace eEngine = com::wazuh::api::engine;


adapter::RouteHandler syncIoc(const std::shared_ptr<::kvdbioc::IKVDBManager>& kvdbManager)
{
    return [weakKvdbManager = std::weak_ptr<::kvdbioc::IKVDBManager>(kvdbManager)](const httplib::Request& req,
                                                                                   httplib::Response& res)
    {
        using RequestType = eIoc::UpdateIoc_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Get handler and parse request
        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbioc::IKVDBManager>(req, weakKvdbManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdbManager, protoReq] = adapter::getRes(result);

        // Validate path is not empty
        if (protoReq.path().empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Field /path cannot be empty");
            return;
        }

        const std::string& filePath = protoReq.path();
        // const std::string& fileHash = protoReq.hash(); // TODO: Use hash for optimization

        try
        {
            // Open the ndjson file
            std::ifstream file(filePath);
            if (!file.is_open())
            {
                res = adapter::userErrorResponse<ResponseType>(
                    fmt::format("Failed to open file: {}", filePath));
                return;
            }

            // Generate random suffix for temporary databases
            const std::string tmpSuffix = "_tmp_" + base::utils::generators::randomHexString(4);
            std::unordered_set<std::string> tempDatabases;

            // Process file line by line
            std::string line;
            size_t lineNumber = 0;
            while (std::getline(file, line))
            {
                ++lineNumber;

                // Skip empty lines
                if (line.empty())
                {
                    continue;
                }

                try
                {
                    // Parse JSON line
                    json::Json iocDoc(line);

                    // Extract DB name and key using helpers
                    auto [dbName, key] = kvdbioc::details::getDbAndKeyFromIOC(iocDoc);

                    // Create temporary DB name
                    std::string tmpDbName = dbName + tmpSuffix;

                    // Create temporary database if it doesn't exist
                    if (tempDatabases.find(tmpDbName) == tempDatabases.end())
                    {
                        if (!kvdbManager->exists(tmpDbName))
                        {
                            kvdbManager->add(tmpDbName);
                        }
                        tempDatabases.insert(tmpDbName);
                    }

                    // Check if key exists if exist, then append to existing value as an array
                    kvdbioc::details::updateValueInDB(kvdbManager, tmpDbName, key, iocDoc);
                }
                catch (const std::exception& e)
                {
                    file.close();
                    res = adapter::userErrorResponse<ResponseType>(
                        fmt::format("Error processing line {}: {}", lineNumber, e.what()));
                    return;
                }
            }

            file.close();

            // Perform hot-swap for each temporary database to production
            for (const auto& tmpDbName : tempDatabases)
            {
                // Extract original DB name by removing the temporary suffix
                std::string originalDbName = tmpDbName.substr(0, tmpDbName.length() - tmpSuffix.length());

                // If the target DB doesn't exist, create it first
                if (!kvdbManager->exists(originalDbName))
                {
                    kvdbManager->add(originalDbName);
                }

                // Hot-swap: move tmp DB to production
                kvdbManager->hotSwap(tmpDbName, originalDbName);
            }

            // Set success response
            ResponseType eResponse;
            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(
                fmt::format("IOC sync failed: {}", e.what()));
            return;
        }
    };
}

} // namespace api::ioccrud::handlers
