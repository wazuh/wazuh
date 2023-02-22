#include "api/kvdb/commands.hpp"

#include <string>

#include <eMessages/eMessage.h>
#include <eMessages/kbdb.pb.h>
#include <fmt/format.h>
#include <json/json.hpp>

#include <utils/stringUtils.hpp>

namespace api::kvdb::cmds
{
namespace eKVDB = ::com::wazuh::api::engine::kvdb;
namespace eEngine = ::com::wazuh::api::engine;


/* Manager Endpoint */

api::CommandFn managerGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        eKVDB::managerGet_Response eResponse;

        const auto params = request.getParameters().value().str(); // The request is validated by the server
        const auto result = eMessage::eMessageFromJson<eKVDB::managerGet_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            eResponse.set_status(eEngine::ReturnStatus::OK);
            const auto& eRequest = std::get<eKVDB::managerGet_Request>(result);
            // TODO: The filter should be applied in the KVDB manager not here
            auto kvdbLists = kvdbManager->listDBs(eRequest.must_be_loaded());

            auto eList = eResponse.mutable_dbs();
            for (const std::string& dbName : kvdbLists)
            {
                eList->Add(dbName.c_str());
            }
        }

        // Adapt the response to the engine
        const auto resJson = eMessage::eMessageToJson<eKVDB::managerGet_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn managerPost(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        const auto params = request.getParameters().value().str(); // The request is validated by the server
        const auto result = eMessage::eMessageFromJson<eKVDB::managerPost_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eKVDB::managerPost_Request>(result);
            errorMsg = !eRequest.has_name() ? std::make_optional("Missing /name") : std::nullopt;

            if (!errorMsg.has_value())
            {
                const auto path = eRequest.has_path() ? eRequest.path() : std::string {""};
                auto result = kvdbManager->createFromJFile(eRequest.name(), path);
                if (result.has_value())
                {
                    errorMsg = std::make_optional(result.value().message);
                }
            }
        }

        if (errorMsg.has_value())
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(errorMsg.value());
        }
        else
        {
            eResponse.set_status(eEngine::ReturnStatus::OK);
        }

        // Adapt the response to the engine
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn managerDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        const auto params = request.getParameters().value().str(); // The request is validated by the server
        const auto result = eMessage::eMessageFromJson<eKVDB::managerDelete_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eKVDB::managerDelete_Request>(result);
            errorMsg = !eRequest.has_name() ? std::make_optional("Missing /name") : std::nullopt;

            if (!errorMsg.has_value())
            {
                auto result = kvdbManager->deleteDB(eRequest.name());
                if (result.has_value())
                {
                    errorMsg = std::make_optional(result.value().message);
                }
            }
        }

        if (errorMsg.has_value())
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(errorMsg.value());
        }
        else
        {
            eResponse.set_status(eEngine::ReturnStatus::OK);
        }

        // Adapt the response to the engine
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn managerDump(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        eKVDB::managerDump_Response eResponse;

        const auto params = request.getParameters().value().str(); // The request is validated by the server
        const auto result = eMessage::eMessageFromJson<eKVDB::managerDump_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eKVDB::managerDump_Request>(result);
            errorMsg = !eRequest.has_name() ? std::make_optional("Missing /name") : std::nullopt;

            if (!errorMsg.has_value())
            {
                auto result = kvdbManager->rDumpDB(eRequest.name());
                if (std::holds_alternative<base::Error>(result))
                {
                    errorMsg = std::make_optional(std::get<base::Error>(result).message);
                }
                else
                {
                    const auto& dump = std::get<std::unordered_map<std::string, std::string>>(result);

                    auto entries = eResponse.mutable_entries();
                    for (const auto& [key, value] : dump)
                    {
                        auto entry = eKVDB::Entry();
                        entry.mutable_key()->assign(key);

                        const auto res = eMessage::eMessageFromJson<google::protobuf::Value>(value);
                        if (std::holds_alternative<base::Error>(res)) // Should not happen but just in case
                        {
                            errorMsg = std::make_optional(std::get<base::Error>(res).message + ". For key '" + key
                                                          + "' and value " + value);
                            break;
                        }
                        const auto json_value = std::get<google::protobuf::Value>(res);
                        entry.mutable_value()->CopyFrom(json_value);
                        entries->Add(std::move(entry));
                    }
                    eResponse.set_status(eEngine::ReturnStatus::OK);
                }
            }
        }

        if (errorMsg.has_value())
        {
            eResponse.Clear();
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(errorMsg.value());
        }

        // Adapt the response to the engine
        const auto resJson = eMessage::eMessageToJson<eKVDB::managerDump_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

/* Specific DB endpoint */
api::CommandFn dbGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        eKVDB::dbGet_Response eResponse;

        const auto params = request.getParameters().value().str(); // The request is validated by the server
        const auto result = eMessage::eMessageFromJson<eKVDB::dbGet_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eKVDB::dbGet_Request>(result);
            errorMsg = !eRequest.has_name()  ? std::make_optional("Missing /name")
                       : !eRequest.has_key() ? std::make_optional("Missing /key")
                                             : std::nullopt;

            if (!errorMsg.has_value())
            {
                auto result = kvdbManager->getRawValue(eRequest.name(), eRequest.key());
                if (std::holds_alternative<base::Error>(result))
                {
                    errorMsg = std::make_optional(std::get<base::Error>(result).message);
                }
                else
                {
                    const auto res = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(result));
                    if (std::holds_alternative<base::Error>(res)) // Should not happen but just in case
                    {
                        errorMsg = std::make_optional(std::get<base::Error>(res).message + ". For value "
                                                      + std::get<std::string>(result));
                    }
                    else
                    {
                        const auto json_value = std::get<google::protobuf::Value>(res);
                        eResponse.mutable_value()->CopyFrom(json_value);
                        eResponse.set_status(eEngine::ReturnStatus::OK);
                    }
                }
            }
        }

        if (errorMsg.has_value())
        {
            eResponse.Clear();
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(errorMsg.value());
        }

        // Adapt the response to the engine
        const auto resJson = eMessage::eMessageToJson<eKVDB::dbGet_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn dbDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        const auto params = request.getParameters().value().str(); // The request is validated by the server
        const auto result = eMessage::eMessageFromJson<eKVDB::dbDelete_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eKVDB::dbDelete_Request>(result);
            errorMsg = !eRequest.has_name()  ? std::make_optional("Missing /name")
                       : !eRequest.has_key() ? std::make_optional("Missing /key")
                                             : std::nullopt;

            if (!errorMsg.has_value())
            {
                auto err = kvdbManager->deleteKey(eRequest.name(), eRequest.key());
                if (err.has_value())
                {
                    errorMsg = std::make_optional(err.value().message);
                }
                else
                {
                    eResponse.set_status(eEngine::ReturnStatus::OK);
                }
            }
        }

        if (errorMsg.has_value())
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(errorMsg.value());
        }

        // Adapt the response to the engine
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn dbPut(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager) {
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        const auto params = request.getParameters().value().str(); // The request is validated by the server
        const auto result = eMessage::eMessageFromJson<eKVDB::dbPut_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eKVDB::dbPut_Request>(result);

            errorMsg = !eRequest.has_name()            ? std::make_optional("Missing /name")
                       : !eRequest.has_entry()         ? std::make_optional("Missing /entry")
                       : !eRequest.entry().has_key()   ? std::make_optional("Missing /entry/key")
                       : !eRequest.entry().has_value() ? std::make_optional("Missing /entry/value")
                                                       : std::nullopt;

            if (!errorMsg.has_value())
            {
                // get the value as a string
                const auto value = eMessage::eMessageToJson<google::protobuf::Value>(eRequest.entry().value());
                if (std::holds_alternative<base::Error>(value))
                {
                    errorMsg = std::make_optional(std::get<base::Error>(value).message);
                }
                else
                {
                    const auto err = kvdbManager->writeRaw(eRequest.name(), eRequest.entry().key(), std::get<std::string>(value));
                    if (err.has_value())
                    {
                        errorMsg = std::make_optional(err.value().message);
                    }
                    else
                    {
                        eResponse.set_status(eEngine::ReturnStatus::OK);
                    }
                }

            }
        }

        if (errorMsg.has_value())
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(errorMsg.value());
        }

        // Adapt the response to the engine
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

void registerAllCmds(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager, std::shared_ptr<api::Registry> registry)
{
    try // TODO: TRY ????
    {
        // Manager (Works on the KVDB manager, create/delete/list/dump KVDBs)
        registry->registerCommand("kvdb.manager/post", managerPost(kvdbManager));
        registry->registerCommand("kvdb.manager/delete", managerDelete(kvdbManager));
        registry->registerCommand("kvdb.manager/get", managerGet(kvdbManager));
        registry->registerCommand("kvdb.manager/dump", managerDump(kvdbManager));

        // Specific KVDB (Works on a specific KVDB instance, not on the manager, create/delete/modify keys)
        registry->registerCommand("kvdb.db/put", dbPut(kvdbManager));
        registry->registerCommand("kvdb.db/delete", dbDelete(kvdbManager));
        registry->registerCommand("kvdb.db/get", dbGet(kvdbManager));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("KVDB API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::kvdb::cmds
