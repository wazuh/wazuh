#include <api/adapter.hpp>
#include <api/kvdb/commands.hpp>

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

api::Handler managerGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eKVDB::managerGet_Request;
        using ResponseType = eKVDB::managerGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        ResponseType eResponse;

        // TODO: The filter should be applied in the KVDB manager not here
        auto kvdbLists = kvdbManager->listDBs(eRequest.must_be_loaded());
        auto eList = eResponse.mutable_dbs();
        for (const std::string& dbName : kvdbLists)
        {
            eList->Add(dbName.c_str());
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler managerPost(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest wRequest) -> api::wpResponse
    {
                using RequestType = eKVDB::managerPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        if (!eRequest.has_name())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /name");
        }

        const auto path = eRequest.has_path() ? eRequest.path() : std::string {""};
        auto result = kvdbManager->createFromJFile(eRequest.name(), path);
        if (result.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(result.value().message);
        }

        // Adapt the response to wazuh api
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler managerDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eKVDB::managerDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        if (!eRequest.has_name())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /name");
        }

        // Adapt the response to wazuh api
        auto result = kvdbManager->deleteDB(eRequest.name());
        if (result.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(result.value().message);
        }
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler managerDump(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eKVDB::managerDump_Request;
        using ResponseType = eKVDB::managerDump_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        if (!eRequest.has_name())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /name");
        }

        auto dumpRes = kvdbManager->rDumpDB(eRequest.name());

        if (std::holds_alternative<base::Error>(dumpRes))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(dumpRes).message);
        }
        const auto& dump = std::get<std::unordered_map<std::string, std::string>>(dumpRes);
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        auto entries = eResponse.mutable_entries();
        for (const auto& [key, value] : dump)
        {
            auto entry = eKVDB::Entry();
            entry.mutable_key()->assign(key);

            const auto res = eMessage::eMessageFromJson<google::protobuf::Value>(value);
            if (std::holds_alternative<base::Error>(res)) // Should not happen but just in case
            {
                const auto msg = std::get<base::Error>(res).message + ". For key '" + key + "' and value " + value;
                return ::api::adapter::genericError<ResponseType>(msg);
            }
            const auto json_value = std::get<google::protobuf::Value>(res);
            entry.mutable_value()->CopyFrom(json_value);
            entries->Add(std::move(entry));
        }

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

/* Specific DB endpoint */
api::Handler dbGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eKVDB::dbGet_Request;
        using ResponseType = eKVDB::dbGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        auto errorMsg = !eRequest.has_name()  ? std::make_optional("Missing /name")
                        : !eRequest.has_key() ? std::make_optional("Missing /key")
                                              : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        auto rawVal = kvdbManager->getRawValue(eRequest.name(), eRequest.key());
        if (std::holds_alternative<base::Error>(rawVal))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(rawVal).message);
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(rawVal));
        if (std::holds_alternative<base::Error>(protoVal)) // Should not happen but just in case
        {
            const auto msh = std::get<base::Error>(protoVal).message + ". For value " + std::get<std::string>(rawVal);
        }

        ResponseType eResponse;
        const auto json_value = std::get<google::protobuf::Value>(protoVal);
        eResponse.mutable_value()->CopyFrom(json_value);
        eResponse.set_status(eEngine::ReturnStatus::OK);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler dbDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eKVDB::dbDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        auto errorMsg = !eRequest.has_name()  ? std::make_optional("Missing /name")
                        : !eRequest.has_key() ? std::make_optional("Missing /key")
                                              : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        const auto err = kvdbManager->deleteKey(eRequest.name(), eRequest.key());
        if (err.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler dbPut(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eKVDB::dbPut_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        auto errorMsg = !eRequest.has_name()            ? std::make_optional("Missing /name")
                        : !eRequest.has_entry()         ? std::make_optional("Missing /entry")
                        : !eRequest.entry().has_key()   ? std::make_optional("Missing /entry/key")
                        : !eRequest.entry().has_value() ? std::make_optional("Missing /entry/value")
                                                        : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        // get the value as a string
        const auto value = eMessage::eMessageToJson<google::protobuf::Value>(eRequest.entry().value());
        if (std::holds_alternative<base::Error>(value)) // Should not happen but just in case
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(value).message);
        }

        const auto err = kvdbManager->writeRaw(eRequest.name(), eRequest.entry().key(), std::get<std::string>(value));
        if (err.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }
        return ::api::adapter::genericSuccess<ResponseType>();
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
