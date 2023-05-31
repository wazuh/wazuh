#include <api/kvdb/handlers.hpp>

#include <string>

#include <fmt/format.h>

#include <api/adapter.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/kvdb.pb.h>
#include <json/json.hpp>
#include <utils/stringUtils.hpp>

namespace api::kvdb::handlers
{
namespace eKVDB = ::com::wazuh::api::engine::kvdb;
namespace eEngine = ::com::wazuh::api::engine;

/* Manager Endpoint */

api::Handler managerGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
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

api::Handler managerPost(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
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

        if (eRequest.name() == "")
        {
            return ::api::adapter::genericError<ResponseType>("/name is empty");
        }

        auto resultExists = kvdbManager->existsDB(eRequest.name());

        if (resultExists)
        {
            return ::api::adapter::genericError<ResponseType>("The Database already exists.");
        }

        const auto path = eRequest.has_path() ? eRequest.path() : std::string {""};
        auto resultCreate = kvdbManager->createDB(eRequest.name());
        if (std::holds_alternative<base::Error>(resultCreate))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultCreate).message);
        }

        // Adapt the response to wazuh api
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler managerDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
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

        if (eRequest.name() == "")
        {
            return ::api::adapter::genericError<ResponseType>("/name is empty");
        }

        auto resultExists = kvdbManager->existsDB(eRequest.name());

        if (!resultExists)
        {
            return ::api::adapter::genericError<ResponseType>("/name KVDB does not exist");
        }

        auto resultDelete = kvdbManager->deleteDB(eRequest.name());

        if (std::holds_alternative<base::Error>(resultDelete))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultDelete).message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler managerDump(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbManager, kvdbScope](api::wpRequest wRequest) -> api::wpResponse
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
        if (eRequest.name() == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /name is empty");
        }

        auto resultExists = kvdbManager->existsDB(eRequest.name());

        if (!resultExists)
        {
            return ::api::adapter::genericError<ResponseType>("/name KVDB does not exist");
        }

        auto resultHandler = kvdbScope->getKVDBHandler(eRequest.name());

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(fmt::format("Engine KVDB API: {}", std::get<base::Error>(resultHandler).message));
        }

        auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

        auto dumpRes = handler->dump();

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
api::Handler dbGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbManager, kvdbScope](api::wpRequest wRequest) -> api::wpResponse
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

        if (eRequest.name() == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /name is empty");
        }

        if (eRequest.key() == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /key is empty");
        }

        auto resultExists = kvdbManager->existsDB(eRequest.name());

        if (!resultExists)
        {
            return ::api::adapter::genericError<ResponseType>("/name KVDB does not exist");
        }

        auto resultHandler = kvdbScope->getKVDBHandler(eRequest.name());

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(fmt::format("Engine KVDB API: {}.", std::get<base::Error>(resultHandler).message));
        }

        auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        auto result = handler->get(eRequest.key());

        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(result));
        if (std::holds_alternative<base::Error>(protoVal)) // Should not happen but just in case
        {
            const auto msj = std::get<base::Error>(protoVal).message + ". For value " + std::get<std::string>(result);
            return ::api::adapter::genericError<ResponseType>(msj);
        }

        ResponseType eResponse;
        const auto json_value = std::get<google::protobuf::Value>(protoVal);
        eResponse.mutable_value()->CopyFrom(json_value);
        eResponse.set_status(eEngine::ReturnStatus::OK);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler dbDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbManager, kvdbScope](api::wpRequest wRequest) -> api::wpResponse
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
        auto errorMsg = !eRequest.has_name() ? std::make_optional("Missing /name")
                        : !eRequest.has_key() ? std::make_optional("Missing /key")
                                              : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        if (eRequest.name() == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /name is empty");
        }

        if (eRequest.key() == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /key is empty");
        }

        auto resultExists = kvdbManager->existsDB(eRequest.name());

        if (!resultExists)
        {
            return ::api::adapter::genericError<ResponseType>("/name KVDB does not exist");
        }

        auto resultHandler = kvdbScope->getKVDBHandler(eRequest.name());

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(fmt::format("Engine KVDB API: {}.", std::get<base::Error>(resultHandler).message));
        }

        auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

        auto result = handler->remove(eRequest.key());

        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler dbPut(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbManager, kvdbScope](api::wpRequest wRequest) -> api::wpResponse
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

        if (eRequest.name() == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /name is empty");
        }

        if (eRequest.entry().key() == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /key is empty");
        }

        if (std::get<std::string>(value) == "")
        {
            return ::api::adapter::genericError<ResponseType>("Field /value is empty");
        }

        auto resultExists = kvdbManager->existsDB(eRequest.name());

        if (!resultExists)
        {
            return ::api::adapter::genericError<ResponseType>("/name KVDB does not exist");
        }

        auto resultHandler = kvdbScope->getKVDBHandler(eRequest.name());

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(fmt::format("Engine KVDB API: {}.", std::get<base::Error>(resultHandler).message));
        }

        auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        auto result = handler->set(eRequest.entry().key(), std::get<std::string>(value));

        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

void registerHandlers(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope, std::shared_ptr<api::Api> api)
{

    //        Manager (Works on the KVDB manager, create/delete/list/dump KVDBs)
    const bool ok = api->registerHandler("kvdb.manager/post", managerPost(kvdbManager))
                    && api->registerHandler("kvdb.manager/delete", managerDelete(kvdbManager))
                    && api->registerHandler("kvdb.manager/get", managerGet(kvdbManager))
                    && api->registerHandler("kvdb.manager/dump", managerDump(kvdbManager, kvdbScope)) &&
                    // Specific KVDB (Works on a specific KVDB instance, not on the manager, create/delete/modify keys)
                    api->registerHandler("kvdb.db/put", dbPut(kvdbManager, kvdbScope))
                    && api->registerHandler("kvdb.db/delete", dbDelete(kvdbManager, kvdbScope))
                    && api->registerHandler("kvdb.db/get", dbGet(kvdbManager, kvdbScope));

    if (!ok)
    {
        throw std::runtime_error("Failed to register KVDB API handlers");
    }
}
} // namespace api::kvdb::handlers
