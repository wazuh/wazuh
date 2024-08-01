#include <api/kvdb/handlers.hpp>

#include <string>

#include <fmt/format.h>

#include <api/adapter.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/kvdb.pb.h>
#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>

namespace api::kvdb::handlers
{
namespace eKVDB = ::com::wazuh::api::engine::kvdb;
namespace eEngine = ::com::wazuh::api::engine;

constexpr auto MESSAGE_DB_NOT_EXISTS = "The KVDB '{}' does not exist.";
constexpr auto MESSAGE_MISSING_NAME = "Missing /name";
constexpr auto MESSAGE_NAME_EMPTY = "Field /name is empty";
constexpr auto MESSAGE_MISSING_KEY = "Missing /key";
constexpr auto MESSAGE_KEY_EMPTY = "Field /key is empty";

/* Manager Endpoint */

api::HandlerSync managerGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
{
    return [kvdbManager](const api::wpRequest& wRequest) -> api::wpResponse
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

api::HandlerSync managerPost(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
{
    return [kvdbManager](const api::wpRequest& wRequest) -> api::wpResponse
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

        auto errorMsg = !eRequest.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : eRequest.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        if (kvdbManager->existsDB(eRequest.name()))
        {
            return ::api::adapter::genericError<ResponseType>("The Database already exists.");
        }

        base::OptError resultCreate;

        if (eRequest.has_path())
        {
            resultCreate = kvdbManager->createDB(eRequest.name(), eRequest.path());
        }
        else
        {
            resultCreate = kvdbManager->createDB(eRequest.name());
        }

        if (resultCreate)
        {
            const auto message =
                fmt::format("The database could not be created. Error: {}", resultCreate.value().message);
            return ::api::adapter::genericError<ResponseType>(message);
        }

        // Adapt the response to wazuh api
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync managerDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
{
    return [kvdbManager](const api::wpRequest& wRequest) -> api::wpResponse
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

        auto errorMsg = !eRequest.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : eRequest.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        if (!kvdbManager->existsDB(eRequest.name()))
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, eRequest.name()));
        }

        const auto resultDelete = kvdbManager->deleteDB(eRequest.name());

        if (resultDelete)
        {
            return ::api::adapter::genericError<ResponseType>(resultDelete.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync managerDump(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const api::wpRequest& wRequest) -> api::wpResponse
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
        unsigned int page = eRequest.has_page() ? eRequest.page() : DEFAULT_HANDLER_PAGE;
        unsigned int records = eRequest.has_records() ? eRequest.records() : DEFAULT_HANDLER_RECORDS;

        auto errorMsg = !eRequest.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : eRequest.name().empty() ? std::make_optional("Field /name cannot be empty")
                        : eRequest.has_page() && eRequest.page() == 0
                            ? std::make_optional("Field /page must be greater than 0")
                        : eRequest.has_records() && eRequest.records() == 0
                            ? std::make_optional("Field /records must be greater than 0")
                            : std::nullopt;

        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        const auto resultExists = kvdbManager->existsDB(eRequest.name());

        if (!resultExists)
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, eRequest.name()));
        }

        auto resultHandler = kvdbManager->getKVDBHandler(eRequest.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultHandler).message);
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        auto dumpRes = handler->dump(page, records);

        if (std::holds_alternative<base::Error>(dumpRes))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(dumpRes).message);
        }
        const auto& dump = std::get<std::list<std::pair<std::string, std::string>>>(dumpRes);
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
                const auto msg =
                    fmt::format("{}. For key '{}' and value {}", std::get<base::Error>(res).message, key, value);
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
api::HandlerSync dbGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const api::wpRequest& wRequest) -> api::wpResponse
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
        auto errorMsg = !eRequest.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : eRequest.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                        : !eRequest.has_key()     ? std::make_optional(MESSAGE_MISSING_KEY)
                        : eRequest.key().empty()  ? std::make_optional(MESSAGE_KEY_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        if (!kvdbManager->existsDB(eRequest.name()))
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, eRequest.name()));
        }

        auto resultHandler = kvdbManager->getKVDBHandler(eRequest.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultHandler).message);
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        const auto resultGet = handler->get(eRequest.key());

        if (std::holds_alternative<base::Error>(resultGet))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultGet).message);
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(resultGet));
        if (std::holds_alternative<base::Error>(protoVal)) // Should not happen but just in case
        {
            const auto msj =
                std::get<base::Error>(protoVal).message + ". For value " + std::get<std::string>(resultGet);
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

api::HandlerSync dbDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const api::wpRequest& wRequest) -> api::wpResponse
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
        auto errorMsg = !eRequest.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : eRequest.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                        : !eRequest.has_key()     ? std::make_optional(MESSAGE_MISSING_KEY)
                        : eRequest.key().empty()  ? std::make_optional(MESSAGE_KEY_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        if (!kvdbManager->existsDB(eRequest.name()))
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, eRequest.name()));
        }

        auto resultHandler = kvdbManager->getKVDBHandler(eRequest.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultHandler).message);
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

        const auto removeError = handler->remove(eRequest.key());

        if (removeError)
        {
            return ::api::adapter::genericError<ResponseType>(removeError.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync dbPut(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const api::wpRequest& wRequest) -> api::wpResponse
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

        auto errorMsg = !eRequest.has_name()            ? std::make_optional(MESSAGE_MISSING_NAME)
                        : eRequest.name().empty()       ? std::make_optional(MESSAGE_NAME_EMPTY)
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

        if (eRequest.entry().key().empty())
        {
            return ::api::adapter::genericError<ResponseType>(MESSAGE_KEY_EMPTY);
        }

        if (std::get<std::string>(value).empty())
        {
            return ::api::adapter::genericError<ResponseType>("Field /value is empty");
        }

        if (!kvdbManager->existsDB(eRequest.name()))
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, eRequest.name()));
        }

        auto resultHandler = kvdbManager->getKVDBHandler(eRequest.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultHandler).message);
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        const auto setError = handler->set(eRequest.entry().key(), std::get<std::string>(value));

        if (setError)
        {
            return ::api::adapter::genericError<ResponseType>(setError.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::HandlerSync dbSearch(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eKVDB::dbSearch_Request;
        using ResponseType = eKVDB::dbSearch_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);
        unsigned int page = eRequest.has_page() ? eRequest.page() : DEFAULT_HANDLER_PAGE;
        unsigned int records = eRequest.has_records() ? eRequest.records() : DEFAULT_HANDLER_RECORDS;

        // Validate the params request
        auto errorMsg = !eRequest.has_name()        ? std::make_optional(MESSAGE_MISSING_NAME)
                        : eRequest.name().empty()   ? std::make_optional(MESSAGE_NAME_EMPTY)
                        : !eRequest.has_prefix()    ? std::make_optional("Missing /prefix")
                        : eRequest.prefix().empty() ? std::make_optional("Field /prefix is empty")
                        : eRequest.has_page() && eRequest.page() == 0
                            ? std::make_optional("Field /page must be greater than 0")
                        : eRequest.has_records() && eRequest.records() == 0
                            ? std::make_optional("Field /records must be greater than 0")
                            : std::nullopt;

        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        if (!kvdbManager->existsDB(eRequest.name()))
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, eRequest.name()));
        }

        auto resultHandler = kvdbManager->getKVDBHandler(eRequest.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(resultHandler).message);
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

        const auto searchRes = handler->search(eRequest.prefix(), page, records);

        if (std::holds_alternative<base::Error>(searchRes))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(searchRes).message);
        }
        const auto& resultSearch = std::get<std::list<std::pair<std::string, std::string>>>(searchRes);
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        auto entries = eResponse.mutable_entries();
        for (const auto& [key, value] : resultSearch)
        {
            auto entry = eKVDB::Entry();
            entry.mutable_key()->assign(key);

            const auto res = eMessage::eMessageFromJson<google::protobuf::Value>(value);
            if (std::holds_alternative<base::Error>(res)) // Should not happen but just in case
            {
                const auto msg =
                    fmt::format("{}. For key '{}' and value {}", std::get<base::Error>(res).message, key, value);
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

void registerHandlers(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                      const std::string& kvdbScopeName,
                      std::shared_ptr<api::Api> api)
{

    //        Manager (Works on the KVDB manager, create/delete/list/dump KVDBs)
    const bool ok = api->registerHandler("kvdb.manager/post", Api::convertToHandlerAsync(managerPost(kvdbManager)))
                    && api->registerHandler("kvdb.manager/delete", Api::convertToHandlerAsync(managerDelete(kvdbManager)))
                    && api->registerHandler("kvdb.manager/get", Api::convertToHandlerAsync(managerGet(kvdbManager)))
                    && api->registerHandler("kvdb.manager/dump", Api::convertToHandlerAsync(managerDump(kvdbManager, kvdbScopeName))) &&
                    // Specific KVDB (Works on a specific KVDB instance, not on the manager, create/delete/modify keys)
                    api->registerHandler("kvdb.db/put", Api::convertToHandlerAsync(dbPut(kvdbManager, kvdbScopeName)))
                    && api->registerHandler("kvdb.db/delete", Api::convertToHandlerAsync(dbDelete(kvdbManager, kvdbScopeName)))
                    && api->registerHandler("kvdb.db/get", Api::convertToHandlerAsync(dbGet(kvdbManager, kvdbScopeName)))
                    && api->registerHandler("kvdb.db/search", Api::convertToHandlerAsync(dbSearch(kvdbManager, kvdbScopeName)));

    if (!ok)
    {
        throw std::runtime_error("Failed to register KVDB API handlers");
    }
}
} // namespace api::kvdb::handlers
