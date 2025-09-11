#include <api/kvdb/handlers.hpp>

#include <string>

#include <fmt/format.h>

#include <api/adapter/helpers.hpp>
#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/kvdb.pb.h>

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

adapter::RouteHandler managerGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager)](const auto& req, auto& res)
    {
        using RequestType = eKVDB::managerGet_Request;
        using ResponseType = eKVDB::managerGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        // Validate the params request
        ResponseType eResponse;

        auto kvdbLists = kvdb->listDBs(protoReq.must_be_loaded());
        auto eList = eResponse.mutable_dbs();

        for (const std::string& dbName : kvdbLists)
        {
            eList->Add(dbName.c_str());
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler managerPost(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager)](const auto& req, auto& res)
    {
        using RequestType = eKVDB::managerPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        auto errorMsg = !protoReq.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : protoReq.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            res = adapter::userErrorResponse<ResponseType>(errorMsg.value());
            return;
        }

        if (kvdb->existsDB(protoReq.name()))
        {
            res = adapter::userErrorResponse<ResponseType>("The Database already exists.");
            return;
        }

        base::OptError resultCreate;

        if (protoReq.has_path())
        {
            resultCreate = kvdb->createDB(protoReq.name(), protoReq.path());
        }
        else
        {
            resultCreate = kvdb->createDB(protoReq.name());
        }

        if (resultCreate)
        {
            const auto message =
                fmt::format("The database could not be created. Error: {}", resultCreate.value().message);
            res = adapter::userErrorResponse<ResponseType>(message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler managerDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager)](const auto& req, auto& res)
    {
        using RequestType = eKVDB::managerDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        auto errorMsg = !protoReq.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : protoReq.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            res = adapter::userErrorResponse<ResponseType>(errorMsg.value());
            return;
        }

        if (!kvdb->existsDB(protoReq.name()))
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, protoReq.name()));
            return;
        }

        const auto resultDelete = kvdb->deleteDB(protoReq.name());

        if (resultDelete)
        {
            res = adapter::userErrorResponse<ResponseType>(resultDelete.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler managerDump(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager,
                                  const std::string& kvdbScopeName)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager), kvdbScopeName](const auto& req, auto& res)
    {
        using RequestType = eKVDB::managerDump_Request;
        using ResponseType = eKVDB::managerDump_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        unsigned int page = protoReq.has_page() ? protoReq.page() : DEFAULT_HANDLER_PAGE;
        unsigned int records = protoReq.has_records() ? protoReq.records() : DEFAULT_HANDLER_RECORDS;

        auto errorMsg = !protoReq.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : protoReq.name().empty() ? std::make_optional("Field /name cannot be empty")
                        : protoReq.has_page() && protoReq.page() == 0
                            ? std::make_optional("Field /page must be greater than 0")
                        : protoReq.has_records() && protoReq.records() == 0
                            ? std::make_optional("Field /records must be greater than 0")
                            : std::nullopt;

        if (errorMsg.has_value())
        {
            res = adapter::userErrorResponse<ResponseType>(errorMsg.value());
            return;
        }

        const auto resultExists = kvdb->existsDB(protoReq.name());

        if (!resultExists)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, protoReq.name()));
            return;
        }

        auto resultHandler = kvdb->getKVDBHandler(protoReq.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(resultHandler).message);
            return;
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        auto dumpRes = handler->dump(page, records);

        if (std::holds_alternative<base::Error>(dumpRes))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(dumpRes).message);
            return;
        }
        const auto& dump = std::get<std::list<std::pair<std::string, std::string>>>(dumpRes);
        ResponseType eResponse;

        auto entries = eResponse.mutable_entries();
        for (const auto& [key, value] : dump)
        {
            auto entry = eKVDB::Entry();
            entry.mutable_key()->assign(key);

            const auto resp = eMessage::eMessageFromJson<google::protobuf::Value>(value);
            if (std::holds_alternative<base::Error>(resp)) // Should not happen but just in case
            {
                const auto msg =
                    fmt::format("{}. For key '{}' and value {}", std::get<base::Error>(resp).message, key, value);
                res = adapter::userErrorResponse<ResponseType>(msg);
                return;
            }
            const auto json_value = std::get<google::protobuf::Value>(resp);
            entry.mutable_value()->CopyFrom(json_value);
            entries->Add(std::move(entry));
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

/* Specific DB endpoint */
adapter::RouteHandler dbGet(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager), kvdbScopeName](const auto& req, auto& res)
    {
        using RequestType = eKVDB::dbGet_Request;
        using ResponseType = eKVDB::dbGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto errorMsg = !protoReq.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : protoReq.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                        : !protoReq.has_key()     ? std::make_optional(MESSAGE_MISSING_KEY)
                        : protoReq.key().empty()  ? std::make_optional(MESSAGE_KEY_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            res = adapter::userErrorResponse<ResponseType>(errorMsg.value());
            return;
        }

        if (!kvdb->existsDB(protoReq.name()))
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, protoReq.name()));
            return;
        }

        auto resultHandler = kvdb->getKVDBHandler(protoReq.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(resultHandler).message);
            return;
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        const auto resultGet = handler->get(protoReq.key());

        if (std::holds_alternative<base::Error>(resultGet))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(resultGet).message);
            return;
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(resultGet));
        if (std::holds_alternative<base::Error>(protoVal)) // Should not happen but just in case
        {
            const auto msj =
                std::get<base::Error>(protoVal).message + ". For value " + std::get<std::string>(resultGet);
            res = adapter::userErrorResponse<ResponseType>(msj);
            return;
        }

        ResponseType eResponse;
        const auto json_value = std::get<google::protobuf::Value>(protoVal);
        eResponse.mutable_value()->CopyFrom(json_value);
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler dbDelete(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager), kvdbScopeName](const auto& req, auto& res)
    {
        using RequestType = eKVDB::dbDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto errorMsg = !protoReq.has_name()      ? std::make_optional(MESSAGE_MISSING_NAME)
                        : protoReq.name().empty() ? std::make_optional(MESSAGE_NAME_EMPTY)
                        : !protoReq.has_key()     ? std::make_optional(MESSAGE_MISSING_KEY)
                        : protoReq.key().empty()  ? std::make_optional(MESSAGE_KEY_EMPTY)
                                                  : std::nullopt;
        if (errorMsg.has_value())
        {
            res = adapter::userErrorResponse<ResponseType>(errorMsg.value());
            return;
        }

        if (!kvdb->existsDB(protoReq.name()))
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, protoReq.name()));
            return;
        }

        auto resultHandler = kvdb->getKVDBHandler(protoReq.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(resultHandler).message);
            return;
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

        const auto removeError = handler->remove(protoReq.key());

        if (removeError)
        {
            res = adapter::userErrorResponse<ResponseType>(removeError.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler dbPut(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager), kvdbScopeName](const auto& req, auto& res)
    {
        using RequestType = eKVDB::dbPut_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        auto errorMsg = !protoReq.has_name()            ? std::make_optional(MESSAGE_MISSING_NAME)
                        : protoReq.name().empty()       ? std::make_optional(MESSAGE_NAME_EMPTY)
                        : !protoReq.has_entry()         ? std::make_optional("Missing /entry")
                        : !protoReq.entry().has_key()   ? std::make_optional("Missing /entry/key")
                        : !protoReq.entry().has_value() ? std::make_optional("Missing /entry/value")
                                                        : std::nullopt;
        if (errorMsg.has_value())
        {
            res = adapter::userErrorResponse<ResponseType>(errorMsg.value());
            return;
        }

        // get the value as a string
        const auto value = eMessage::eMessageToJson<google::protobuf::Value>(protoReq.entry().value());
        if (std::holds_alternative<base::Error>(value)) // Should not happen but just in case
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(value).message);
            return;
        }

        if (protoReq.entry().key().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_KEY_EMPTY);
            return;
        }

        if (std::get<std::string>(value).empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Field /value is empty");
            return;
        }

        if (!kvdb->existsDB(protoReq.name()))
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, protoReq.name()));
            return;
        }

        auto resultHandler = kvdb->getKVDBHandler(protoReq.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(resultHandler).message);
            return;
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));
        const auto setError = handler->set(protoReq.entry().key(), std::get<std::string>(value));

        if (setError)
        {
            res = adapter::userErrorResponse<ResponseType>(setError.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler dbSearch(std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [wKvdb = std::weak_ptr<::kvdbManager::IKVDBManager>(kvdbManager), kvdbScopeName](const auto& req, auto& res)
    {
        using RequestType = eKVDB::dbSearch_Request;
        using ResponseType = eKVDB::dbSearch_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbManager::IKVDBManager>(req, wKvdb);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdb, protoReq] = adapter::getRes(result);

        unsigned int page = protoReq.has_page() ? protoReq.page() : DEFAULT_HANDLER_PAGE;
        unsigned int records = protoReq.has_records() ? protoReq.records() : DEFAULT_HANDLER_RECORDS;

        // Validate the params request
        auto errorMsg = !protoReq.has_name()        ? std::make_optional(MESSAGE_MISSING_NAME)
                        : protoReq.name().empty()   ? std::make_optional(MESSAGE_NAME_EMPTY)
                        : !protoReq.has_prefix()    ? std::make_optional("Missing /prefix")
                        : protoReq.prefix().empty() ? std::make_optional("Field /prefix is empty")
                        : protoReq.has_page() && protoReq.page() == 0
                            ? std::make_optional("Field /page must be greater than 0")
                        : protoReq.has_records() && protoReq.records() == 0
                            ? std::make_optional("Field /records must be greater than 0")
                            : std::nullopt;

        if (errorMsg.has_value())
        {
            res = adapter::userErrorResponse<ResponseType>(errorMsg.value());
            return;
        }

        if (!kvdb->existsDB(protoReq.name()))
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format(MESSAGE_DB_NOT_EXISTS, protoReq.name()));
            return;
        }

        auto resultHandler = kvdb->getKVDBHandler(protoReq.name(), kvdbScopeName);

        if (std::holds_alternative<base::Error>(resultHandler))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(resultHandler).message);
            return;
        }

        auto handler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler));

        const auto searchRes = handler->search(protoReq.prefix(), page, records);

        if (std::holds_alternative<base::Error>(searchRes))
        {
            res = adapter::userErrorResponse<ResponseType>(std::get<base::Error>(searchRes).message);
            return;
        }
        const auto& resultSearch = std::get<std::list<std::pair<std::string, std::string>>>(searchRes);
        ResponseType eResponse;

        auto entries = eResponse.mutable_entries();
        for (const auto& [key, value] : resultSearch)
        {
            auto entry = eKVDB::Entry();
            entry.mutable_key()->assign(key);

            const auto resp = eMessage::eMessageFromJson<google::protobuf::Value>(value);
            if (std::holds_alternative<base::Error>(resp)) // Should not happen but just in case
            {
                const auto msg =
                    fmt::format("{}. For key '{}' and value {}", std::get<base::Error>(resp).message, key, value);
                res = adapter::userErrorResponse<ResponseType>(msg);
                return;
            }
            const auto json_value = std::get<google::protobuf::Value>(resp);
            entry.mutable_value()->CopyFrom(json_value);
            entries->Add(std::move(entry));
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::kvdb::handlers
