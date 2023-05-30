#include "api/test/handlers.hpp"

#include <api/adapter.hpp>

#include <eMessages/eMessage.h>
#include <eMessages/test.pb.h>

#include "api/test/sessionManager.hpp"

namespace api::test::handlers
{

namespace eTest = ::com::wazuh::api::engine::test;
namespace eEngine = ::com::wazuh::api::engine;

api::Handler resourceNew(void)
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::New_Request;
        using ResponseType = eTest::New_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        // Field name, policy and lifespan are required
        const auto errorMsg = !eRequest.has_name()     ? std::make_optional("Missing /name field")
                              : !eRequest.has_policy() ? std::make_optional("Missing /policy field")
                                                       : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        auto& sessionManager = api::sessionManager::SessionManager::getInstance();

        const auto result = sessionManager.createSession(eRequest.name(), eRequest.policy(), eRequest.lifespan());

        if (result.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(result.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler resourceGet(void)
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::Get_Request;
        using ResponseType = eTest::Get_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        const auto errorMsg = !eRequest.has_name() ? std::make_optional("Missing /name field") : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        auto& sessionManager = api::sessionManager::SessionManager::getInstance();
        const auto session = sessionManager.getSession(eRequest.name());
        if (!session.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Session '{}' could not be found", eRequest.name()));
        }

        ResponseType eResponse;

        // TODO: improve creation date representation
        eResponse.set_creationdate(std::to_string(session->getCreationDate()));
        eResponse.set_id(session->getSessionID());
        eResponse.set_lifespan(session->getLifespan());
        eResponse.set_policyname(session->getPolicyName());
        eResponse.set_routename(session->getRouteName());

        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler resourceList(void)
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::List_Request;
        using ResponseType = eTest::List_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        auto& sessionManager = api::sessionManager::SessionManager::getInstance();
        auto list = sessionManager.getSessionsList();

        ResponseType eResponse;
        for (const auto& sessionName : list)
        {
            eResponse.add_list(sessionName);
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler resourceRemove(void)
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::Remove_Request;
        using ResponseType = eTest::Remove_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        const auto errorMsg =
            !eRequest.has_name() && !eRequest.has_removeall()
                ? std::make_optional("Missing both /name and /removeall fields, at least one field must be set")
                : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        auto& sessionManager = api::sessionManager::SessionManager::getInstance();

        if (eRequest.has_removeall() && eRequest.removeall())
        {
            if (!sessionManager.removeAllSessions())
            {
                return ::api::adapter::genericError<ResponseType>(
                    fmt::format("Sessions could not be deleted", eRequest.name()));
            }
        }
        else if (eRequest.has_name())
        {
            const auto session = sessionManager.getSession(eRequest.name());
            if (!session.has_value())
            {
                return ::api::adapter::genericError<ResponseType>(
                    fmt::format("Session '{}' could not be found", eRequest.name()));
            }

            if (!sessionManager.removeSession(eRequest.name()))
            {
                return ::api::adapter::genericError<ResponseType>(
                    fmt::format("Session '{}' could not be deleted", eRequest.name()));
            }
        }
        else
        {
            return ::api::adapter::genericError<ResponseType>("Invalid request");
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

void registerHandlers(const Config& config, std::shared_ptr<api::Api> api)
{
    try
    {
        api->registerHandler("test.resource/remove", resourceRemove());
        api->registerHandler("test.resource/get", resourceGet());
        api->registerHandler("test.resource/list", resourceList());
        api->registerHandler("test.resource/new", resourceNew());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("test API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::test::handlers
