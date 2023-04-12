#include <api/integration/handlers.hpp>

#include <api/adapter.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/integration.pb.h>
#include <json/json.hpp>
#include <name.hpp>

namespace api::integration::handlers
{
namespace eIntegration = ::com::wazuh::api::engine::integration;
namespace eEngine = ::com::wazuh::api::engine;

api::Handler integrationAddTo(std::shared_ptr<api::integration::Integration> integration)
{
    return [integration](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eIntegration::PolicyAddIntegration_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_policy()        ? std::make_optional("Missing /policy parameter")
                           : !eRequest.has_integration() ? std::make_optional("Missing /integration parameter")
                                                         : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the names
        base::Name policyName;
        base::Name integrationName;
        try
        {
            policyName = base::Name {eRequest.policy()};
            integrationName = base::Name {eRequest.integration()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid name in parameter:"} + e.what());
        }

        // Build target policy and integration resources
        catalog::Resource targetPolicy;
        catalog::Resource targetIntegration;
        try
        {
            targetPolicy = catalog::Resource {policyName, catalog::Resource::Format::json};
            targetIntegration = catalog::Resource {integrationName, catalog::Resource::Format::json};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = integration->addTo(targetPolicy, targetIntegration);
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}
api::Handler integrationRemoveFrom(std::shared_ptr<api::integration::Integration> integration)
{
    return [integration](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eIntegration::PolicyDelIntegration_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_policy()        ? std::make_optional("Missing /policy parameter")
                           : !eRequest.has_integration() ? std::make_optional("Missing /integration parameter")
                                                         : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the names
        base::Name policyName;
        base::Name integrationName;
        try
        {
            policyName = base::Name {eRequest.policy()};
            integrationName = base::Name {eRequest.integration()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid name in parameter:"} + e.what());
        }

        // Build target policy and integration resources
        catalog::Resource targetPolicy;
        catalog::Resource targetIntegration;
        try
        {
            targetPolicy = catalog::Resource {policyName, catalog::Resource::Format::json};
            targetIntegration = catalog::Resource {integrationName, catalog::Resource::Format::json};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = integration->removeFrom(targetPolicy, targetIntegration);
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

void registerHandlers(std::shared_ptr<api::integration::Integration> integration,
                      std::shared_ptr<api::Api> api)
{
    api->registerHandler("integration.policy/add_to", integrationAddTo(integration));
    api->registerHandler("integration.policy/remove_from", integrationRemoveFrom(integration));
}
} // namespace api::integration::handlers
