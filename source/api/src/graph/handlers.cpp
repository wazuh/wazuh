
#include "api/graph/handlers.hpp"

#include <api/adapter.hpp>
#include <builder/ibuilder.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/graph.pb.h>
#include <logpar/registerParsers.hpp>
#include <schemf/schema.hpp>

namespace
{
enum class GraphType
{
    POLICY,
    EXPRESSIONS
};
}

namespace api::graph::handlers
{

namespace eGraph = ::com::wazuh::api::engine::graph;
namespace eEngine = ::com::wazuh::api::engine;

api::HandlerSync resourceGet(const Config& config)
{
    return [config](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eGraph::GraphGet_Request;
        using ResponseType = eGraph::GraphGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_policy() ? std::make_optional("Missing or invalid /policy parameter")
                           : !eRequest.has_type() ? std::make_optional("Missing or invalid /type parameter")
                                                  : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        GraphType graphType;

        if (eRequest.type().compare("policy") == 0)
        {
            graphType = GraphType::POLICY;
        }
        else if (eRequest.type().compare("expressions") == 0)
        {
            graphType = GraphType::EXPRESSIONS;
        }
        else
        {
            return ::api::adapter::genericError<ResponseType>(
                "Invalid /type parameter, must be either 'policy' or 'expressions'");
        }

        base::Name policyName;
        try
        {
            policyName = base::Name {eRequest.policy()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /policy name: "} + e.what());
        }

        decltype(config.m_builder->buildPolicy({}, false, false)) policy;
        try
        {
            policy = config.m_builder->buildPolicy({policyName}, false, false);
        }
        catch (const std::exception& e)
        {
            const auto msg = fmt::format("An error occurred while building the policy: {}", e.what());
            return ::api::adapter::genericError<ResponseType>(msg);
        }

        ResponseType eResponse;

        if (GraphType::POLICY == graphType)
        {
            eResponse.set_content(policy->getGraphivzStr());
        }
        else
        {
            base::Expression policyExpression;
            try
            {
                policyExpression = policy->expression();
            }
            catch (const std::exception& e)
            {
                const auto msg =
                    fmt::format("An error occurred while getting the policy expressions graph: {}", e.what());
                return ::api::adapter::genericError<ResponseType>(msg);
            }

            eResponse.set_content(base::toGraphvizStr(policyExpression));
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

void registerHandlers(const Config& config, std::shared_ptr<api::Api> api)
{
    const bool ok = api->registerHandler("graph.resource/get", Api::convertToHandlerAsync(resourceGet(config)));

    if (!ok)
    {
        throw std::runtime_error("Failed to register catalog handlers");
    }
}

} // namespace api::graph::handlers
