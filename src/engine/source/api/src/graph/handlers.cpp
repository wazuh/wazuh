
#include "api/graph/handlers.hpp"
#include "api/router/handlers.hpp"

#include <api/adapter.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/graph.pb.h>
#include <hlp/registerParsers.hpp>
#include <kvdb/kvdbManager.hpp>

#include "builder.hpp"
#include "register.hpp"
#include "registry.hpp"

namespace
{
enum class GraphType
{
    POLICY,
    EXPRESSIONS
};
}

using namespace api::router::handlers;

namespace api::graph::handlers
{

namespace eGraph = ::com::wazuh::api::engine::graph;
namespace eEngine = ::com::wazuh::api::engine;

api::Handler resourceGet(const Config& config)
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

        base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
        auto hlpParsers = config.store->get(hlpConfigFileName);
        if (std::holds_alternative<base::Error>(hlpParsers))
        {
            const auto msg = fmt::format("Wazuh Logpar schema could not be loaded from the store: {}",
                                         std::get<base::Error>(hlpParsers).message);
            return ::api::adapter::genericError<ResponseType>(msg);
        }
        auto logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers));
        hlp::registerParsers(logpar);

        auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
        try
        {

            builder::internals::dependencies deps;
            deps.logparDebugLvl = 0;
            deps.logpar = logpar;
            deps.kvdbManager = config.kvdbManager;
            deps.helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
            builder::internals::registerHelperBuilders(deps.helperRegistry, deps);
            builder::internals::registerBuilders(registry, deps);
        }
        catch (const std::exception& e)
        {
            const auto msg = fmt::format("An error occurred while registering the builders: {}", e.what());
            return ::api::adapter::genericError<ResponseType>(msg);
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

        builder::Builder policyBuilder(config.store, registry);
        decltype(policyBuilder.buildPolicy({})) policy;
        try
        {
            policy = policyBuilder.buildPolicy({policyName});
        }
        catch (const std::exception& e)
        {
            const auto msg = fmt::format("An error occurred while building the policy: {}", e.what());
            return ::api::adapter::genericError<ResponseType>(msg);
        }

        ResponseType eResponse;

        if (GraphType::POLICY == graphType)
        {
            eResponse.set_content(policy.getGraphivzStr());
        }
        else
        {
            base::Expression policyExpression;
            try
            {
                policyExpression = policy.getExpression();
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
    const bool ok = api->registerHandler("graph.resource/get", resourceGet(config));

    if (!ok)
    {
        throw std::runtime_error("Failed to register catalog handlers");
    }
}

} // namespace api::graph::handlers
