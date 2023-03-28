#include "api/metrics/handlers.hpp"

#include <json/json.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/metrics.pb.h>

#include <api/adapter.hpp>

namespace api::metrics::handlers
{

namespace eMetrics = ::com::wazuh::api::engine::metrics;
namespace eEngine = ::com::wazuh::api::engine;

/* Manager Endpoint */

api::Handler metricsDumpCmd()
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Dump_Request;
        using ResponseType = eMetrics::Dump_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        ResponseType eResponse;

        auto result = Metrics::instance().getDataHub()->dumpCmd();

        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);

        const auto aux = std::get<std::string>(result);
        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(aux);
        const auto json_value = std::get<google::protobuf::Value>(protoVal);
        eResponse.mutable_value()->CopyFrom(json_value);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

// api::Handler metricsGetCmd()
// {
//     return [](api::wpRequest wRequest) -> api::wpResponse
//     {
//         // Get Metric name parameter
//         const auto [ok, response] = getNameOrError(params);
//         if (!ok)
//         {
//             return api::WazuhResponse {response};
//         }

//         auto result = Metrics::instance().getDataHub()->getCmd(response);
//         if (std::holds_alternative<base::Error>(result))
//         {
//             return api::WazuhResponse {std::get<base::Error>(result).message};
//         }

//         return api::WazuhResponse {
//             std::get<json::Json>(result),
//             fmt::format("Metric successfully obtained")};
//     };
// }

// api::Handler metricsEnableCmd()
// {
//     return [](api::wpRequest wRequest) -> api::wpResponse
//     {
//         auto name = params.getString("/nameInstrument");
//         auto state = params.getBool("/enableState");
//         try
//         {
//             Metrics::instance().setEnableInstrument(name.value(), state.value());
//         }
//         catch (const std::exception& e)
//         {
//             return api::WazuhResponse(e.what());
//         }

//         return api::WazuhResponse("OK");
//     };
// }

// api::Handler metricsListCmd()
// {
//     return [](api::wpRequest wRequest) -> api::wpResponse
//     {
//         auto result = Metrics::instance().getInstrumentsList();
//         return api::WazuhResponse(result.str());
//     };
// }

// api::Handler metricsTestCmd()
// {
//     return [](api::wpRequest wRequest) -> api::wpResponse
//     {
//         Metrics::instance().generateCounterToTesting();
//         return api::WazuhResponse("OK");
//     };
// }

void registerHandlers(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerHandler("metrics/dump", metricsDumpCmd());
        // registry->registerCommand("get_metrics", metricsGetCmd());
        // registry->registerCommand("enable_metrics", metricsEnableCmd());
        // registry->registerCommand("list_metrics", metricsListCmd());
        // registry->registerCommand("test_metrics", metricsTestCmd());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("metrics API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::metrics::handlers
