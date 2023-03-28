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
        auto result = Metrics::instance().getDataHub()->dumpCmd();

        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(result));
        const auto json_value = std::get<google::protobuf::Value>(protoVal);

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.mutable_value()->CopyFrom(json_value);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler metricsGetCmd()
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Get_Request;
        using ResponseType = eMetrics::Get_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        if (!eRequest.has_name())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /name");
        }

        auto result = Metrics::instance().getDataHub()->getCmd(eRequest.name());
        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(result));
        const auto json_value = std::get<google::protobuf::Value>(protoVal);

        ResponseType eResponse;
        eResponse.mutable_value()->CopyFrom(json_value);
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler metricsEnableCmd()
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Enable_Request;
        using ResponseType = eMetrics::Enable_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        auto errorMsg = !eRequest.has_name()     ? std::make_optional("Missing /name")
                        : !eRequest.has_status() ? std::make_optional("Missing /status")
                                                 : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        try
        {
            Metrics::instance().setEnableInstrument(eRequest.name(), eRequest.status());
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler metricsTestCmd()
{
    return [](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Test_Request;
        using ResponseType = eMetrics::Test_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        
        Metrics::instance().generateCounterToTesting();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

// api::Handler metricsListCmd()
// {
//     return [](api::wpRequest wRequest) -> api::wpResponse
//     {
//         auto result = Metrics::instance().getInstrumentsList();
//         return api::WazuhResponse(result.str());
//     };
// }

void registerHandlers(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerHandler("metrics/dump", metricsDumpCmd());
        registry->registerHandler("metrics/get", metricsGetCmd());
        registry->registerHandler("metrics/enable", metricsEnableCmd());
        // registry->registerCommand("list_metrics", metricsListCmd());
        registry->registerHandler("metrics/test", metricsTestCmd());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("metrics API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::metrics::handlers
