#include <api/metrics/handlers.hpp>

#include <eMessages/metrics.pb.h>

namespace api::metrics::handlers
{
namespace eMetrics = adapter::eEngine::metrics;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler enableMetric(const std::shared_ptr<fastmetrics::IManager>& metricsManager)
{
    return [weakManager = std::weak_ptr<fastmetrics::IManager> {metricsManager}](const auto& req, auto& res)
    {
        using RequestType = eMetrics::Enable_Request;
        using ResponseType = eMetrics::Enable_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, fastmetrics::IManager>(req, weakManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [manager, protoReq] = adapter::getRes(result);

        // Validate the request
        if (!protoReq.has_instrumentname())
        {
            res = adapter::userErrorResponse<ResponseType>("Field 'instrumentName' is required");
            return;
        }

        const std::string& metricName = protoReq.instrumentname();
        const bool enable = protoReq.has_status() ? protoReq.status() : true;

        // Get the specific metric
        auto metric = manager->get(metricName);
        if (!metric)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Metric '{}' not found", metricName));
            return;
        }

        // Enable or disable the metric
        if (enable)
        {
            metric->enable();
        }
        else
        {
            metric->disable();
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_content(fmt::format("Metric '{}' {}", metricName, enable ? "enabled" : "disabled"));
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler getMetric(const std::shared_ptr<fastmetrics::IManager>& metricsManager)
{
    return [weakManager = std::weak_ptr<fastmetrics::IManager> {metricsManager}](const auto& req, auto& res)
    {
        using RequestType = eMetrics::Get_Request;
        using ResponseType = eMetrics::Get_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, fastmetrics::IManager>(req, weakManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [manager, protoReq] = adapter::getRes(result);

        // Validate the request
        if (!protoReq.has_instrumentname())
        {
            res = adapter::userErrorResponse<ResponseType>("Field 'instrumentName' is required");
            return;
        }

        const std::string& metricName = protoReq.instrumentname();

        // Get the specific metric
        auto metric = manager->get(metricName);
        if (!metric)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Metric '{}' not found", metricName));
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_name(metricName);
        eResponse.set_type(static_cast<int>(metric->type()));
        eResponse.set_enabled(metric->isEnabled());
        eResponse.set_value(metric->value());

        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler listMetrics(const std::shared_ptr<fastmetrics::IManager>& metricsManager)
{
    return [weakManager = std::weak_ptr<fastmetrics::IManager> {metricsManager}](const auto& req, auto& res)
    {
        using RequestType = eMetrics::List_Request;
        using ResponseType = eMetrics::List_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, fastmetrics::IManager>(req, weakManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [manager, protoReq] = adapter::getRes(result);

        // Get all metrics names
        auto names = manager->getAllNames();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        for (const auto& name : names)
        {
            eResponse.add_names(name);
        }

        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler dumpMetrics(const std::shared_ptr<fastmetrics::IManager>& metricsManager)
{
    return [weakManager = std::weak_ptr<fastmetrics::IManager> {metricsManager}](const auto& req, auto& res)
    {
        using RequestType = eMetrics::Dump_Request;
        using ResponseType = eMetrics::Dump_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, fastmetrics::IManager>(req, weakManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [manager, protoReq] = adapter::getRes(result);

        // Get all metrics names
        auto names = manager->getAllNames();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        for (const auto& name : names)
        {
            auto metric = manager->get(name);
            if (metric)
            {
                auto* entry = eResponse.add_entries();
                entry->set_name(name);
                entry->set_type(static_cast<int>(metric->type()));
                entry->set_enabled(metric->isEnabled());
                entry->set_value(metric->value());
            }
        }

        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::metrics::handlers
