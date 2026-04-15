#include <api/metrics/handlers.hpp>

#include <unordered_map>

#include <base/utils/timeUtils.hpp>
#include <eMessages/metrics.pb.h>

namespace api::metrics::handlers
{
namespace eMetrics = adapter::eEngine::metrics;
namespace eEngine = adapter::eEngine;

namespace
{
/**
 * @brief Convert MetricType enum to lowercase string for API responses
 */
const char* metricTypeToString(fastmetrics::MetricType type)
{
    switch (type)
    {
        case fastmetrics::MetricType::COUNTER: return "counter";
        case fastmetrics::MetricType::GAUGE_INT: return "gauge_int";
        case fastmetrics::MetricType::PULL: return "pull";
        default: return "unknown";
    }
}
} // namespace

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

        // Resolve metric name: if space is set, prefix with "space.<space>."
        std::string metricName = protoReq.instrumentname();
        if (protoReq.has_space() && !protoReq.space().empty())
        {
            metricName = "space." + protoReq.space() + "." + metricName;
        }
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

        // Resolve metric name: if space is set, prefix with "space.<space>."
        std::string metricName = protoReq.instrumentname();
        if (protoReq.has_space() && !protoReq.space().empty())
        {
            metricName = "space." + protoReq.space() + "." + metricName;
        }

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
        eResponse.set_type(metricTypeToString(metric->type()));
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

        // Filter by space if requested
        const std::string spacePrefix =
            protoReq.has_space() && !protoReq.space().empty() ? "space." + protoReq.space() + "." : "";

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        for (const auto& name : names)
        {
            if (!spacePrefix.empty())
            {
                // Only include metrics from the requested space, strip the prefix
                if (name.size() > spacePrefix.size() && name.compare(0, spacePrefix.size(), spacePrefix) == 0)
                {
                    eResponse.add_names(name.substr(spacePrefix.size()));
                }
            }
            else
            {
                eResponse.add_names(name);
            }
        }

        if (eResponse.names_size() == 0)
        {
            if (!spacePrefix.empty())
            {
                res = adapter::userErrorResponse<ResponseType>(
                    fmt::format("No metrics found for space '{}'", protoReq.space()));
            }
            else
            {
                res = adapter::userErrorResponse<ResponseType>("No metrics registered");
            }
            return;
        }

        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler dumpMetrics(const std::shared_ptr<fastmetrics::IManager>& metricsManager,
                                  const std::string& daemonName,
                                  const std::string& uptimeISO)
{
    return [weakManager = std::weak_ptr<fastmetrics::IManager> {metricsManager}, daemonName, uptimeISO](const auto& req,
                                                                                                        auto& res)
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
        eResponse.set_name(daemonName);
        eResponse.set_uptime(uptimeISO);
        eResponse.set_timestamp(base::utils::time::getCurrentISO8601());

        // Partition metrics: global vs per-space (space.<name>.xxx)
        constexpr std::string_view SPACE_PREFIX = "space.";
        std::unordered_map<std::string, eMetrics::SpaceMetrics*> spaceMap;

        for (const auto& name : names)
        {
            auto metric = manager->get(name);
            if (!metric)
            {
                continue;
            }

            // Check if metric belongs to a space
            if (name.size() > SPACE_PREFIX.size() && name.compare(0, SPACE_PREFIX.size(), SPACE_PREFIX) == 0)
            {
                // Parse: space.<spaceName>.<metricSuffix>
                auto dotPos = name.find('.', SPACE_PREFIX.size());
                if (dotPos != std::string::npos)
                {
                    auto spaceName = name.substr(SPACE_PREFIX.size(), dotPos - SPACE_PREFIX.size());
                    auto metricSuffix = name.substr(dotPos + 1);

                    auto it = spaceMap.find(spaceName);
                    if (it == spaceMap.end())
                    {
                        auto* spaceMetrics = eResponse.add_spaces();
                        spaceMetrics->set_name(spaceName);
                        spaceMap[spaceName] = spaceMetrics;
                        it = spaceMap.find(spaceName);
                    }

                    auto* entry = it->second->add_metrics();
                    entry->set_name(metricSuffix);
                    entry->set_type(metricTypeToString(metric->type()));
                    entry->set_enabled(metric->isEnabled());
                    entry->set_value(metric->value());
                    continue;
                }
            }

            // Global metric
            auto* entry = eResponse.add_global();
            entry->set_name(name);
            entry->set_type(metricTypeToString(metric->type()));
            entry->set_enabled(metric->isEnabled());
            entry->set_value(metric->value());
        }

        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::metrics::handlers
