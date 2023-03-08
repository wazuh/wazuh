#include "api/metrics/commands.hpp"

#include <fmt/format.h>
#include <json/json.hpp>

namespace api::metrics::cmds
{

std::tuple<bool, std::string> getNameOrError(const json::Json& params)
{
    const auto metricName = params.getString("/name");
    if (!metricName)
    {
        return {false, METRICS_NAME_MISSING};
    }

    if (metricName.value().empty())
    {
        return {false, METRICS_NAME_EMPTY};
    }

    return {true, metricName.value()};
}

api::CommandFn metricsDumpCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse
    {
        auto result = Metrics::instance().getDataHub()->dumpCmd();
        if (std::holds_alternative<base::Error>(result))
        {
            return api::WazuhResponse {std::get<base::Error>(result).message};
        }

        return api::WazuhResponse {
            std::get<json::Json>(result),
            fmt::format("Metrics successfully dumped")};
    };
}

api::CommandFn metricsGetCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse
    {
        // Get Metrics's name parameter
        const auto [ok, response] = getNameOrError(params);
        if (!ok)
        {
            return api::WazuhResponse {response};
        }

        auto result = Metrics::instance().getDataHub()->getCmd(response);
        if (std::holds_alternative<base::Error>(result))
        {
            return api::WazuhResponse {std::get<base::Error>(result).message};
        }

        return api::WazuhResponse {
            std::get<json::Json>(result),
            fmt::format("Metrics successfully geted")};
    };
}

api::CommandFn metricsEnableCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse
    {
        auto name = params.getString("/nameInstrument");
        auto state = params.getBool("/enableState");
        try
        {
            Metrics::instance().setEnableInstrument(name.value(), state.value());
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse(e.what());
        }

        return api::WazuhResponse("OK");
    };
}

api::CommandFn metricsListCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse
    {
        auto result = Metrics::instance().getListInstruments();
        return api::WazuhResponse(result.str());
    };
}

void registerAllCmds(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("dump_metrics", metricsDumpCmd());
        registry->registerCommand("get_metrics", metricsGetCmd());
        registry->registerCommand("enable_metrics", metricsEnableCmd());
        registry->registerCommand("list_metrics", metricsListCmd());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("metrics API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::metrics::cmds
