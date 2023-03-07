#include "api/metrics/commands.hpp"

#include <fmt/format.h>
#include <json/json.hpp>

namespace api::metrics::cmds
{
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

void registerAllCmds(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("dump_metrics", metricsDumpCmd());
        registry->registerCommand("enable_metrics", metricsEnableCmd());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("metrics API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::metrics::cmds
