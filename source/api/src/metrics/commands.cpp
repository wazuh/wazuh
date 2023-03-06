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

void registerAllCmds(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("dump_metrics", metricsDumpCmd());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("metrics API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::metrics::cmds

