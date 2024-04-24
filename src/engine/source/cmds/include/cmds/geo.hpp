#ifndef _CMD_GEO_HPP
#define _CMD_GEO_HPP

#include <string>

#include <CLI/CLI.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <cmds/apiclnt/client.hpp>

namespace cmd::geo
{
namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_geo_api";
} // namespace details

void runAdd(const std::shared_ptr<apiclnt::Client>& client, const std::string& path, const std::string& type);
void runDelete(const std::shared_ptr<apiclnt::Client>& client, const std::string& path);
void runList(const std::shared_ptr<apiclnt::Client>& client, bool jsonFormat);
void runRemoteUpsert(const std::shared_ptr<apiclnt::Client>& client,
                     const std::string& path,
                     const std::string& type,
                     const std::string& dbUrl,
                     const std::string& hashUrl);

void configure(CLI::App_p app);
} // namespace cmd::geo
#endif // _CMD_GEO_HPP
