#ifndef _CMD_CATALOG_HPP
#define _CMD_CATALOG_HPP

#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/json.hpp>

namespace cmd::catalog
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_catalog_api";
} // namespace details

void runGet(std::shared_ptr<apiclnt::Client> client,
            const std::string& format,
            const std::string& nameStr,
            const bool original,
            const std::string& namespaceId,
            const std::string& role);

void runUpdate(std::shared_ptr<apiclnt::Client> client,
               const std::string& format,
               const std::string& nameStr,
               const std::string& content,
               const std::string& role);

void runCreate(std::shared_ptr<apiclnt::Client> client,
               const std::string& format,
               const std::string& resourceTypeStr,
               const std::string& content,
               const std::string& namespaceId,
               const std::string& role);

void runDelete(std::shared_ptr<apiclnt::Client> client,
               const std::string& nameStr,
               const std::string& role);

void runValidate(std::shared_ptr<apiclnt::Client> client,
                 const std::string& format,
                 const std::string& nameStr,
                 const std::string& content);

void runLoad(std::shared_ptr<apiclnt::Client> client,
             const std::string& format,
             const std::string& nameStr,
             const std::string& path,
             bool recursive,
             const std::string& namespaceId,
             const std::string& role);

void configure(CLI::App_p app);
} // namespace cmd::catalog

#endif // _CMD_CATALOG_HPP
