#ifndef _CATALOG_COMMANDS_HPP
#define _CATALOG_COMMANDS_HPP

#include "api/catalog/catalog.hpp"

#include <memory>

#include <api/registry.hpp>

namespace api::catalog::cmds
{
/****************************************************************************************/
/* GET                                                                                  */
/****************************************************************************************/
/**
 * @brief Get the CommandFn for the getAsset functionality.
 *
 * @param catalog Catalog to use
 * @return api::CommandFn Command function
 */
api::CommandFn getAssetCmd(std::shared_ptr<Catalog> catalog);

/****************************************************************************************/
/* POST                                                                                 */
/****************************************************************************************/
/**
 * @brief Get the CommandFn for the postAsset functionality.
 *
 * @param catalog Catalog to use
 * @return api::CommandFn Command function
 */
api::CommandFn postAssetCmd(std::shared_ptr<Catalog> catalog);

/****************************************************************************************/
/* DELETE                                                                               */
/****************************************************************************************/
/**
 * @brief Get the CommandFn for the deleteAsset functionality.
 *
 * @param catalog Catalog to use
 * @return api::CommandFn Command function
 */
api::CommandFn deleteAssetCmd(std::shared_ptr<Catalog> catalog);

/**
 * @brief Register all available Catalog commands in the API registry.
 *
 * @param catalog Catalog to use
 * @param registry API registry
 * @throw std::runtime_error If the command registration fails for any reason and at any
 * point
 */
void registerAllCmds(std::shared_ptr<Catalog> catalog,
                     std::shared_ptr<api::Registry> registry);

} // namespace cmds

#endif // _CATALOG_COMMANDS_HPP
