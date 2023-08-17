#ifndef _API_GRAPH_HANDLERS_HPP
#define _API_GRAPH_HANDLERS_HPP

#include <api/api.hpp>
#include <store/istore.hpp>
#include <kvdb/kvdbManager.hpp>

namespace api::graph::handlers
{

/**
 * @brief Graph configuration parameters.
 *
 */
struct Config
{
    std::shared_ptr<store::IStore> store;

    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
};

/** @brief Handler for the resource endpoint get command.
 *
 * @param config Graph configuration.
 * @return api::Handler
 */
api::Handler resourceGet(const Config& config);

/** @brief Register all handlers for the graph API.
 *
 * @param config Graph configuration.
 * @param api API instance.
 * @throw std::runtime_error If the command registration fails for any reason and at any
 */
void registerHandlers(const Config& config, std::shared_ptr<api::Api> api);

} // namespace api::graph::handlers

#endif // _API_GRAPH_HANDLERS_HPP
