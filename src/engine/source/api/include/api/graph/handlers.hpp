#ifndef _API_GRAPH_HANDLERS_HPP
#define _API_GRAPH_HANDLERS_HPP

#include <api/api.hpp>
#include <builder/ibuilder.hpp>

namespace api::graph::handlers
{

/**
 * @brief Graph configuration parameters.
 *
 * TODO: Change to weak pointers.
 */
struct Config
{
    std::shared_ptr<builder::IBuilder> m_builder;
};

/** @brief Handler for the resource endpoint get command.
 *
 * @param config Graph configuration.
 * @return api::HandlerSync
 */
api::HandlerSync resourceGet(const Config& config);

/** @brief Register all handlers for the graph API.
 *
 * @param config Graph configuration.
 * @param api API instance.
 * @throw std::runtime_error If the command registration fails for any reason and at any
 */
void registerHandlers(const Config& config, std::shared_ptr<api::Api> api);

} // namespace api::graph::handlers

#endif // _API_GRAPH_HANDLERS_HPP
