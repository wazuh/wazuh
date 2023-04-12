#ifndef _API_INTEGRATION_HANDLERS_HPP
#define _API_INTEGRATION_HANDLERS_HPP

#include <memory>

#include <api/integration/integration.hpp>
#include <api/api.hpp>

namespace api::integration::handlers
{
/**
 * @brief Handler for the integration add to policy endpoint.
 *
 * @param integration Integration to use
 * @return api::Handler Handler for the endpoint
 */
api::Handler integrationAddTo(std::shared_ptr<api::integration::Integration> integration);

/**
 * @brief Handler for the integration remove from policy endpoint.
 *
 * @param integration Integration to use
 * @return api::Handler Handler for the endpoint
 */
api::Handler integrationRemoveFrom(std::shared_ptr<api::integration::Integration> integration);

/**
 * @brief Register all available Integration handlers in the API registry.
 *
 * @param integration Integration to use
 * @param registry API registry
 * @throw std::runtime_error If the command registration fails for any reason and at any
 * point
 */
void registerHandlers(std::shared_ptr<api::integration::Integration> integration,
                      std::shared_ptr<api::Api> api);
} // namespace api::integration::handlers

#endif // _API_INTEGRATION_HANDLERS_HPP
