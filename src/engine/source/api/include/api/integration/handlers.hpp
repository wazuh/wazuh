#ifndef _API_INTEGRATION_HANDLERS_HPP
#define _API_INTEGRATION_HANDLERS_HPP

#include <memory>

#include <api/integration/integration.hpp>
#include <api/registry.hpp>

namespace api::integration::handlers
{
api::Handler integrationAddTo(std::shared_ptr<api::integration::Integration> integration);
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
                      std::shared_ptr<api::Registry> registry);
} // namespace api::integration::handlers

#endif // _API_INTEGRATION_HANDLERS_HPP
