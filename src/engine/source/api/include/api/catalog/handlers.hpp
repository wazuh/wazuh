#ifndef _API_CATALOG_HANDLERS_HPP
#define _API_CATALOG_HANDLERS_HPP

#include <api/catalog/catalog.hpp>

#include <memory>

#include <api/registry.hpp>

namespace api::catalog::handlers
{

/* Resource Endpoint */
api::Handler resourcePost(std::shared_ptr<Catalog> catalog);
api::Handler resourceGet(std::shared_ptr<Catalog> catalog);
api::Handler resourceDelete(std::shared_ptr<Catalog> catalog);
api::Handler resourcePut(std::shared_ptr<Catalog> catalog);
api::Handler resourceValidate(std::shared_ptr<Catalog> catalog);

/**
 * @brief Register all available Catalog handlers in the API registry.
 *
 * @param catalog Catalog to use
 * @param registry API registry
 * @throw std::runtime_error If the command registration fails for any reason and at any
 * point
 */
void registerHandlers(std::shared_ptr<Catalog> catalog, std::shared_ptr<api::Registry> registry);

} // namespace api::catalog::handlers

#endif // _API_CATALOG_HANDLERS_HPP
