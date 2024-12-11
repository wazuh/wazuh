#ifndef _API_CATALOG_HANDLERS_HPP
#define _API_CATALOG_HANDLERS_HPP

#include <api/catalog/catalog.hpp>

#include <memory>

#include <api/api.hpp>
#include <rbac/irbac.hpp>

namespace api::catalog::handlers
{

/* Resource Endpoint */
api::HandlerSync resourcePost(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::HandlerSync resourceGet(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::HandlerSync resourceDelete(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::HandlerSync resourcePut(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::HandlerSync resourceValidate(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::HandlerSync policyAddIntegration(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::HandlerSync policyDelIntegration(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::HandlerSync getNamespaces(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);

/**
 * @brief Register all available Catalog handlers in the API registry.
 *
 * @param catalog Catalog to use
 * @param api API to register the handlers
 * @throw std::runtime_error If the command registration fails for any reason and at any
 * point
 */
void registerHandlers(std::shared_ptr<Catalog> catalog, std::shared_ptr<api::Api> api);

} // namespace api::catalog::handlers

#endif // _API_CATALOG_HANDLERS_HPP
