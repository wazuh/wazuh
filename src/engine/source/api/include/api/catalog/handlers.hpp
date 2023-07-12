#ifndef _API_CATALOG_HANDLERS_HPP
#define _API_CATALOG_HANDLERS_HPP

#include <api/catalog/catalog.hpp>

#include <memory>

#include <api/api.hpp>
#include <rbac/irbac.hpp>


namespace api::catalog::handlers
{

/* Resource Endpoint */
api::Handler resourcePost(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::Handler resourceGet(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::Handler resourceDelete(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::Handler resourcePut(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::Handler resourceValidate(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::Handler policyAddIntegration(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);
api::Handler policyDelIntegration(std::shared_ptr<Catalog> catalog, std::weak_ptr<rbac::IRBAC> rbac);

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
