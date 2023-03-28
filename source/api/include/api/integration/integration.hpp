#ifndef _API_INTEGRATION_HPP
#define _API_INTEGRATION_HPP

#include <memory>
#include <optional>

#include <api/catalog/catalog.hpp>
#include <api/catalog/resource.hpp>
#include <error.hpp>

namespace api::integration
{

/**
 * @brief Integration API endpoint
 *
 */
class Integration
{
private:
    std::shared_ptr<api::catalog::Catalog> m_catalog;

public:
    /**
     * @brief Construct a new Integration object
     *
     * @param catalog Catalog API dependency
     */
    Integration(std::shared_ptr<api::catalog::Catalog> catalog)
        : m_catalog(catalog)
    {
    }

    /**
     * @brief Add an integration to a policy
     *
     * @param policy Policy resource
     * @param integration Integration resource
     * @return std::optional<base::Error> Error if any
     */
    std::optional<base::Error> addTo(const api::catalog::Resource& policy, const api::catalog::Resource& integration);

    /**
     * @brief Remove an integration from a policy
     *
     * @param policy Policy resource
     * @param integration Integration resource
     * @return std::optional<base::Error> Error if any
     */
    std::optional<base::Error> removeFrom(const api::catalog::Resource& policy,
                                          const api::catalog::Resource& integration);
};
} // namespace api::integration

#endif // _API_INTEGRATION_HPP
