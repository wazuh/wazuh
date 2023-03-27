#ifndef _API_INTEGRATION_HPP
#define _API_INTEGRATION_HPP

#include <memory>
#include <optional>

#include <api/catalog/catalog.hpp>
#include <api/catalog/resource.hpp>
#include <error.hpp>

namespace api::integration
{

class Integration
{
private:
    std::shared_ptr<api::catalog::Catalog> m_catalog;

public:
    Integration(std::shared_ptr<api::catalog::Catalog> catalog)
        : m_catalog(catalog)
    {
    }
    std::optional<base::Error> addTo(const api::catalog::Resource& policy, const api::catalog::Resource& integration);

    std::optional<base::Error> removeFrom(const api::catalog::Resource& policy,
                                          const api::catalog::Resource& integration);
};
} // namespace api::integration

#endif // _API_INTEGRATION_HPP
