#ifndef _API_GEO_HANDLERS_HPP
#define _API_GEO_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <geo/imanager.hpp>

namespace api::geo::handlers
{

adapter::RouteHandler addDb(const std::shared_ptr<::geo::IManager>& geoManager);
adapter::RouteHandler delDb(const std::shared_ptr<::geo::IManager>& geoManager);
adapter::RouteHandler listDb(const std::shared_ptr<::geo::IManager>& geoManager);
adapter::RouteHandler remoteUpsertDb(const std::shared_ptr<::geo::IManager>& geoManager);

} // namespace api::geo::handlers
#endif // _API_GEO_HANDLERS_HPP
