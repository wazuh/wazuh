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

inline void registerHandlers(const std::shared_ptr<::geo::IManager>& geoManager,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/geo/db/add", addDb(geoManager));
    server->addRoute(httpsrv::Method::POST, "/geo/db/del", delDb(geoManager));
    server->addRoute(httpsrv::Method::POST, "/geo/db/list", listDb(geoManager));
    server->addRoute(httpsrv::Method::POST, "/geo/db/remoteUpsert", remoteUpsertDb(geoManager));
}

} // namespace api::geo::handlers
#endif // _API_GEO_HANDLERS_HPP
