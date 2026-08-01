#ifndef _API_STATUS_HANDLERS_HPP
#define _API_STATUS_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <cmsync/icmsync.hpp>
#include <geo/imanager.hpp>
#include <iocsync/iiocsync.hpp>

namespace api::status::handlers
{

/**
 * @brief Get the engine status
 *
 * GET /status
 * Request: {}
 * Response: { ready, spaces, ioc, geo }
 */
adapter::RouteHandler getStatus(const std::shared_ptr<cm::sync::ICMSync>& cmSync,
                                const std::shared_ptr<ioc::sync::IIocSync>& iocSync,
                                const std::shared_ptr<::geo::IManager>& geoManager);

/**
 * @brief Register status API handlers
 */
inline void registerHandlers(const std::shared_ptr<cm::sync::ICMSync>& cmSync,
                             const std::shared_ptr<ioc::sync::IIocSync>& iocSync,
                             const std::shared_ptr<::geo::IManager>& geoManager,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::GET, "/status", getStatus(cmSync, iocSync, geoManager));
}

} // namespace api::status::handlers

#endif // _API_STATUS_HANDLERS_HPP
