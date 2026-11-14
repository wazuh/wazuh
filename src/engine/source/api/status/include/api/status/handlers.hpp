// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _API_STATUS_HANDLERS_HPP
#define _API_STATUS_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <cmsync/icmsync.hpp>
#include <geo/imanager.hpp>
#include <httpsrv/irouteregistrar.hpp>
#include <iocsync/iiocsync.hpp>

namespace api::status::handlers
{

/**
 * @brief Get the engine status
 *
 * GET /status
 * Request: {}
 * Response: { ready, spaces, ioc, geo }
 *
 * cmSync and iocSync may be null (event processing disabled): the response then has no spaces/ioc entries
 * and ready is false.
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
                             const std::shared_ptr<httpsrv::IRouteRegistrar>& server)
{
    // The readiness probe: a liveness route answered on the I/O thread (it only reads published snapshots), so
    // long imports or tester runs holding every API worker never delay it.
    httpsrv::RouteOptions liveness;
    liveness.cls = httpsrv::RouteClass::Liveness;
    liveness.runInline = true;
    server->addRoute(httpsrv::Method::GET, "/status", getStatus(cmSync, iocSync, geoManager), liveness);
}

} // namespace api::status::handlers

#endif // _API_STATUS_HANDLERS_HPP
