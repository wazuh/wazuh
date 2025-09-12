#ifndef _API_ARCHIVER_HANDLERS_HPP
#define _API_ARCHIVER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <archiver/iarchiver.hpp>
#include <base/baseTypes.hpp>

namespace api::archiver::handlers
{
adapter::RouteHandler activateArchiver(const std::shared_ptr<::archiver::IArchiver>& archiver);

adapter::RouteHandler deactivateArchiver(const std::shared_ptr<::archiver::IArchiver>& archiver);

adapter::RouteHandler getArchiverStatus(const std::shared_ptr<::archiver::IArchiver>& archiver);

inline void registerHandlers(const std::shared_ptr<::archiver::IArchiver>& archiver,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/archiver/activate", activateArchiver(archiver));
    server->addRoute(httpsrv::Method::POST, "/archiver/deactivate", deactivateArchiver(archiver));
    server->addRoute(httpsrv::Method::POST, "/archiver/status", getArchiverStatus(archiver));
}
} // namespace api::archiver::handlers

#endif // _API_ARCHIVER_HANDLERS_HPP
