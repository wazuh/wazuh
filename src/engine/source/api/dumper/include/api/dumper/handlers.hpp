#ifndef API_DUMPER_HANDLERS_HPP
#define API_DUMPER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <base/baseTypes.hpp>
#include <dumper/idumper.hpp>

namespace api::dumper::handlers
{
adapter::RouteHandler activateDumper(const std::shared_ptr<::dumper::IDumper>& dumper);

adapter::RouteHandler deactivateDumper(const std::shared_ptr<::dumper::IDumper>& dumper);

adapter::RouteHandler getDumperStatus(const std::shared_ptr<::dumper::IDumper>& dumper);

inline void registerHandlers(const std::shared_ptr<::dumper::IDumper>& dumper,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/event-dumper/activate", activateDumper(dumper));
    server->addRoute(httpsrv::Method::POST, "/event-dumper/deactivate", deactivateDumper(dumper));
    server->addRoute(httpsrv::Method::POST, "/event-dumper/status", getDumperStatus(dumper));
}
} // namespace api::dumper::handlers

#endif // API_DUMPER_HANDLERS_HPP
