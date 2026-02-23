#ifndef _API_RAWEVTINDEXER_HANDLERS_HPP
#define _API_RAWEVTINDEXER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <base/baseTypes.hpp>

#include <rawevtindexer/iraweventindexer.hpp>

namespace api::rawevtindexer::handlers
{
adapter::RouteHandler enableRawEventIndexer(const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer);

adapter::RouteHandler disableRawEventIndexer(const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer);

adapter::RouteHandler getRawEventIndexerStatus(const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer);

inline void registerHandlers(const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/_internal/raweventindexer/enable", enableRawEventIndexer(rawIndexer));
    server->addRoute(httpsrv::Method::POST, "/_internal/raweventindexer/disable", disableRawEventIndexer(rawIndexer));
    server->addRoute(httpsrv::Method::POST, "/_internal/raweventindexer/status", getRawEventIndexerStatus(rawIndexer));
}
} // namespace api::rawevtindexer::handlers

#endif // _API_RAWEVTINDEXER_HANDLERS_HPP