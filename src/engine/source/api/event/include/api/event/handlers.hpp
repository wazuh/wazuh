#ifndef _API_EVENT_HANDLERS_HPP
#define _API_EVENT_HANDLERS_HPP

#include <functional>
#include <string_view>

#include <api/adapter/adapter.hpp>
#include <archiver/iarchiver.hpp>
#include <rawevtindexer/iraweventindexer.hpp>
#include <router/iapi.hpp>

namespace api::event::handlers
{
using EventHook = std::function<void(const json::Json& header, std::string_view rawEvent)>;

adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::archiver::IArchiver>& archiver,
                                const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer);

} // namespace api::event::handlers

#endif // _API_EVENT_HANDLERS_HPP
