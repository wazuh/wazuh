#ifndef _API_EVENT_HANDLERS_HPP
#define _API_EVENT_HANDLERS_HPP

#include <queue>

#include <api/adapter/adapter.hpp>
#include <archiver/iarchiver.hpp>
#include <base/baseTypes.hpp>
#include <router/iapi.hpp>

namespace api::event::handlers
{
using ProtolHandler = std::function<std::queue<base::Event>(std::string&&)>;

adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                ProtolHandler protocolHandler,
                                const std::shared_ptr<::archiver::IArchiver>& archiver);

} // namespace api::event::handlers

#endif // _API_EVENT_HANDLERS_HPP
