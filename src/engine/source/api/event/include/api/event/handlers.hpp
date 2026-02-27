#ifndef _API_EVENT_HANDLERS_HPP
#define _API_EVENT_HANDLERS_HPP

#include <functional>
#include <string_view>

#include <api/adapter/adapter.hpp>
#include <archiver/iarchiver.hpp>
#include <router/iapi.hpp>

namespace api::event::handlers
{
adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::archiver::IArchiver>& archiver);

} // namespace api::event::handlers

#endif // _API_EVENT_HANDLERS_HPP
