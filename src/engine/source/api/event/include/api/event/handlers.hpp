// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _API_EVENT_HANDLERS_HPP
#define _API_EVENT_HANDLERS_HPP

#include <functional>
#include <string_view>

#include <agentcache/agentMetadataCache.hpp>
#include <dumper/idumper.hpp>
#include <httpsrv/types.hpp>
#include <router/iapi.hpp>

namespace api::event::handlers
{
httpsrv::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::dumper::IDumper>& dumper,
                                std::shared_ptr<agentcache::AgentMetadataCache> agentMetadataCache);

} // namespace api::event::handlers

#endif // _API_EVENT_HANDLERS_HPP
