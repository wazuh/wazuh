// SPDX-License-Identifier: AGPL-3.0-or-later
#include <api/contentsync/handlers.hpp>

#include <utility>

#include <base/logging.hpp>
#include <eMessages/engine.pb.h>

namespace api::contentsync::handlers
{

namespace eEngine = ::com::wazuh::api::engine;

adapter::RouteHandler triggerSync(const std::shared_ptr<scheduler::TriggerableTask>& task, std::string what)
{
    return [weakTask = std::weak_ptr(task), what = std::move(what)](const httplib::Request&, httplib::Response& res)
    {
        auto taskPtr = weakTask.lock();
        if (!taskPtr)
        {
            res = adapter::internalErrorResponse<eEngine::GenericStatus_Response>(
                what + " synchronization is not available");
            return;
        }

        taskPtr->trigger();
        LOG_DEBUG("[API] {} synchronization requested", what);

        eEngine::GenericStatus_Response response;
        response.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(response);
    };
}

} // namespace api::contentsync::handlers
