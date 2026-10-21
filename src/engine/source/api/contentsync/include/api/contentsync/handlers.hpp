// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _API_CONTENTSYNC_HANDLERS_HPP
#define _API_CONTENTSYNC_HANDLERS_HPP

#include <memory>
#include <string>

#include <api/adapter/adapter.hpp>
#include <scheduler/triggerableTask.hpp>

/**
 * @brief On-demand triggers for the content the engine pulls from the wazuh-indexer.
 *
 * Each route runs its sync task now rather than at its next scheduled run. Neither blocks: the
 * answer means "accepted", not "finished", and the outcome is read from `GET /status`. A request
 * that arrives while the task runs makes it run once more right after, so calling repeatedly is
 * safe and cheap — a content that has not moved costs one hash probe.
 */
namespace api::contentsync::handlers
{

/**
 * @brief A handler that triggers a sync task.
 *
 * @param task The task. Held weakly, so a shutdown that destroys it cannot leave the server calling
 *             into a freed object; when it is gone (or was never built) the route answers 500.
 * @param what What the task syncs, for the answer and the log.
 * @return The route handler.
 */
adapter::RouteHandler triggerSync(const std::shared_ptr<scheduler::TriggerableTask>& task, std::string what);

/**
 * @brief Register the content synchronization routes.
 *
 * POST /content/ruleset/update and POST /content/ioc/sync. Both take an empty request and answer a
 * `GenericStatus_Response`. The IOC route is separate from `POST /content/ioc/update`, which ingests
 * a local nd-json file: the two share no input and no code path.
 *
 * @param rulesetSync The ruleset sync task (`cm-sync-task`).
 * @param iocSync The IOC sync task (`ioc-sync-task`).
 * @param server API server.
 */
inline void registerHandlers(const std::shared_ptr<scheduler::TriggerableTask>& rulesetSync,
                             const std::shared_ptr<scheduler::TriggerableTask>& iocSync,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/content/ruleset/update", triggerSync(rulesetSync, "ruleset"));
    server->addRoute(httpsrv::Method::POST, "/content/ioc/sync", triggerSync(iocSync, "IOC"));
}

} // namespace api::contentsync::handlers

#endif // _API_CONTENTSYNC_HANDLERS_HPP
