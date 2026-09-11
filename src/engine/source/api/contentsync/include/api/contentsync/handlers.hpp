#ifndef _API_CONTENTSYNC_HANDLERS_HPP
#define _API_CONTENTSYNC_HANDLERS_HPP

#include <memory>

#include <api/adapter/adapter.hpp>
#include <cmsync/icmsync.hpp>
#include <iocsync/iiocsync.hpp>

/**
 * @brief On-demand triggers for the content the engine pulls from the wazuh-indexer.
 *
 * Both routes do the same thing for their own content: ask the content manager to run a cycle now
 * rather than at the next scheduler tick. Neither blocks — the request goes onto the content
 * manager's short bounded lane and runs on one of its workers — so a caller gets an immediate
 * answer meaning "accepted", not "finished". Progress and results are read from `GET /status`,
 * which already reports per-space and per-type sync state.
 *
 * A cycle whose content has not moved costs one hash probe, and a topic that is already syncing is
 * left alone rather than run twice, so these are safe to call repeatedly.
 */
namespace api::contentsync::handlers
{

/**
 * @brief Trigger a ruleset synchronization for every tracked space.
 *
 * POST /content/ruleset/update
 * Request: {}
 * Response: GenericStatus_Response
 *
 * New capability: the ruleset previously had no way to be refreshed other than waiting for
 * `cm-sync-task`.
 *
 * @param cmSync Ruleset sync service.
 * @return The route handler.
 */
adapter::RouteHandler updateRuleset(const std::shared_ptr<cm::sync::ICMSync>& cmSync);

/**
 * @brief Trigger an IOC synchronization from the indexer for every tracked type.
 *
 * POST /content/ioc/sync
 * Request: {}
 * Response: GenericStatus_Response
 *
 * Deliberately a separate route from `POST /content/ioc/update`, which ingests a local nd-json file
 * given a path and a hash. The two share no input and no code path; folding the indexer mode into
 * the same route as a flag would have made half of its request fields meaningless on each call.
 *
 * @param iocSync IOC sync service.
 * @return The route handler.
 */
adapter::RouteHandler syncIocFromIndexer(const std::shared_ptr<ioc::sync::IIocSync>& iocSync);

/**
 * @brief Register the content synchronization handlers.
 *
 * @param cmSync Ruleset sync service.
 * @param iocSync IOC sync service.
 * @param server API server.
 */
inline void registerHandlers(const std::shared_ptr<cm::sync::ICMSync>& cmSync,
                             const std::shared_ptr<ioc::sync::IIocSync>& iocSync,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/content/ruleset/update", updateRuleset(cmSync));
    server->addRoute(httpsrv::Method::POST, "/content/ioc/sync", syncIocFromIndexer(iocSync));
}

} // namespace api::contentsync::handlers

#endif // _API_CONTENTSYNC_HANDLERS_HPP
