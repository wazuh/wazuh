// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMCONTENT_RULESET_SINK_HPP
#define CMCONTENT_RULESET_SINK_HPP

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <base/json.hpp>
#include <cmcrud/icmcrudservice.hpp>
#include <cmstore/types.hpp>
#include <contentSink.hpp>
#include <router/iapi.hpp>

namespace cmcontent
{

/**
 * @brief What one ruleset cycle did, for the sync service to fold into its persisted state.
 */
struct RulesetOutcome
{
    bool applied {false};                                 ///< A new namespace was imported and routed.
    bool disabled {false};                                ///< The remote policy is disabled; the route was removed.
    std::optional<cm::store::NamespaceId> newNamespaceId; ///< The namespace now serving the route.
    std::string hash;                                     ///< Hash of the content now deployed.
    bool routeAvailable {false};                          ///< Whether a route exists for this space after the cycle.
};

/**
 * @brief Assembles one space's ruleset in memory and swaps it into the router atomically.
 *
 * Unlike the IOC sink, this one stages in memory rather than on disk: a ruleset is small and the
 * promotion is `importNamespace` followed by a router hot-swap, so there is nothing to gain from
 * writing it out first. That is also why every page is merely `Accepted` — until `commit` runs,
 * none of it exists anywhere a reader could see.
 *
 * One sink per space, matching one topic per space.
 */
class RulesetSpaceSink final : public content_manager::IContentSink
{
public:
    /**
     * @brief Build the sink.
     *
     * @param crud Namespace store.
     * @param router Router the space's route lives in.
     * @param space Origin space in the indexer.
     * @param routeName Route name for this space.
     */
    RulesetSpaceSink(std::weak_ptr<cm::crud::ICrudService> crud,
                     std::weak_ptr<router::IRouterAPI> router,
                     std::string space,
                     std::string routeName);

    ~RulesetSpaceSink() override;

    /**
     * @brief Seed the sink with the persisted namespace, and report the one actually in force.
     *
     * Called before every scheduled cycle. The first call seeds the sink with the namespace the
     * sync service persisted; from then on the sink is the authority, because every swap and
     * teardown goes through it — including those of on-demand cycles, which run on a lane worker
     * the sync service never observes. Later calls therefore ignore the argument and return the
     * sink's own view, so the caller can adopt a change it did not drive instead of overwriting it
     * with a namespace that has already been deleted.
     *
     * @param persistedNamespaceId The persisted namespace, or nullopt when the space has never synced.
     * @return The namespace the sink considers in force, or nullopt when none is.
     */
    std::optional<cm::store::NamespaceId> prepare(const std::optional<cm::store::NamespaceId>& persistedNamespaceId);

    /**
     * @brief What the last cycle did, taken out of the sink.
     *
     * Returns by value and resets, so a caller cannot read a stale outcome from a cycle it did not
     * itself drive — an on-demand cycle running between a scheduled `runOnce` and this call would
     * otherwise leave its own result here to be mistaken for the caller's.
     *
     * @return The outcome of the last completed cycle.
     */
    RulesetOutcome takeOutcome();

    /**
     * @copydoc content_manager::IContentSink::beginSession
     */
    content_manager::SessionDecision beginSession(const content_manager::SessionInfo& info) noexcept override;

    /**
     * @copydoc content_manager::IContentSink::acceptPage
     */
    content_manager::PageAck acceptPage(const content_manager::ContentPage& page) noexcept override;

    /**
     * @copydoc content_manager::IContentSink::commit
     */
    content_manager::CommitResult commit(const content_manager::CommitInfo& info) noexcept override;

    /**
     * @copydoc content_manager::IContentSink::abort
     */
    void abort(content_manager::AbortReason reason, const std::string& detail) noexcept override;

private:
    /// Everything a policy is made of, accumulated across the cycle's pages.
    struct Accumulator
    {
        std::vector<json::Json> kvdbs;
        std::vector<json::Json> decoders;
        std::vector<json::Json> filters;
        std::vector<json::Json> integrations;
        json::Json policy;
        bool policySeen {false};
    };

    /// Remove the route and the namespace of a space whose remote policy is disabled.
    /// @pre m_mutex is held.
    void teardown() noexcept;

    /// Point the route at @p namespaceId, creating it when it does not exist yet.
    /// @pre m_mutex is held.
    void routeTo(const cm::store::NamespaceId& namespaceId);

    /// Drop the staging namespace, if one was allocated. Never throws.
    /// @pre m_mutex is held.
    void discardStaging() noexcept;

    std::weak_ptr<cm::crud::ICrudService> m_crud;
    std::weak_ptr<router::IRouterAPI> m_router;
    std::string m_space;
    std::string m_routeName;

    /**
     * @brief Guards every mutable member below.
     *
     * The library serialises the sink's own callbacks, so they never race each other — but
     * @ref prepare and @ref takeOutcome are called by the sync service, on its thread, and a cycle
     * triggered through the on-demand API runs on a lane worker. Those two are not serialised
     * against each other by anything, and `m_currentNamespaceId` is a `std::optional<NamespaceId>`
     * holding a `std::string`: concurrent access is a data race, not merely a stale read.
     */
    mutable std::mutex m_mutex;

    std::optional<cm::store::NamespaceId> m_currentNamespaceId;
    bool m_seeded {false}; ///< Whether prepare() has seeded m_currentNamespaceId yet.
    std::optional<cm::store::NamespaceId> m_stagingNamespaceId;
    Accumulator m_accumulator;
    std::string m_remoteHash;
    RulesetOutcome m_outcome;
};

} // namespace cmcontent

#endif // CMCONTENT_RULESET_SINK_HPP
