// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMCONTENT_RULESET_SINK_HPP
#define CMCONTENT_RULESET_SINK_HPP

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <base/json.hpp>
#include <cmcrud/icmcrudservice.hpp>
#include <cmstore/types.hpp>
#include <contentSink.hpp>
#include <contentTokenStore.hpp>
#include <router/iapi.hpp>

namespace cmcontent
{

/**
 * @brief What is deployed for one space, read from the router.
 */
struct RulesetDeployment
{
    bool available {false};      ///< A route serves the space.
    std::string hash;            ///< Hash of the deployed ruleset; "" when no route serves it.
    std::optional<bool> enabled; ///< Whether the remote policy is enabled, as last probed; empty before.
};

/**
 * @brief One space's ruleset deployment: assembles it in memory and swaps it into the router.
 *
 * The sink owns everything about the space's deployment — the route `cmsync_<space>`, the namespaces
 * `cmsync_<space>_<suffix>` it creates and retires — and the router is the record of it: the
 * namespace a route serves is the one in force, and its hash is the topic's change-detection token
 * (the sink is also the topic's token store). Nothing else keeps a copy that could disagree.
 *
 * Staging is in memory: a ruleset is small and the promotion is `importNamespace` followed by a
 * router hot-swap, so every page is merely `Accepted` until `commit` runs.
 *
 * Called by one thread at a time: the cycles of its topic, which never overlap, and the sync
 * service that runs them.
 */
class RulesetSpaceSink final
    : public content_manager::IContentSink
    , public content_manager::IContentTokenStore
{
public:
    /**
     * @brief Build the sink.
     *
     * @param crud Namespace store.
     * @param router Router the space's route lives in.
     * @param space Origin space in the indexer.
     */
    RulesetSpaceSink(std::weak_ptr<cm::crud::ICrudService> crud,
                     std::weak_ptr<router::IRouterAPI> router,
                     std::string space);

    ~RulesetSpaceSink() override;

    /**
     * @brief The route name of a space.
     *
     * @param space Origin space.
     * @return `cmsync_<space>`.
     */
    static std::string routeName(std::string_view space);

    /// @return What is deployed for this space now.
    RulesetDeployment deployment() const noexcept;

    /**
     * @brief Delete this space's namespaces that no route serves.
     *
     * A process killed between `importNamespace` and the route swap leaves a namespace nothing
     * points at. Without a readable router nothing is deleted: a dead namespace cannot then be told
     * from a deployed one.
     */
    void collectOrphanNamespaces() noexcept;

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

    /// The hash of the ruleset the route serves, when the route is enabled.
    std::string load(std::string_view topic) noexcept override;

    /// Nothing to write: the commit's route swap already recorded the hash.
    bool store(std::string_view topic, std::string_view token) noexcept override;

    /// Nothing to clear: a forced reload replaces the deployment when it commits.
    bool clear(std::string_view topic) noexcept override;

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

    /// @return The namespace the route serves, or nullopt when there is no readable route.
    std::optional<cm::store::NamespaceId> servedNamespace() const noexcept;

    /// Remove the route and the namespace it serves.
    void teardown() noexcept;

    /// Point the route at @p namespaceId, creating it when it does not exist yet.
    void routeTo(const cm::store::NamespaceId& namespaceId);

    /// Drop the staging namespace, if one was allocated. Never throws.
    void discardStaging() noexcept;

    std::weak_ptr<cm::crud::ICrudService> m_crud;
    std::weak_ptr<router::IRouterAPI> m_router;
    std::string m_space;
    std::string m_routeName;

    std::optional<bool> m_policyEnabled;
    std::optional<cm::store::NamespaceId> m_stagingNamespaceId;
    Accumulator m_accumulator;
};

} // namespace cmcontent

#endif // CMCONTENT_RULESET_SINK_HPP
