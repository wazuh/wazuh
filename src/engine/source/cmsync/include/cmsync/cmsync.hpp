// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CMSYNC_CMSYNC
#define _CMSYNC_CMSYNC

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <base/statusSnapshot.hpp>
#include <cmcontent/contentTopic.hpp>
#include <cmcontent/registration.hpp>
#include <cmcontent/rulesetSink.hpp>
#include <cmcrud/icmcrudservice.hpp>
#include <router/iapi.hpp>
#include <store/istore.hpp>

#include <cmsync/icmsync.hpp>

namespace cm::sync
{

/**
 * @brief Delay before the next sync run while a space has no route.
 *
 * @param retryInterval `analysisd.cm_sync_retry_interval`; 0 disables the early retry.
 * @param syncInterval `analysisd.cm_sync_interval`, the regular run.
 * @return 0 when disabled (the regular run applies), otherwise the retry interval capped at the regular one.
 */
constexpr std::size_t earlyRetryInterval(std::size_t retryInterval, std::size_t syncInterval)
{
    return retryInterval < syncInterval ? retryInterval : syncInterval;
}

/**
 * @brief Keeps the `standard` and `custom` ruleset spaces in step with the indexer.
 *
 * One content topic per space. Each topic's sink owns the space's deployment (route and
 * namespaces); this class decides when the topics run, turns each outcome into the status the API
 * reports, and persists the little the router does not record: when each space last updated and
 * whether its remote policy is enabled.
 *
 * One run at a time: @ref synchronize is the only thing that runs the topics.
 */
class CMSync final : public ICMSync
{
public:
    /**
     * @brief Build the service and register one topic per tracked space.
     *
     * Namespaces of a tracked space that no route serves are deleted here, before any cycle runs.
     *
     * @param cmcrudPtr Namespace store.
     * @param storePtr Internal config store, where the per-space record lives.
     * @param routerPtr Router API.
     * @param topicFactory Builds each space's topic (`cmcontent::defaultTopicFactory` in production).
     * @param contentOptions Page size and timing tunables for the registrations.
     * @param retry How often a failed cycle is retried within one run.
     * @throws std::invalid_argument if @p topicFactory is empty.
     * @throws std::runtime_error if the persisted record cannot be read.
     */
    CMSync(const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
           const std::shared_ptr<::store::IStore>& storePtr,
           const std::shared_ptr<router::IRouterAPI>& routerPtr,
           const cmcontent::TopicFactory& topicFactory,
           const cmcontent::Options& contentOptions,
           cmcontent::RetryPolicy retry);
    ~CMSync() override;

    /**
     * @copydoc ICMSync::synchronize
     */
    bool synchronize() override;

    /**
     * @copydoc ICMSync::requestShutdown
     */
    void requestShutdown() override;

    /**
     * @copydoc ICMSync::getSpacesStatus
     */
    std::vector<SpaceStatus> getSpacesStatus() const override;

private:
    /// One tracked space. `topic` is declared after `sink` so it is destroyed first: destroying it
    /// waits for an in-flight cycle, which is still using the sink.
    struct Space
    {
        std::string name;
        std::shared_ptr<cmcontent::RulesetSpaceSink> sink;
        std::unique_ptr<cmcontent::IContentTopic> topic;
        cmcontent::RulesetDeployment deployment; ///< As of the last cycle; what the status reports.
        base::SyncStatus status {base::SyncStatus::READY};
        std::uint32_t lastSuccessfulUpdate {0}; ///< Persisted.
        bool enabled {false};                   ///< Persisted.
        bool policyKnown {false};               ///< `enabled` comes from a policy read (now or persisted).
    };

    /**
     * @brief Run one space's topic and fold the outcome into its state.
     *
     * @param space The space.
     * @return True when the persisted record changed.
     */
    bool syncSpace(Space& space);

    void loadState();     ///< Read the persisted record, when there is one.
    void persistState();  ///< Write the persisted record.
    void publishStatus(); ///< Rebuild the status snapshot.

    std::weak_ptr<::store::IStore> m_store;
    cmcontent::RetryPolicy m_retry;
    std::vector<Space> m_spaces; ///< Fixed at construction.
    std::mutex m_syncMutex;      ///< One synchronize() at a time.
    std::atomic<bool> m_shutdownRequested {false};
    base::StatusSnapshot<SpaceStatus> m_status;
};

} // namespace cm::sync

#endif // _CMSYNC_CMSYNC
