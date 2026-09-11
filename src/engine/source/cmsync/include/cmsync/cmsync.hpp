#ifndef _CMSYNC_CMSYNC
#define _CMSYNC_CMSYNC

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <json.hpp>

#include <base/statusSnapshot.hpp>
#include <cmcontent/contentTopic.hpp>
#include <cmcontent/registration.hpp>
#include <cmcontent/rulesetSink.hpp>
#include <cmcrud/icmcrudservice.hpp>
#include <router/iapi.hpp>
#include <store/istore.hpp>
#include <wiconnector/iwindexerconnector.hpp>

#include <cmsync/icmsync.hpp>

namespace cm::sync
{

// Forward declarations, state of synchronized namespace
class SyncedNamespace;

/**
 * @brief Keeps each space's ruleset namespace in step with the indexer.
 *
 * The download is no longer implemented here: it is one `ContentRegister` per space over the shared
 * content manager, which owns the PIT, the pagination and the consumer-readiness guarantee. What
 * remains is what is genuinely ruleset-specific — which spaces to track, how their namespaces map
 * onto router entries, and how a cycle's outcome becomes the status the API reports.
 */
class CMSync : public ICMSync
{

private:
    /// One space's registration: the sink it feeds and the topic it is registered under.
    ///
    /// Declaration order is destruction order reversed, and it matters: `topic` must go first,
    /// because destroying it blocks until any in-flight cycle has drained and that cycle is still
    /// using the sink.
    struct Registration
    {
        std::shared_ptr<cmcontent::RulesetSpaceSink> sink;
        std::unique_ptr<cmcontent::IContentTopic> topic;
    };

    std::weak_ptr<wiconnector::IWIndexerConnector> m_indexerPtr; ///< Indexer connector resource
    std::weak_ptr<cm::crud::ICrudService> m_cmcrudPtr;           ///< Resource namespace handler
    std::weak_ptr<::store::IStore> m_store;                      ///< Internal config store
    std::weak_ptr<router::IRouterAPI> m_router;                  ///< Router API for event injection

    std::size_t m_attempts;    ///< Number of attempts to retry a cycle before failing
    std::size_t m_waitSeconds; ///< Seconds to wait between attempts

    nlohmann::json m_indexerConnection;  ///< Indexer connection settings handed to every registration
    cmcontent::Options m_contentOptions; ///< Page size and timing tunables for every registration
    cmcontent::TopicFactory m_topicFactory; ///< Builds each space's topic; substituted in tests

    /// Guards m_namespacesState and serialises whole scheduled cycles against each other.
    ///
    /// It does NOT reach the content cycle: an on-demand update runs on one of the content
    /// manager's lane workers, not on the thread that holds this. Nothing a cycle touches may
    /// therefore live behind this mutex — which is why the token a cycle reads is derived from the
    /// router (see @ref loadTokenForRoute) rather than looked up in `m_namespacesState`.
    mutable std::shared_mutex m_mutex;
    std::vector<SyncedNamespace> m_namespacesState; ///< State of the namespaces being synchronized

    /// Derived state over m_namespacesState: one entry per tracked space.
    ///
    /// Structural changes are serialised by m_mutex. m_registrationsMutex guards the container
    /// itself, for the callers that cannot take m_mutex: requestShutdown() and
    /// requestOnDemandUpdate() both run while a cycle holds it.
    std::unordered_map<std::string, Registration> m_registrations;
    mutable std::mutex m_registrationsMutex;

    std::atomic<bool> m_shutdownRequested {false}; ///< Flag to signal graceful shutdown of sync operations

    /// Lock-free status snapshot of all spaces. Read via load() (wait-free). Rebuilt and published
    /// via store() by updateSpacesStatusSnapshot() on the single sync thread.
    base::StatusSnapshot<SpaceStatus> m_spacesStatus;

    /// Rebuild the spaces status from cached per-namespace state and publish it atomically (lock-free reads).
    void updateSpacesStatusSnapshot();

    /**
     * @brief Check if a space exists in the wazuh-indexer
     *
     * @param space Space name to check
     * @return true if the space exists, false otherwise
     * @throws std::runtime_error on errors.
     */
    bool existSpaceInRemote(std::string_view space);

    /**
     * @brief Run one content cycle for a space and fold its outcome into the persisted state.
     *
     * @param nsState State of the namespace to synchronize.
     * @return true if the state changed and must be dumped.
     * @pre m_mutex is held.
     */
    bool syncSpace(SyncedNamespace& nsState);

    /**
     * @brief Build the content registration for one space.
     *
     * @param nsState State of the namespace.
     * @pre m_mutex is held.
     */
    void registerTopic(const SyncedNamespace& nsState);

    /**
     * @brief Read the hash of the ruleset a route currently serves.
     *
     * The router is the source of truth here, not a persisted field: it knows what is *deployed*,
     * which is the only thing worth comparing a remote hash against. A route deleted out of band
     * therefore reads back as "no token", and the next cycle rebuilds it — exactly the behaviour
     * the previous per-space comparison had, without adding a field to the state document.
     *
     * Takes the route name rather than the topic on purpose: the mapping from one to the other
     * lives in `m_namespacesState`, and this runs on the content cycle's thread, which may be an
     * on-demand lane worker holding none of this object's locks. Binding the route name into the
     * registration at construction keeps the cycle away from that vector entirely.
     *
     * @param routeName Route name of the space.
     * @return The deployed hash, or "" when no route exists or it is not enabled.
     */
    std::string loadTokenForRoute(const std::string& routeName) const;

    /**
     * @brief Delete staging namespaces left behind by an interrupted sync.
     *
     * A cycle that is killed between `importNamespace` and the route swap leaves a namespace that
     * nothing points at and nothing will ever clean up, because the only reference to it died with
     * the process. They are identifiable — `cmsync_<space>_<suffix>` — and everything that is not
     * the namespace a tracked space currently serves is garbage by definition.
     *
     * @pre m_mutex is held.
     */
    void collectOrphanNamespaces();

    void addSpaceToSync(std::string_view space);      ///< Add a space to the sync list
    void removeSpaceFromSync(std::string_view space); ///< Remove a space from the sync

    void loadStateFromStore(); ///< Load sync state from the internal store
    void dumpStateToStore();   ///< Dump sync state to the internal store

public:
    CMSync() = delete;

    /**
     * @brief Construct a new CMSync object.
     *
     * @param indexerPtr Indexer connector, used for the cheap pre-flight checks.
     * @param cmcrudPtr Namespace store.
     * @param storePtr Internal config store.
     * @param routerPtr Router API.
     * @param indexerConnection Indexer connection settings for the content registrations.
     * @param attempts Number of attempts to retry a cycle before failing.
     * @param waitSeconds Seconds to wait between attempts.
     * @param contentOptions Page size and timing tunables for the content registrations.
     * @param topicFactory Builds each space's topic. Defaults to the real content manager; tests
     * pass a fake so the orchestration here can be exercised without an indexer.
     */
    CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
           const std::shared_ptr<::store::IStore>& storePtr,
           const std::shared_ptr<router::IRouterAPI>& routerPtr,
           nlohmann::json indexerConnection,
           const size_t attempts,
           const size_t waitSeconds,
           cmcontent::Options contentOptions,
           cmcontent::TopicFactory topicFactory = {});
    ~CMSync() override;

    /**
     * @brief Perform synchronization of all configured namespaces
     *
     * Iterates every space configured for synchronization, runs one content cycle for each, and
     * updates the router and the persisted state from its outcome.
     */
    void synchronize();

    /**
     * @copydoc ICMSync::requestShutdown
     */
    void requestShutdown() override;

    /**
     * @copydoc ICMSync::getSpacesStatus
     */
    std::vector<SpaceStatus> getSpacesStatus() const override;

    /**
     * @brief Queue an out-of-band update, off the scheduler.
     *
     * Non-blocking: the request goes onto the content manager's short bounded lane and runs on one
     * of its workers, so it is safe to call from an HTTP handler thread. Same-topic concurrency is
     * refused by the topic itself, so this cannot run two cycles for one space at once.
     *
     * @param space Space to update. Empty updates every tracked space.
     */
    void requestOnDemandUpdate(std::string_view space = {}) override;
};

} // namespace cm::sync

#endif // _CMSYNC_CMSYNC
