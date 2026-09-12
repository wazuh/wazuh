#ifndef IOCSYNC_IOCSYNC_HPP
#define IOCSYNC_IOCSYNC_HPP

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
#include <cmcontent/iocTypeSink.hpp>
#include <cmcontent/registration.hpp>
#include <iockvdb/iManager.hpp>
#include <store/istore.hpp>
#include <wiconnector/iwindexerconnector.hpp>

#include <iocsync/iiocsync.hpp>

namespace ioc::sync
{

// Forward declarations, state of synchronized IOC database
class SyncedIOCDatabase;

/**
 * @brief Keeps the IOC enrichment databases in step with the indexer.
 *
 * The download itself — the PIT, the pagination, the consumer-readiness check, the per-type hash
 * comparison — is no longer implemented here. It is one `ContentRegister` per IOC type over the
 * shared content manager, and what is left in this class is the part that is genuinely IOC-specific:
 * which types to track, what their persisted state looks like, and how a cycle's outcome maps onto
 * the status the API reports.
 */
class IocSync : public IIocSync
{

private:
    /// One IOC type's registration: the sink it feeds, the token it is at, and the topic itself.
    ///
    /// Declaration order is destruction order reversed, and it matters: `topic` must go first,
    /// because destroying it blocks until any in-flight cycle has drained and that cycle is still
    /// using the sink and the token cell.
    struct Registration
    {
        std::shared_ptr<cmcontent::IocTypeSink> sink;
        std::shared_ptr<cmcontent::TokenCell> token;
        std::unique_ptr<cmcontent::IContentTopic> topic;
    };

    std::weak_ptr<wiconnector::IWIndexerConnector> m_indexerPtr; ///< Indexer connector resource
    std::weak_ptr<ioc::kvdb::IKVDBManager> m_kvdbiocManagerPtr;  ///< KVDB IOC manager
    std::weak_ptr<::store::IStore> m_store;                      ///< Internal config store

    std::size_t m_attempts;    ///< Number of attempts to retry a cycle before giving up
    std::size_t m_waitSeconds; ///< Seconds to wait between attempts

    nlohmann::json m_indexerConnection; ///< Indexer connection settings handed to every registration
    cmcontent::Options m_contentOptions; ///< Page size and timing tunables for every registration
    cmcontent::TopicFactory m_topicFactory; ///< Builds each type's topic; substituted in tests

    /// Guards m_databasesState and serialises whole scheduled cycles against each other.
    ///
    /// It does NOT reach the content cycle: an on-demand update runs on one of the content
    /// manager's lane workers, not on the thread that holds this, so nothing the cycle touches may
    /// live behind this mutex. That is why each type's token lives in its own
    /// `cmcontent::TokenCell` rather than in `m_databasesState` — the cell is what the cycle reads
    /// and writes, and `m_databasesState` is reconciled from it by whichever thread holds this
    /// mutex, at a point where no cycle for that type can be running.
    mutable std::shared_mutex m_mutex;
    std::vector<SyncedIOCDatabase> m_databasesState; ///< State of the IOC databases being synchronized

    /// Derived state over m_databasesState: one entry per tracked type.
    ///
    /// Structural changes (insert/erase) are serialised by m_mutex. m_registrationsMutex guards the
    /// container itself, for the callers that cannot take m_mutex: requestShutdown() and
    /// requestOnDemandUpdate() both run while a cycle holds it, and waiting would defeat their
    /// purpose.
    std::unordered_map<std::string, Registration> m_registrations;
    mutable std::mutex m_registrationsMutex;

    std::atomic<bool> m_shutdownRequested {false}; ///< Flag to signal graceful shutdown of sync operations

    /// Lock-free status snapshot of all IOC types. Read via load() (wait-free). Rebuilt and published
    /// via store() by updateIocStatusSnapshot() on the single sync thread.
    base::StatusSnapshot<IocTypeStatus> m_iocStatus;

    /// Rebuild the IOC status from m_databasesState and publish it atomically (lock-free reads).
    void updateIocStatusSnapshot();

    /// Report a sync cycle that could not complete: types without a usable version yet (empty hash)
    /// or that were mid-sync (RUNNING) are marked FAILED. Types with an existing version keep it
    /// (READY, old data still usable). Publishes the snapshot.
    void reportSyncFailure();

    /**
     * @brief Check if IOC data index exists in wazuh-indexer
     *
     * @return true if the IOC index exists, false otherwise
     * @throws std::runtime_error on errors.
     */
    bool existIocDataInRemote();

    /**
     * @brief Synchronize a single IOC type through its registration.
     *
     * @param dbState State of the IOC database to synchronize.
     * @param kvdbiocPtr KVDB IOC manager shared pointer.
     * @return true if the type's persisted state changed.
     * @pre m_mutex is held.
     */
    bool syncIOCType(SyncedIOCDatabase& dbState, const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocPtr);

    /**
     * @brief Copy a type's token out of its cell into the persisted state.
     *
     * The cycle writes the cell; this is where that reaches `m_databasesState`, on the thread that
     * owns it. Called after every cycle including the ones that failed or did not run, because an
     * on-demand cycle may have committed in the meantime and the state document must not end up
     * describing a hash the databases no longer hold.
     *
     * @param dbState State to update.
     * @param registration The type's registration.
     * @return True when the stored hash changed, i.e. the state must be persisted.
     * @pre m_mutex is held.
     */
    static bool reconcileToken(SyncedIOCDatabase& dbState, const Registration& registration);

    void addIOCTypeToSync(std::string_view iocType);      ///< Add an IOC type to the sync list
    void removeIOCTypeFromSync(std::string_view iocType); ///< Remove an IOC type from the sync list

    /**
     * @brief Build the content registration for one IOC type.
     *
     * @param iocType IOC type.
     * @param initialToken Hash the type is already at, seeded into its token cell.
     * @pre m_mutex is held.
     */
    void registerTopic(std::string_view iocType, const std::string& initialToken);

    void loadStateFromStore(); ///< Load sync state from the internal store
    void saveStateToStore();   ///< Save sync state to the internal store

public:
    IocSync() = delete;

    /**
     * @brief Construct a new Ioc Sync object
     *
     * @param indexerPtr Pointer to the indexer connector resource, used for the cheap pre-flight
     * checks that short-circuit a whole cycle
     * @param kvdbiocManagerPtr Pointer to the KVDB IOC manager, used to create and manage IOC databases
     * @param storePtr Pointer to the internal config store
     * @param indexerConnection Indexer connection settings (hosts, ssl, credentials) for the content
     * registrations
     * @param maxRetries Maximum number of attempts to retry a cycle before failing
     * @param retryIntervalSeconds Seconds to wait between attempts
     * @param contentOptions Page size and timing tunables for the content registrations
     * @param topicFactory Builds each type's topic. Defaults to the real content manager; tests pass
     * a fake so the orchestration here can be exercised without an indexer.
     */
    IocSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
            const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocManagerPtr,
            const std::shared_ptr<::store::IStore>& storePtr,
            nlohmann::json indexerConnection,
            const size_t maxRetries,
            const size_t retryIntervalSeconds,
            cmcontent::Options contentOptions,
            cmcontent::TopicFactory topicFactory = {});
    ~IocSync() override;

    /**
     * @copydoc IIocSync::synchronize
     */
    void synchronize() override;

    /**
     * @copydoc IIocSync::requestShutdown
     */
    void requestShutdown() override;

    /**
     * @copydoc IIocSync::getIocStatus
     */
    std::vector<IocTypeStatus> getIocStatus() const override;

    /**
     * @brief Queue an out-of-band update, off the scheduler.
     *
     * Non-blocking: the request goes onto the content manager's short bounded lane and runs on one
     * of its workers, so it is safe to call from an HTTP handler thread. Same-topic concurrency is
     * refused by the topic itself, so this cannot run two cycles for one type at once.
     *
     * @param iocType IOC type to update. Empty updates every tracked type.
     */
    void requestOnDemandUpdate(std::string_view iocType = {}) override;
};

} // namespace ioc::sync

#endif // IOCSYNC_IOCSYNC_HPP
