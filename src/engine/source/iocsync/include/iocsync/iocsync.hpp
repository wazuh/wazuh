// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef IOCSYNC_IOCSYNC_HPP
#define IOCSYNC_IOCSYNC_HPP

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <base/statusSnapshot.hpp>
#include <cmcontent/contentTopic.hpp>
#include <cmcontent/iocTypeSink.hpp>
#include <cmcontent/registration.hpp>
#include <iockvdb/iManager.hpp>
#include <store/istore.hpp>

#include <iocsync/iiocsync.hpp>

namespace ioc::sync
{

/**
 * @brief Keeps the IOC enrichment databases in step with the indexer.
 *
 * One content topic per supported IOC type, whose sink loads it into its KVDB. This class decides
 * when the topics run, rebuilds a database that has gone missing, turns each outcome into the status
 * the API reports, and persists each type's hash — which is also the topic's change-detection token.
 *
 * One run at a time: @ref synchronize is the only thing that runs the topics, and the token store
 * it hands them is only touched from inside it.
 */
class IocSync final : public IIocSync
{
public:
    /**
     * @brief Build the service and register one topic per supported IOC type.
     *
     * @param kvdbiocManagerPtr KVDB manager holding the IOC databases.
     * @param storePtr Internal config store, where each type's hash lives.
     * @param topicFactory Builds each type's topic (`cmcontent::defaultTopicFactory` in production).
     * @param contentOptions Page size and timing tunables for the registrations.
     * @param retry How often a failed cycle is retried within one run.
     * @throws std::invalid_argument if @p topicFactory is empty.
     * @throws std::runtime_error if the persisted state cannot be read.
     */
    IocSync(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocManagerPtr,
            const std::shared_ptr<::store::IStore>& storePtr,
            const cmcontent::TopicFactory& topicFactory,
            const cmcontent::Options& contentOptions,
            cmcontent::RetryPolicy retry);
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

private:
    /// One IOC type. `topic` is declared after `sink` so it is destroyed first: destroying it waits
    /// for an in-flight cycle, which is still using the sink.
    struct IocType
    {
        std::string type;
        std::string targetDb;
        std::shared_ptr<cmcontent::IocTypeSink> sink;
        std::unique_ptr<cmcontent::IContentTopic> topic;
        std::string hash;                       ///< Persisted; the topic's token.
        std::uint32_t lastSuccessfulUpdate {0}; ///< Persisted.
        base::SyncStatus status {base::SyncStatus::READY};
    };

    /**
     * @brief Run one type's topic and fold the outcome into its state.
     *
     * @param type The IOC type.
     * @param kvdb The KVDB manager.
     */
    void syncType(IocType& type, const ioc::kvdb::IKVDBManager& kvdb);

    void loadState();     ///< Read the persisted state, when there is one.
    void persistState();  ///< Write the persisted state.
    void publishStatus(); ///< Rebuild the status snapshot.

    std::weak_ptr<ioc::kvdb::IKVDBManager> m_kvdbiocManagerPtr;
    std::weak_ptr<::store::IStore> m_store;
    cmcontent::RetryPolicy m_retry;
    std::vector<IocType> m_types; ///< Fixed at construction.
    std::mutex m_syncMutex;       ///< One synchronize() at a time.
    bool m_stateChanged {false};  ///< The persisted state must be written; touched under m_syncMutex.
    std::atomic<bool> m_shutdownRequested {false};
    base::StatusSnapshot<IocTypeStatus> m_status;
};

} // namespace ioc::sync

#endif // IOCSYNC_IOCSYNC_HPP
