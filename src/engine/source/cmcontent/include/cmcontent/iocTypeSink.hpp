// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMCONTENT_IOC_TYPE_SINK_HPP
#define CMCONTENT_IOC_TYPE_SINK_HPP

#include <memory>
#include <string>

#include <contentSink.hpp>
#include <iockvdb/iManager.hpp>

namespace cmcontent
{

/**
 * @brief Loads one IOC type's documents into a staging KVDB and hot-swaps it into place.
 *
 * Readers never observe a half-written database: the one they read is only ever swapped whole.
 * One sink per IOC type, matching one topic per IOC type.
 */
class IocTypeSink final : public content_manager::IContentSink
{
public:
    /**
     * @brief Build the sink.
     *
     * @param kvdbManager KVDB manager owning both the staging and the target databases.
     * @param iocType IOC type this sink handles.
     */
    IocTypeSink(std::weak_ptr<ioc::kvdb::IKVDBManager> kvdbManager, std::string iocType);

    ~IocTypeSink() override;

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
    /// Drops the staging database, if one is open. Never throws.
    void discardStaging() noexcept;

    std::weak_ptr<ioc::kvdb::IKVDBManager> m_kvdbManager;
    std::string m_iocType;
    std::string m_targetDbName;

    /// Fixed per type, so a staging database left behind by a crash is still addressable — and
    /// therefore removable — by the next session. See beginSession().
    std::string m_stagingDbNameForType;

    std::string m_stagingDbName; ///< Empty when no session is open.
    std::size_t m_storedCount {0};
};

} // namespace cmcontent

#endif // CMCONTENT_IOC_TYPE_SINK_HPP
