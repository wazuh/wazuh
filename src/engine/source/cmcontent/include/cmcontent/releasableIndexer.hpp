// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMCONTENT_RELEASABLE_INDEXER_HPP
#define CMCONTENT_RELEASABLE_INDEXER_HPP

#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include <contentIndexer.hpp>

namespace cmcontent
{

/**
 * @brief The Engine's indexer as the content topics see it, with a switch to let go of it.
 *
 * The topics and the event writer share one connector, and every topic holds its indexer for its
 * whole life. Without this, stopping the writer would only drop one of the connector's owners, and
 * its queue and threads would outlive the shutdown sequence. @ref release drops the topics' share at
 * the same point, so the connector stops when the Engine shuts it down.
 *
 * Calls hold a shared lock, so they still run concurrently; @ref release waits for the ones in
 * flight. After it, every call fails as an unreachable indexer would.
 */
class ReleasableIndexer final : public content_manager::IContentIndexer
{
public:
    /**
     * @brief Wrap an indexer.
     *
     * @param inner The indexer the calls go to.
     * @throws std::invalid_argument if @p inner is null.
     */
    explicit ReleasableIndexer(std::shared_ptr<content_manager::IContentIndexer> inner);

    /// Drop the wrapped indexer, once the calls in flight have returned. Idempotent.
    void release() noexcept;

    /**
     * @copydoc content_manager::IContentIndexer::openPit
     */
    content_manager::ContentPit
    openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards) override;

    /**
     * @copydoc content_manager::IContentIndexer::closePit
     */
    void closePit(const content_manager::ContentPit& pit) noexcept override;

    /**
     * @copydoc content_manager::IContentIndexer::search
     */
    nlohmann::json search(const content_manager::ContentPit& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter,
                          const std::optional<nlohmann::json>& source,
                          const std::optional<nlohmann::json>& slice) override;

    /**
     * @copydoc content_manager::IContentIndexer::searchIndex
     */
    nlohmann::json searchIndex(std::string_view index,
                               std::size_t size,
                               const nlohmann::json& query,
                               const std::optional<nlohmann::json>& source) override;

private:
    /// @return The wrapped indexer. @pre The shared lock is held.
    content_manager::IContentIndexer& inner() const;

    mutable std::shared_mutex m_mutex;
    std::shared_ptr<content_manager::IContentIndexer> m_inner;
};

} // namespace cmcontent

#endif // CMCONTENT_RELEASABLE_INDEXER_HPP
