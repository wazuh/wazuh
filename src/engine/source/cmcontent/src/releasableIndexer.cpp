// SPDX-License-Identifier: AGPL-3.0-or-later
#include <mutex>
#include <stdexcept>
#include <utility>

#include <cmcontent/releasableIndexer.hpp>

namespace cmcontent
{

ReleasableIndexer::ReleasableIndexer(std::shared_ptr<content_manager::IContentIndexer> inner)
    : m_inner(std::move(inner))
{
    if (!m_inner)
    {
        throw std::invalid_argument {"ReleasableIndexer needs an indexer"};
    }
}

void ReleasableIndexer::release() noexcept
{
    std::shared_ptr<content_manager::IContentIndexer> released;
    {
        std::unique_lock lock {m_mutex};
        released = std::move(m_inner);
    }
    // Destroyed here, outside the lock: with the last owner gone this stops the connector.
}

content_manager::IContentIndexer& ReleasableIndexer::inner() const
{
    if (!m_inner)
    {
        throw std::runtime_error {"the indexer connector has been shut down"};
    }
    return *m_inner;
}

content_manager::ContentPit
ReleasableIndexer::openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards)
{
    std::shared_lock lock {m_mutex};
    return inner().openPit(indices, keepAlive, expandWildcards);
}

void ReleasableIndexer::closePit(const content_manager::ContentPit& pit) noexcept
{
    std::shared_lock lock {m_mutex};
    if (m_inner)
    {
        m_inner->closePit(pit);
    }
}

nlohmann::json ReleasableIndexer::search(const content_manager::ContentPit& pit,
                                         std::size_t size,
                                         const nlohmann::json& query,
                                         const nlohmann::json& sort,
                                         const std::optional<nlohmann::json>& searchAfter,
                                         const std::optional<nlohmann::json>& source,
                                         const std::optional<nlohmann::json>& slice)
{
    std::shared_lock lock {m_mutex};
    return inner().search(pit, size, query, sort, searchAfter, source, slice);
}

nlohmann::json ReleasableIndexer::searchIndex(std::string_view index,
                                              std::size_t size,
                                              const nlohmann::json& query,
                                              const std::optional<nlohmann::json>& source)
{
    std::shared_lock lock {m_mutex};
    return inner().searchIndex(index, size, query, source);
}

} // namespace cmcontent
