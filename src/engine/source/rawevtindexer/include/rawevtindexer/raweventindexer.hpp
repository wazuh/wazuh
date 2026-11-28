// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _RAWEVENTINDEXER_RAWEVENTINDEXER_HPP
#define _RAWEVENTINDEXER_RAWEVENTINDEXER_HPP

#include <atomic>
#include <memory>
#include <string>
#include <string_view>

#include <wiconnector/iwindexerconnector.hpp>

#include <rawevtindexer/iraweventindexer.hpp>

namespace raweventindexer
{

class RawEventIndexer final : public IRawEventIndexer
{
private:
    std::atomic<bool> m_enabled;                                ///< Atomic flag for enabled state
    std::weak_ptr<wiconnector::IWIndexerConnector> m_connector; ///< Weak pointer to indexer connector

public:
    /**
     * @brief Construct a new Raw Event Indexer object
     *
     * Raw events always go to wiconnector::RAW_EVENTS_INDEX, the index the connector routes to its `raw` bucket.
     *
     * @param connector Shared pointer to the indexer connector
     */
    explicit RawEventIndexer(std::weak_ptr<wiconnector::IWIndexerConnector> connector);

    /**
     * @copydoc IRawEventIndexer::index
     */
    void index(const std::string& data) override;

    /**
     * @copydoc IRawEventIndexer::index
     */
    void index(std::string&& data) override;

    /**
     * @copydoc IRawEventIndexer::index
     */
    void index(const char* data) override;

    /**
     * @copydoc IRawEventIndexer::index
     */
    void index(std::string_view data) override;

    /**
     * @copydoc IRawEventIndexer::enable
     */
    void enable() override;

    /**
     * @copydoc IRawEventIndexer::disable
     */
    void disable() override;

    /**
     * @copydoc IRawEventIndexer::isEnabled
     */
    bool isEnabled() const override;

    /**
     * @copydoc IRawEventIndexer::hotReloadConf
     */
    void hotReloadConf(const json::Json& value) override;

    ~RawEventIndexer() override = default;
};

} // namespace raweventindexer

#endif // _RAWEVENTINDEXER_RAWEVENTINDEXER_HPP
