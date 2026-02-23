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
    std::string m_indexName;                                    ///< Index name for raw events

public:
    static constexpr std::string_view DEFAULT_INDEX_NAME = "wazuh-events-raw-v5"; /// Default index name for raw events

    /**
     * @brief Construct a new Raw Event Indexer object
     *
     * @param connector Shared pointer to the indexer connector
     * @param indexName The index name to use for raw events (default: DEFAULT_INDEX_NAME)
     * @param isEnabled Initial enabled state (default: false)
     */
    explicit RawEventIndexer(std::weak_ptr<wiconnector::IWIndexerConnector> connector,
                             std::string_view indexName = DEFAULT_INDEX_NAME,
                             bool isEnabled = false);

    /**
     * @copydoc IRawEventIndexer::index
     */
    void index(const std::string& data) override;

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

    ~RawEventIndexer() override = default;
};

} // namespace raweventindexer

#endif // _RAWEVENTINDEXER_RAWEVENTINDEXER_HPP
