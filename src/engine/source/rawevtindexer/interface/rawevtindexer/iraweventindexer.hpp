#ifndef _RAWEVENTINDEXER_IRAWEVENTINDEXER_HPP
#define _RAWEVENTINDEXER_IRAWEVENTINDEXER_HPP

#include <string>
#include <string_view>

#include <base/json.hpp>

namespace raweventindexer
{

class IRawEventIndexer
{
public:
    virtual ~IRawEventIndexer() = default;

    /**
     * @brief Index the given raw event data if the indexer is enabled (ignore errors)
     *
     * @param data The raw event data to index, as a std::string.
     */
    virtual void index(const std::string& data) = 0;

    /**
     * @brief Index the given raw event data if the indexer is enabled (ignore errors)
     *
     * @param data The raw event data to index, as a C-style string (To avoid copies in some cases).
     */
    virtual void index(const char* data) = 0;

    /**
     * @brief Index the given raw event data if the indexer is enabled (ignore errors)
     *
     * @param data The raw event data to index, as a std::string_view (zero-copy view).
     */
    virtual void index(std::string_view data) = 0;

    /**
     * @brief Enable the raw event indexer.
     */
    virtual void enable() = 0;

    /**
     * @brief Disable the raw event indexer.
     */
    virtual void disable() = 0;

    /**
     * @brief Check if the raw event indexer is enabled.
     *
     * @return true if the indexer is enabled, false otherwise.
     */
    virtual bool isEnabled() const = 0;

    /**
     * @brief Applies a remote configuration value to the raw event indexer.
     *
     * @param value Candidate remote value for this module.
     * @throws std::invalid_argument if the value is not a valid boolean.
     */
    virtual void hotReloadConf(const json::Json& value) = 0;
};

} // namespace raweventindexer

#endif // _RAWEVENTINDEXER_IRAWEVENTINDEXER_HPP
