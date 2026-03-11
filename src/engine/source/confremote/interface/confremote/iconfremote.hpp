#ifndef CONFREMOTE_ICONFREMOTE_HPP
#define CONFREMOTE_ICONFREMOTE_HPP

#include <functional>
#include <string_view>

#include <base/json.hpp>

namespace confremote
{

class IConfRemote
{
public:
    virtual ~IConfRemote() = default;

    /**
     * @brief Synchronizes runtime settings from wazuh-indexer.
     *
     * Non-throwing outward behavior: failures are handled internally.
     */
    virtual void synchronize() = 0;

    /**
     * @brief Registers a callback for a specific setting key.
     *
     * Returns the last persisted value for the key if available,
     * otherwise returns the provided default value.
     *
     * @param key Setting key.
     * @param onConfigChange Callback invoked with the candidate value. Return true to accept/apply it.
     * @param defaultValue Fallback value returned when no persisted value is available.
     * @return json::Json Persisted value or provided default value.
     */
    virtual json::Json addTrigger(std::string_view key,
                                  std::function<bool(const json::Json&)> onConfigChange,
                                  const json::Json& defaultValue) = 0;
};

} // namespace confremote

#endif // CONFREMOTE_ICONFREMOTE_HPP
