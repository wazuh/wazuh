#ifndef REMOTECONF_IREMOTECONF_HPP
#define REMOTECONF_IREMOTECONF_HPP

#include <functional>
#include <string_view>

#include <base/json.hpp>

namespace remoteconf
{

class IRemoteConf
{
public:
    virtual ~IRemoteConf() = default;

    /**
     * @brief Initializes runtime settings from the remote source.
     *
     * Non-throwing outward behavior: failures are handled internally.
     */
    virtual void initialize() = 0;

    /**
     * @brief Refreshes runtime settings from the remote source.
     *
     * Non-throwing outward behavior: failures are handled internally.
     */
    virtual void refresh() = 0;

    /**
     * @brief Registers a callback for a specific setting key.
     *
     * @param key Setting key (flattened path style).
     * @param onChange Callback invoked with the candidate value. Return true to accept/apply it.
     * @param defaultValue Fallback value applied when no remote/cache value is available.
     */
    virtual void addTrigger(std::string_view key,
                            std::function<bool(const json::Json& cnf)> onChange,
                            const json::Json& defaultValue) = 0;
};

} // namespace remoteconf

#endif // REMOTECONF_IREMOTECONF_HPP
