#ifndef CONFREMOTE_ICONFREMOTE_HPP
#define CONFREMOTE_ICONFREMOTE_HPP

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
     * @brief Requests graceful shutdown for in-flight or future sync operations.
     */
    virtual void requestShutdown() = 0;

};

} // namespace confremote

#endif // CONFREMOTE_ICONFREMOTE_HPP
