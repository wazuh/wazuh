#ifndef _ISOCKFACE_UNIXINTERFACE_HPP
#define _ISOCKFACE_UNIXINTERFACE_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

#include <sockiface/isockHandler.hpp>

namespace sockiface
{

/**
 * @brief Base class to interface with both, stream and datagram, UNIX sockets.
 *
 * @note This class needs to be inherited by a class that implements the actual socket
 * interface.
 */
class unixInterface : public ISockHandler
{

private:
    int m_sock {-1};       ///< Socket file descriptor.
    std::string m_path;    ///< Path to the socket.
    Protocol m_protocol;   ///< Protocol type.
    uint32_t m_maxMsgSize; ///< Maximum message size.

    /**
     * @brief Set the Socket Size option.
     *
     * Set the SO_RCVBUF and SO_SNDBUF socket options.
     * @return false on success.
     * @return true on error.
     */
    bool setSocketSize() const noexcept;

protected:
    /**
     * @brief Get the Socket file descriptor.
     *
     * @return socket file descriptor.
     */
    const auto getFD() const noexcept { return m_sock; }

    /**
     * @brief Construct a new UNIX Interface.
     *
     * @param path path to the socket.
     * @param protocol protocol type.
     * @param maxMsgSize maximum message size.
     */
    unixInterface(std::string_view path, const Protocol protocol, const uint32_t maxMsgSize);

    /**
     * @brief Close the socket and destroy the object.
     */
    virtual ~unixInterface();

public:
    /*
     * Avoid shared the same socket fd for multiple instances of the same socket path.
     */
    unixInterface(const unixInterface&) = delete;
    unixInterface& operator=(const unixInterface&) = delete;
    unixInterface(unixInterface&& moved)
        : m_path(std::move(moved.m_path))
        , m_protocol(moved.m_protocol)
        , m_maxMsgSize(moved.m_maxMsgSize)
    {
        this->m_sock = std::exchange(moved.m_sock, -1);
    };

    unixInterface& operator=(unixInterface&& moved)
    {
        if (this != &moved)
        {
            this->m_path = std::move(moved.m_path);
            this->m_protocol = moved.m_protocol;
            this->m_maxMsgSize = moved.m_maxMsgSize;
            this->m_sock = std::exchange(moved.m_sock, -1);
        }
        return *this;
    };

    /**
     * @copydoc ISockHandler::getMaxMsgSize
     */
    uint32_t getMaxMsgSize() const noexcept override { return m_maxMsgSize; }

    /**
     * @copydoc ISockHandler::getPath
     */
    std::string getPath() const noexcept override { return m_path; }

    /**
     * @copydoc ISockHandler::socketConnect
     */
    void socketConnect() override;

    /**
     * @copydoc ISockHandler::socketDisconnect
     */
    void socketDisconnect() override;

    /**
     * @copydoc ISockHandler::isConnected
     */
    bool isConnected() const noexcept override;
};

} // namespace sockiface
#endif // _ISOCKFACE_UNIXINTERFACE_HPP
