#ifndef _SOCKETINTERFACE_UNIX_H
#define _SOCKETINTERFACE_UNIX_H

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace base::utils::socketInterface
{

/**
 * @brief Specifies the protocol used by the socket.
 */
enum class Protocol
{
    STREAM,
    DATAGRAM,
};

/**
 * @brief Send operation result codes.
 */
enum class SendRetval
{
    SUCCESS,
    SIZE_ZERO,
    SIZE_TOO_LONG,
    SOCKET_ERROR,
};

/**
 * @brief Exeption thrown when the socket is not connected but a reconnection is possible.
 *
 * E.g: The socket is closed remotely, the socket is full, broken pipe, connection reset,
 * etc.
 */
class RecoverableError : public std::runtime_error
{
public:
    RecoverableError(const std::string& msg)
        : std::runtime_error(msg)
    {
    }
};

/**
 * @brief Base class to interface with both, stream and datagram, UNIX sockets.
 *
 * @note This class needs to be inherited by a class that implements the actual socket
 * interface.
 */
class unixInterface
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
    unixInterface(std::string_view path,
                  const Protocol protocol,
                  const uint32_t maxMsgSize);
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
     * @brief Get the Maximum message size.
     *
     * @return maximum message size.
     */
    const auto getMaxMsgSize() const noexcept { return m_maxMsgSize; }

    /**
     * @brief Get the Path to the socket.
     *
     * @return path to the socket.
     */
    const auto& getPath() const noexcept { return m_path; }

    /**
     * @brief Connect to the socket, reconnect if already connected.
     *
     * @throws std::runtime_error if the connection fails.
     */
    void socketConnect();

    /**
     * @brief Disconnect from the socket, if connected.
     */
    void socketDisconnect();

    /**
     * @brief Check if the socket is connected.
     *
     * @return true if the socket is connected, false otherwise.
     */
    bool isConnected() const noexcept;

    /*
     * The following methods should be implemented in the derived classes.
     */
    virtual SendRetval sendMsg(const std::string& msg) = 0;
    virtual std::vector<char> recvMsg() = 0;
};

} // namespace base::utils::socketInterface
#endif // _SOCKETINTERFACE_UNIX_H
