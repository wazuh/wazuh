#ifndef _SOCKETINTERFACE_UNIX_H
#define _SOCKETINTERFACE_UNIX_H

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace base::utils::socketInterface
{

enum class Protocol
{
    STREAM,
    DATAGRAM,
};

/*
 enum class type {
     client,
     server,
 };
*/

enum class sndRetval
{
    SUCCESS,
    SIZE_ZERO,
    SIZE_TOO_LONG,
    SOCKET_ERROR,
};

class RecoverableError : public std::runtime_error
{
public:
    RecoverableError(const std::string& msg)
        : std::runtime_error(msg)
    {
    }
};

class unixInterface
{

private:
    int m_sock {-1};    ///< Socket file descriptor
    std::string m_path; ///< Path to the socket
    Protocol m_proto;   ///< Protocol type
    int m_maxMsgSize;   ///< Maximum message size

    /**
     * @brief Set the Socket Size option
     *
     * Set the SO_RCVBUF and SO_SNDBUF socket options.
     * @return false on success.
     * @return true on error.
     */
    bool setSocketSize() const noexcept;

protected:
    /**
     * @brief Get the Socket file descriptor
     *
     * @return socket file descriptor
     */
    const auto getFD() const noexcept { return m_sock; }

    /**
     * @brief Construct a new unix Interface
     *
     * @param path path to the socket
     * @param proto protocol type
     * @param maxMsgSize maximum message size
     */
    unixInterface(std::string_view path, const Protocol proto, const int maxMsgSize);
    virtual ~unixInterface();

public:
    /*
     * Avoid shared the same socket fd for multiple instances of the same socket path.
     */
    unixInterface(const unixInterface&) = delete;
    unixInterface& operator=(const unixInterface&) = delete;
    unixInterface(unixInterface&& moved)
        : m_path(std::move(moved.m_path))
        , m_proto(moved.m_proto)
        , m_maxMsgSize(moved.m_maxMsgSize)
    {
        this->m_sock = std::exchange(moved.m_sock, -1);
    };
    unixInterface& operator=(unixInterface&& moved)
    {
        if (this != &moved)
        {
            this->m_path = std::move(moved.m_path);
            this->m_proto = moved.m_proto;
            this->m_maxMsgSize = moved.m_maxMsgSize;
            this->m_sock = std::exchange(moved.m_sock, -1);
        }
        return *this;
    };

    /**
     * @brief Get the Maximum message size
     *
     * @return maximum message size
     */
    const auto getMaxMsgSize() const noexcept { return m_maxMsgSize; }

    /**
     * @brief Get the Path to the socket
     *
     * @return path to the socket
     */
    const auto& getPath() const noexcept { return m_path; }

    /**
     * @brief Connect to the socket, reconnect if already connected
     *
     * @throws std::runtime_error if the connection fails
     */
    void sConnect();

    /**
     * @brief Disconnect from the socket, if connected
     */
    void sDisconnect();

    /**
     * @brief Check if the socket is connected
     *
     * @return true if the socket is connected, false otherwise
     */
    bool isConnected() const noexcept;

    /*
     * The following methods should be implemented in the derived classes
     */

    /**
     * @brief Send a message to the socket. Connect if not connected.
     *
     * @param msg message to send.
     * @throw std::runtime_error if the connection fails
     */
    virtual sndRetval sendMsg(const std::string& msg) = 0;
    virtual std::vector<char> recvMsg() = 0;
    // virtual std::string recvString() = 0;
};

} // namespace base::utils::socketInterface
#endif // _SOCKETINTERFACE_UNIX_H
