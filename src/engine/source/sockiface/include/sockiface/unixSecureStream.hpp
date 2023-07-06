#ifndef _SOCKETINTERFACE_UNIX_SECSTREAM_H
#define _SOCKETINTERFACE_UNIX_SECSTREAM_H

#include "unixInterface.hpp"

namespace sockiface
{
/*
    Wazuh TCP protocol format

    On the TCP messages the payload size must be prefixed to the actual payload:

    - TCP Message: <Payload Size><Payload>

    The "Payload Size" has the following format:
    - Size: 4 bytes
    - Sign: Unsigned
    - Endianness: Little-endian

    See: https://documentation.wazuh.com/current/development/message-format.html
*/

constexpr int STREAM_MAX_MSG_SIZE {65536};

/**
 * @brief This class implements an interface to a UNIX stream socket.
 * The messages are handled by following the Wazuh TCP protocol.
 */
class unixSecureStream : public unixInterface
{
private:
    /**
     * @brief Receive a message from a stream socket, full message (MSG_WAITALL).
     *
     * @param buf buffer to store the message.
     * @param size size of the buffer.
     * @return int size of the message on success.
     * @return 0 on socket disconnected or timeout.
     * @return \ref SOCKET_ERROR otherwise (and errno is set).
     *
     * @warning This function blocks until the message is received or the socket is
     * disconnected.
     *
     */
    ssize_t recvWaitAll(void* buf, size_t size) const noexcept;

public:
    /**
     * @brief Create a unixSecureStream object linked to a UNIX socket located at `path`.
     *
     * Set the socket size to the maximum message size (default=2^16).
     * @param path UNIX domain socket pathname.
     * @param maxMsgSize Maximum message size (default=2^16).
     *
     * @throw std::invalid_argument if the path is empty.
     */
    unixSecureStream(std::string_view path, const int maxMsgSize = STREAM_MAX_MSG_SIZE)
        : unixInterface(path, Protocol::STREAM, maxMsgSize) {};

    unixSecureStream(unixSecureStream&& moveOrigin)
        : unixInterface(std::move(moveOrigin)) {};

    ~unixSecureStream() = default; // Close de socket in the base class.

    /**
     * @copydoc ISockHandler::sendMsg
    */
    SendRetval sendMsg(const std::string& msg) override;

    /**
     * @copydoc ISockHandler::recvMsg
    */
    std::vector<char> recvMsg() override;
};
} // namespace base::utils::socketInterface

#endif // _SOCKETINTERFACE_UNIX_SECSTREAM_H
