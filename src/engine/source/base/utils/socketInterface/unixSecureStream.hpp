#ifndef _SOCKETINTERFACE_UNIX_SECSTREAM_H
#define _SOCKETINTERFACE_UNIX_SECSTREAM_H

#include "unixInterface.hpp"

namespace base::utils::socketInterface
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
    unixSecureStream(std::string_view path, const int maxMsgSize = 65536)
        : unixInterface(path, Protocol::STREAM, maxMsgSize) {};

    unixSecureStream(unixSecureStream&& moveOrigin)
        : unixInterface(std::move(moveOrigin))
        {};

    ~unixSecureStream() = default; // Close de socket in the base class.

    /**
     * @brief Send a message to the socket. Open the socket if it is not already open.
     *
     * @param msg message to send.
     *
     * @return SendRetval::SUCCESS on success.
     * @return SendRetval::size_zero if msg is empty.
     * @return SendRetval::size_too_long if msg is too long
     * @return SendRetval::SOCKET_ERROR if the socket cannot be written to. (errno is
     * set).
     *
     * @throws recoverableError if a broken pipe error occurs (EPIPE). Log the
     * warning and disconnect the socket.
     * @throws std::runtime_error if not connected and the socket cannot be connected.
     */
    SendRetval sendMsg(const std::string& msg) override;

    /**
     * @brief  Receive a message from the socket.
     *
     * @return vector of bytes (char) received terminated by an '\0' character.
     *
     * @throws recoverableError if connection is reset by peer (ECONNRESET), timeout
     * or disconnected (errno is not set).
     * @note This method no try connect if the socket is not connected.
     * @warning this method blocks until the message is received or the socket is
     * disconnected.
     */
    std::vector<char> recvMsg() override;

    /**
     * @brief Receive a message from the socket and store it in a string.
     *
     * This method is a wrapper around \ref recvMsg.
     * @return string containing the message received.
     * @note This method no try connect if the socket is not connected.
     * @warning this method blocks until the message is received or the socket is
     * disconnected.
     */
    std::string recvString(); // override;
};
} // namespace base::utils::socketInterface

#endif // _SOCKETINTERFACE_UNIX_SECSTREAM_H
