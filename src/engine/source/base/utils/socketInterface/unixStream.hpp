#ifndef _SOCKINTERFACE_USTREAM_H
#define _SOCKINTERFACE_USTREAM_H

#include <stdexcept>
#include <string>
#include <vector>

#include <stdint.h>

#include "common.h"

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

namespace base::utils::socketInterface::unixStream
{
constexpr auto MSG_MAX_SIZE {65536}; ///< Maximum message size (2^16)

/**
 * @brief
 *
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
 * @brief Connect to a UNIX stream socket located at `path`
 *
 * @param path UNIX domain socket pathname
 * @return socket file descriptor.
 * @throw std::runtime_error if the socket cannot be created.
 */
int socketConnect(std::string_view path);

/**
 * @brief Send a message to a stream socket, full message (MSG_WAITALL)
 *
 * @param sock sock file descriptor.
 * @param msg message to send.
 * @return CommRetval::SUCCESS on success.
 * @return CommRetval::INVALID_SOCKET if the socket is =< 0.
 * @return CommRetval::SIZE_TOO_LONG if the message is too long (>= \ref MSG_MAX_SIZE).
 * @return CommRetval::SIZE_ZERO if msg is empty.
 * @return CommRetval::SOCKET_ERROR if the socket cannot be written to. (errno is set).
 *
 * @throw RecoverableError if a broken pipe error occurs (EPIPE).
 * @warning This function blocks until the message is sent or the socket is disconnected.
 */
CommRetval sendMsg(const int sock, const std::string& msg);

/**
 * @brief Receive a message from a stream socket, full message (MSG_WAITALL)
 *
 * @param sock sock file descriptor.
 * @return vector<char> message on success.
 * @throw std::runtime_error on error.

 * @warning This function blocks until the message is received or the socket is
 * disconnected.
 */
std::vector<char> recvMsg(const int sock);

/**
 * @brief Receive a message from a stream socket, full message (MSG_WAITALL)
 *
 * @param sock sock file descriptor.
 * @return std::string message on success.
 *
 * @throw RecoverableError if the remote socket is closed or if a ECONNRESET error occurs.
 * @throw std::runtime_error on other errors.
 *
 * @warning This function blocks until the message is received or the socket is
 */
std::string recvString(const int sock);

} // namespace socketinterface

#endif
