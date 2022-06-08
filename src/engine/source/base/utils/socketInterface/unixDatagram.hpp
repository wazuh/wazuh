#ifndef _SOCKINTERFACE_UDATAGRAM_H
#define _SOCKINTERFACE_UDATAGRAM_H

#include <string>

#include "common.h"

namespace base::utils::socketInterface::unixDatagram
{
constexpr auto MSG_MAX_SIZE {65536}; ///< Maximum message size (2^16)

/**
 * @brief Connect to a UNIX datagram socket located at `path`
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

}
#endif
