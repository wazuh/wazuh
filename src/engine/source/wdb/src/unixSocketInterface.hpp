#ifndef _WDB_PROTOCOL_H
#define _WDB_PROTOCOL_H

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <logging/logging.hpp>

/*
TODO readme with socket protocol description
*/

namespace socketinterface
{
// https://github.com/wazuh/wazuh/blob/v4.3.0/src/shared/wazuhdb_op.c#L29
// https://github.com/wazuh/wazuh/blob/v4.3.0/src/headers/defs.h#L31
// https://github.com/wazuh/wazuh/blob/v4.3.0/src/wazuh_db/main.c#L246-L249
constexpr int SOCKET_BUFFER_MAX_SIZE {65536}; ///< Maximum socket message size (2^16)
constexpr int HEADER_SIZE {sizeof(uint32_t)};
constexpr int MSG_MAX_SIZE {SOCKET_BUFFER_MAX_SIZE - HEADER_SIZE}; ///< Maximum message size (socket msg - '\0')

// Return codes
constexpr int INVALID_SOCKET {-5}; ///< Invalid socket
constexpr int NULL_PTR {-4};       ///< Message to send cannot be null
constexpr int SIZE_ZERO {-3};      ///< Message canot be empty
constexpr int SIZE_TOO_LONG {-2};  ///< Message size is too long
constexpr int SOCKET_ERROR {-1};   ///< Socket error code

/**
 * @brief Connect to a UNIX stream socket located at `path`
 *
 * @param path UNIX domain socket pathname
 * @return socket file descriptor in case of success, \ref SOCKET_ERROR otherwise.
 */
int socketConnect(const char* path);

/**
 * @brief Send a message to a stream socket, full message (MSG_WAITALL)
 *
 * @param sock sock file descriptor.
 * @param msg message to send.
 * @param size size of the message.
 * @return Size of the message on success.
 * @return \ref SOCKET_ERROR on socket error (and errno is set).
 * @return \ref SIZE_TOO_LONG if the message is too long.
 * @return \ref NULL_PTR if msg is a nullptr.
 * @return \ref SIZE_ZERO if msg is empty.
 * @return \ref INVALID_SOCKET if sock fd is =< 0.
 *
 * @warning This function blocks until the message is sent or the socket is disconnected.
 * @warning This function does not check the size of the message.
 */
int sendMsg(int sock, const char* msg, uint32_t size);

/**
 * @brief Send a c-string to a stream socket, full message (MSG_WAITALL)
 *
 * @param sock sock file descriptor.
 * @param msg message to send. Will be terminated by '\0'.
 * @return Size of the message on success.
 * @return \ref SOCKET_ERROR on socket error (and errno is set).
 * @return \ref SIZE_TOO_LONG if the message is too long.
 * @return \ref NULL_PTR if msg is a nullptr.
 * @return \ref SIZE_ZERO if msg is empty.
 * @return \ref INVALID_SOCKET if sock fd is =< 0.
 *
 * @warning This function blocks until the message is sent or the socket is disconnected.
 * @warning This function does not check the size of the message.
 */
int sendMsg(int sock, const char* msg);

/** @brief Receive a message from a stream socket, full message (MSG_WAITALL)
 *
 * Return the message in ret buffer
 * @param sock sock file descriptor.
 * @param[out] ret buffer to store the message.
 * @param size size of the ret buffer.
 * @return Size of the message on success.
 * @return \ref SIZE_TOO_LONG if the message is too long.
 * @return \ref SOCKET_ERROR on error (and errno is set).
 * @return 0 on socket disconnected or timeout.
 * @warning This function blocks until the message is received or the socket is
 * disconnected.
 *
 */
int recvMsg(int sock, char* ret, uint32_t size);

} // namespace socketinterface

#endif
