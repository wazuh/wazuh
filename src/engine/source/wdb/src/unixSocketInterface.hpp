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

constexpr int SOCKET_ERROR {-1}; ///< Socket error code

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
 * @return Size of the message on success. \ref SOCKET_ERROR otherwise (and errno is set).
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
 * @return Size of the message on success. \ref SOCKET_ERROR otherwise (and errno is set).
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
 * @return \ref SOCKET_ERROR on error (and errno is set).
 * @return 0 on socket disconnected or timeout.
 * @warning This function blocks until the message is received or the socket is disconnected.
 *
 */
int recvMsg(int sock, char* ret, uint32_t size);


} // namespace socketInterface

#endif
