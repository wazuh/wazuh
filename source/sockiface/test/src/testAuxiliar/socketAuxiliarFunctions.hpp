#ifndef _SOCKET_AUXILIAR_FUNCTIONS_H
#define _SOCKET_AUXILIAR_FUNCTIONS_H

#include <netinet/in.h>
#include <string>
#include <vector>

#include <base/logging.hpp>

enum UnixSocketErrorCodes
{
    SOCKET_ERROR = -1,
    BIND_ERROR = -2,
    CHMOD_ERROR = -3,
    LISTEN_ERROR = -4,
    ACCEPT_ERROR = -5
};

enum CommRetval
{
    SUCCESS = 0,
    COMMUNICATION_ERROR = -1,
    SIZE_ZERO = -2,
    SIZE_TOO_LONG = -3,
    INVALID_SOCKET = -4
};

constexpr int MAX_BUFFER_SIZE {1024};
constexpr int MESSAGE_HEADER_SIZE {sizeof(uint32_t)};
constexpr int MSG_MAX_SIZE {65536}; ///< Maximum message size (2^16)

constexpr std::string_view TEST_SEND_MESSAGE = "Test message to be send!\n";

/**
 * @brief Test auxiliar function to bind a UNIX socket
 *
 * @param path Socket pathname
 * @param socketType SOCK_STREAM | SOCK_DGRAM
 * @return int Socket file descriptor
 */
int testBindUnixSocket(std::string_view path, const int socketType);

/**
 * @brief Test auxiliar function to accept the socket connections
 *
 * @param socketFD File descriptor of the connection socket
 * @return int File descriptor of the client socket
 */
int testAcceptConnection(const int socketFD);

/**
 * @brief Connect to a UNIX socket of type `socketType` located at `path`
 *
 * @param path UNIX socket pathname
 * @param type UNIX socket type SOCK_STREAM | SOCK_DGRAM
 * @return socket file descriptor.
 * @throw std::runtime_error if the socket cannot be created.
 */
int testSocketConnect(std::string_view path, const int socketType);

/**
 * @brief Receive a message from a stream socket, full message (MSG_WAITALL).
 *
 * @param socketFD File descriptor of the socket.
 * @param buf buffer to store the message.
 * @param size size of the buffer.
 * @return ssize_t size of the message on success.
 * @return 0 on socket disconnected or timeout.
 * @return \ref SOCKET_ERROR otherwise (and errno is set).
 *
 * @warning This function blocks until the message is received or the socket is
 * disconnected.
 *
 */
ssize_t testRecvWaitAll(int socketFD, void* buf, size_t size) noexcept;

/**
 * @brief Send a message to a socket.
 *
 * @param socketFD socket file descriptor.
 * @param msg message to send.
 * @param doSendLength send the message length before the message.
 * @return CommRetval::SUCCESS on success.
 * @return CommRetval::INVALID_SOCKET if the socket is =< 0.
 * @return CommRetval::SIZE_TOO_LONG if the message is too long (>= \ref MSG_MAX_SIZE).
 * @return CommRetval::SIZE_ZERO if msg is empty.
 * @return CommRetval::COMMUNICATION_ERROR if the socket cannot be written to. (errno is
 * set).
 *
 * @throw RecoverableError if a broken pipe error occurs (EPIPE).
 * @warning This function blocks until the message is sent or the socket is disconnected.
 */
CommRetval testSendMsg(const int socketFD, const std::string& msg, const bool doSendLength = true);

/**
 * @brief Receive a Wazuh protocol message from a socket.
 *
 * @param socketFD socket file descriptor.
 * @return vector<char> message on success.
 * @throw std::runtime_error on error.

 * @warning This function blocks until the message is received or the socket is
 * disconnected.
 */
std::vector<char> testRecvMsg(const int socketFD, const int sockType);

/**
 * @brief Receive a string from a socket, after parsing the Wazuh protocol.
 *
 * @param socketFD socket file descriptor.
 *
 * @return std::string message on success.
 *
 * @throw std::runtime_error on error.
 *
 * @warning This function blocks until the message is received or the socket is closed.
 */
std::string testRecvString(const int socketFD, const int sockType);

#endif //_SOCKET_AUXILIAR_FUNCTIONS_H
