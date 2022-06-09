#ifndef _SOCKET_AUXILIAR_FUNCTIONS_H
#define _SOCKET_AUXILIAR_FUNCTIONS_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

constexpr int MAX_BUFFER_SIZE = 1024;
constexpr int MESSAGE_HEADER_SIZE = sizeof(uint32_t);

constexpr std::string_view TEST_SEND_MESSAGE = "Test message to be send!\n";
constexpr std::string_view TEST_DGRAM_SOCK_PATH = "/tmp/testDgram.sock";
constexpr std::string_view TEST_STREAM_SOCK_PATH = "/tmp/testStream.sock";

enum UnixSocketErrorCodes
{
    SOCKET_ERROR = -1,
    BIND_ERROR = -2,
    CHMOD_ERROR = -3,
    LISTEN_ERROR = -4,
    ACCEPT_ERROR = -5
};

/**
 * @brief Test auxiliar function to bind a UNIX socket
 *
 * @param path Socket pathname
 * @param socketType SOCK_STREAM | SOCK_DGRAM
 * @return int Socket file descriptor
 */
static int testBindUnixSocket(std::string_view path, const int socketType)
{
    /* Remove the socket's path if it already exists */
    unlink(path.data());

    /* Set-up sockaddr structure */
    struct sockaddr_un n_us;
    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path.data(), sizeof(n_us.sun_path) - 1);

    const int socketFD = socket(PF_UNIX, socketType, 0);
    if (0 > socketFD)
    {
        return UnixSocketErrorCodes::SOCKET_ERROR;
    }

    if (bind(socketFD, (struct sockaddr*)&n_us, SUN_LEN(&n_us)) < 0)
    {
        close(socketFD);
        return UnixSocketErrorCodes::BIND_ERROR;
    }

    /* Change socket's permissions */
    if (chmod(path.data(), 0660) < 0)
    {
        close(socketFD);
        return UnixSocketErrorCodes::CHMOD_ERROR;
    }

    if (SOCK_STREAM == socketType && listen(socketFD, 1) < 0)
    {
        close(socketFD);
        return UnixSocketErrorCodes::LISTEN_ERROR;
    }

    return socketFD;
}

/**
 * @brief Test auxiliar function to accept the socket connections
 *
 * @param serverSocketFD File descriptor of the connection socket
 * @return int File descriptor of the client socket
 */
static int testAcceptConnection(const int serverSocketFD)
{
    struct sockaddr_in _nc;
    memset(&_nc, 0, sizeof(_nc));
    socklen_t _ncl = sizeof(_nc);

    const int clientSocketFD = accept(serverSocketFD, (struct sockaddr*)&_nc, &_ncl);
    if (clientSocketFD < 0)
    {
        return UnixSocketErrorCodes::ACCEPT_ERROR;
    }

    return clientSocketFD;
}

#endif //_SOCKET_AUXILIAR_FUNCTIONS_H
