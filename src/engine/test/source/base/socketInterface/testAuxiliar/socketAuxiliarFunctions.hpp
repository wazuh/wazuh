#ifndef _SOCKET_AUXILIAR_FUNCTIONS_H
#define _SOCKET_AUXILIAR_FUNCTIONS_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

constexpr int MAX_BUFFER_SIZE = 1024;
constexpr int MESSAGE_HEADER_SIZE = sizeof(uint32_t);
constexpr std::string_view TEST_SEND_MESSAGE = "Test message to be send!\n";
constexpr std::string_view TEST_SOCKET_PATH = "/tmp/test.sock";

/**
 * @brief Test auxiliar function to bind a datagram UNIX socket
 *
 * @param path Socket pathname
 * @return int Socket file descriptor
 */
static int testBindUnixSocket(std::string_view path)
{
    int sockFD = 0;
    struct sockaddr_un n_us;

    /* Make sure the path isn't there */
    unlink(path.data());

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path.data(), sizeof(n_us.sun_path) - 1);

    if ((sockFD = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        return (-1);
    }

    if (bind(sockFD, (struct sockaddr*)&n_us, SUN_LEN(&n_us)) < 0)
    {
        close(sockFD);
        return (-1);
    }

    /* Change permissions */
    if (chmod(path.data(), 0660) < 0)
    {
        close(sockFD);
        return (-1);
    }

    if (listen(sockFD, 1) < 0)
    {
        close(sockFD);
        return (-1);
    }

    return (sockFD);
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
        return (-1);
    }

    return (clientSocketFD);
}
#endif //_SOCKET_AUXILIAR_FUNCTIONS_H
