#include <src/unixSocketInterface.hpp>

#include <iostream>

#include <netinet/in.h>

#include <gtest/gtest.h>

using namespace socketinterface;
/*
TODO:
- Rename FILE_TEST
- TEST CONEXION OK
- TEST CONEXION NOT OK (PERMISSION)
- TEST CONEXION NOT OK (NOT SUCH FILE OR DIRECTORY)
- TEST SEND OK
- TEST SEND OUT OF RANGE
- TEST RECV OK
- TEST RECV OUT OF RANGE
- TEST Loopback
*/

// Test sock stream unix server
/* Bind to a Unix domain, using DGRAM sockets */
int OS_BindUnixDomain(const char *path)
{
    struct sockaddr_un n_us;
    int ossock = 0;

    /* Make sure the path isn't there */
    unlink(path);

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

    if ((ossock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        return (SOCKET_ERROR);
    }

    if (bind(ossock, (struct sockaddr *)&n_us, SUN_LEN(&n_us)) < 0) {
        close(ossock);
        return (SOCKET_ERROR);
    }

    /* Change permissions */
    if (chmod(path, 0660) < 0) {
        close(ossock);
        return (SOCKET_ERROR);
    }

    if (listen(ossock, 128) < 0) {
        close(ossock);
        return (SOCKET_ERROR);
    }

    return (ossock);
}

/* Accept a TCP connection */
int OS_AcceptTCP(int socket)
{
    int clientsocket;
    struct sockaddr_in _nc;
    socklen_t _ncl;

    memset(&_nc, 0, sizeof(_nc));
    _ncl = sizeof(_nc);

    if ((clientsocket = accept(socket, (struct sockaddr *) &_nc,
                               &_ncl)) < 0) {
        return (-1);
    }

    return (clientsocket);
}


TEST(wdb_procol, init)
{
    const char * hi = "Test mesg send!\n";
    char reply[1024] = {};

    // Create server
    int fd_server = OS_BindUnixDomain("/root/test.sock");
    ASSERT_GT(fd_server, 0);


    int fd_client = socketConnect("/root/test.sock");
    ASSERT_GT(fd_client, 0);

    std::cout << "send: " << hi << std::endl;
    sendMsg(fd_client, hi, strlen(hi));
    sendMsg(fd_client, "Hey, how are u?");
    int srv_client = OS_AcceptTCP(fd_server);
    int recvBytes = recvMsg(srv_client , reply, 1024);
    std::cout << "recv (" << recvBytes  << "): "<< reply << std::endl;
    recvBytes = recvMsg(srv_client , reply, 1024);
    std::cout << "recv (" << recvBytes  << "): "<< reply << std::endl;

    close(fd_client);
    close(fd_server);
    close(srv_client);
    unlink("/root/test.sock");
}
