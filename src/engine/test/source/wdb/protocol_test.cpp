#include "protocol.hpp"

#include <iostream>

#include <gtest/gtest.h>



TEST(wdb_procol, init)
{
    const char * hi = "buen dia!\n";
    char reply[1024] = {};
    int fd = OS_ConnectUnixDomain("/root/test.sock");
    ASSERT_GT(fd, 0);
    std::cout << hi << std::endl;
    OS_SendSecureTCP(fd, sizeof(hi), hi);
    OS_RecvSecureTCP(fd, reply, 1024);
    //\x09\x00\x00\x00\x68\x6f\x6c\x61\x31\x32\x33\x0a\x00
    std::cout << reply << std::endl;
    close(fd);
}
