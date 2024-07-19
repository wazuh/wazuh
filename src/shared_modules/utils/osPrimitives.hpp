/*
 * Wazuh - OS primitives
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OS_PRIMITIVES_HPP
#define _OS_PRIMITIVES_HPP

#include <cstdio>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

class OSPrimitives
{

protected:
    OSPrimitives() = default;
    virtual ~OSPrimitives() = default;

    inline int close(int fd)
    {
        return ::close(fd);
    }

    inline int socket(int domain, int type, int protocol)
    {
        return ::socket(domain, type, protocol);
    }

    inline int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
    {
        return ::bind(sockfd, addr, addrlen);
    }

    inline int listen(int sockfd, int backlog)
    {
        return ::listen(sockfd, backlog);
    }

    inline int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
    {
        return ::accept(sockfd, addr, addrlen);
    }

    inline int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
    {
        return ::connect(sockfd, addr, addrlen);
    }

    inline int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
    {
        return ::setsockopt(sockfd, level, optname, optval, optlen);
    }

    inline ssize_t send(int sockfd, const void* buf, size_t len, int flags)
    {
        return ::send(sockfd, buf, len, flags);
    }

    inline ssize_t recv(int sockfd, void* buf, size_t len, int flags)
    {
        return ::recv(sockfd, buf, len, flags);
    }

    inline int shutdown(int sockfd, int how)
    {
        return ::shutdown(sockfd, how);
    }

    inline int fcntl(int fd, int cmd, int arg)
    {
        return ::fcntl(fd, cmd, arg);
    }

    inline int fchmod(int fd, mode_t mode)
    {
        return ::fchmod(fd, mode);
    }

    inline int chmod(const char* path, mode_t mode)
    {
        return ::chmod(path, mode);
    }

    inline FILE* fopen(const char* filename, const char* mode)
    {
        return ::fopen(filename, mode);
    }

    inline int fclose(FILE* stream)
    {
        return ::fclose(stream);
    }

    inline int gethostname(char* name, size_t len)
    {
        return ::gethostname(name, len);
    }
};

#endif // _OS_PRIMITIVES_HPP
