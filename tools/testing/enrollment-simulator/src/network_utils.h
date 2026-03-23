#pragma once

#include <openssl/ssl.h>

// RAII wrapper for sockets
class SocketRAII {
private:
    int sock_;
public:
    explicit SocketRAII(int domain, int type, int protocol);
    ~SocketRAII();

    int get() const { return sock_; }
    bool valid() const { return sock_ >= 0; }

    // Non-copyable
    SocketRAII(const SocketRAII&) = delete;
    SocketRAII& operator=(const SocketRAII&) = delete;
};

// RAII wrapper for SSL connections
class SSLRAII {
private:
    SSL* ssl_;
public:
    explicit SSLRAII(SSL_CTX* ctx);
    ~SSLRAII();

    SSL* get() const { return ssl_; }
    bool valid() const { return ssl_ != nullptr; }

    // Non-copyable
    SSLRAII(const SSLRAII&) = delete;
    SSLRAII& operator=(const SSLRAII&) = delete;
};
