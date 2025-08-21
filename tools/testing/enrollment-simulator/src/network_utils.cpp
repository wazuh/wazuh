#include "network_utils.h"
#include "types.h"

#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>

// SocketRAII implementation
SocketRAII::SocketRAII(int domain, int type, int protocol)
    : sock_(socket(domain, type, protocol)) {}

SocketRAII::~SocketRAII() {
    if (sock_ >= 0) {
        close(sock_);
    }
}

// SSLRAII implementation
SSLRAII::SSLRAII(SSL_CTX* ctx) : ssl_(SSL_new(ctx)) {}

SSLRAII::~SSLRAII() {
    if (ssl_) {
        SSL_free(ssl_);
    }
}
