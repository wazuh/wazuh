#ifndef SHARED_OS_IP_H
#define SHARED_OS_IP_H

#define w_free_os_ip(x)                                                                                                \
    if (x) {                                                                                                           \
        if (x->is_ipv6) {                                                                                              \
            os_free(x->ipv6)                                                                                           \
        } else {                                                                                                       \
            os_free(x->ipv4)                                                                                           \
        };                                                                                                             \
        os_free(x->ip);                                                                                                \
        os_free(x)                                                                                                     \
    }

/* IPv4 structure */
typedef struct _os_ipv4 {
    unsigned int ip_address;
    unsigned int netmask;
} os_ipv4;

/* IPv6 structure */
typedef struct _os_ipv6 {
    uint8_t ip_address[16];
    uint8_t netmask[16];
} os_ipv6;

/* IP structure */
typedef struct _os_ip {
    char * ip;
    union {
        os_ipv4 * ipv4;
        os_ipv6 * ipv6;
    };
    bool is_ipv6;
} os_ip;

#endif /* SHARED_OS_IP_H */
