/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#include "shared.h"
#include "rootcheck.h"

#if defined(sun) || defined(__sun__)
#define NETSTAT         "netstat -an -P %s | "\
                        "grep \"[^0-9]%d \" > /dev/null 2>&1"
#else
#define NETSTAT         "netstat -an | grep \"^%s\" | " \
                        "grep \"[^0-9]%d \" > /dev/null 2>&1"
#endif

#ifdef __linux__
/* iproute2 counterpart of netstat. No -H: older ss releases reject it. Only
 * the local address column (4th) is matched, so neither the header, the
 * Send-Q backlog nor a peer port can hide a local port. A failing ss makes
 * the pipeline exit 2 instead of reporting the port as missing, and so does
 * a listing with no sockets: it only runs for a port bind() found in use.
 */
#define SS              "{ ss -an --%s 2> /dev/null || echo FAIL; } | " \
                        "awk '/^FAIL$/ {e = 1} $4 ~ /:%d$/ {f = 1} " \
                        "END {exit (e || NR < 2) ? 2 : !f}' > /dev/null 2>&1"
#define SS_PROBE        "ss -an --tcp > /dev/null 2>&1 && " \
                        "ss -an --udp > /dev/null 2>&1 && " \
                        "awk 'BEGIN {exit 0}' > /dev/null 2>&1"
#define PORT_TOOLS      "ss or netstat"
#else
#define PORT_TOOLS      "netstat"
#endif

/* Tools used by the current scan. ss reads netlink and netstat reads /proc,
 * so with both a port must be listed by each to count as visible.
 */
static bool use_ss;
static bool use_netstat;

/* Listings that failed during the current scan */
static int listing_errors;

/* Prototypes */
static int  run_port_cmd(const char *cmd);
static int  run_netstat(int proto, int port);
static int  conn_port(int proto, int port);
static void test_ports(int proto, int *_errors, int *_total);


/* Returns 0 when the command exits 1: the port is not in the listing */
static int run_port_cmd(const char *cmd)
{
    int ret = system(cmd);

    if (ret == 0) {
        return (1);
    } else if (WEXITSTATUS(ret) == 1) {
        return (0);
    }

    listing_errors++;
    return (1);
}

static int run_netstat(int proto, int port)
{
    char nt[OS_SIZE_1024 + 1];
    const char *proto_name;

    if (proto == IPPROTO_TCP) {
        proto_name = "tcp";
    } else if (proto == IPPROTO_UDP) {
        proto_name = "udp";
    } else {
        mterror(ARGV0, "Netstat error (wrong protocol)");
        return (0);
    }

#ifdef __linux__
    if (use_ss) {
        snprintf(nt, OS_SIZE_1024, SS, proto_name, port);
        if (!run_port_cmd(nt)) {
            return (0);
        }
    }
#endif

    if (use_netstat) {
        snprintf(nt, OS_SIZE_1024, NETSTAT, proto_name, port);
        if (!run_port_cmd(nt)) {
            return (0);
        }
    }

    return (1);
}

static int conn_port(int proto, int port)
{
    int rc = 0;
    int ossock;
    struct sockaddr_in server;

    if (proto == IPPROTO_UDP) {
        if ((ossock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            return (0);
        }
    } else if (proto == IPPROTO_TCP) {
        if ((ossock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            return (0);
        }
    } else {
        return (0);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    /* If we can't bind, it means the port is open */
    if (bind(ossock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        rc = 1;
    }

    /* Setting if port is open or closed */
    if (proto == IPPROTO_TCP) {
        total_ports_tcp[port] = (char) rc;
    } else {
        total_ports_udp[port] = (char) rc;
    }

    close(ossock);
    return (rc);
}

static void test_ports(int proto, int *_errors, int *_total)
{
    int i;

    for (i = 0; i <= 65535; i++) {
        (*_total)++;
        if (conn_port(proto, i)) {
            /* Check if we can find it using netstat. If not,
             * check again to see if the port is still being used.
             */
            if (run_netstat(proto, i)) {
                continue;
            }

#ifdef OSSECHIDS
            /* If we are in the context of OSSEC-HIDS, sleep here (no rush) */
#ifdef WIN32
        Sleep(rootcheck.tsleep);
#else
        struct timeval timeout = {0, rootcheck.tsleep * 1000};
        select(0, NULL, NULL, NULL, &timeout);
#endif
#endif

            if (!run_netstat(proto, i) && conn_port(proto, i)) {
                char op_msg[OS_SIZE_1024 + 1];

                (*_errors)++;

                snprintf(op_msg, OS_SIZE_1024, "Port '%d'(%s) hidden. "
                         "Kernel-level rootkit or trojaned "
                         "version of netstat.", i,
                         (proto == IPPROTO_UDP) ? "udp" : "tcp");

                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
        }

        if ((*_errors) > 20) {
            char op_msg[OS_SIZE_1024 + 1];

            snprintf(op_msg, OS_SIZE_1024, "Excessive number of '%s' ports "
                     "hidden. It maybe a false-positive or "
                     "something really bad is going on.",
                     (proto == IPPROTO_UDP) ? "udp" : "tcp" );
            notify_rk(ALERT_SYSTEM_CRIT, op_msg);
            return;
        }
    }

}

void check_rc_ports()
{
    int _errors = 0;
    int _total = 0;

    int i = 0;

    use_ss = false;
#ifdef __linux__
    if (is_program_available("ss")) {
        /* A broken ss would report every bound port as hidden */
        if (system(SS_PROBE) == 0) {
            use_ss = true;
        } else {
            mtwarn(ARGV0, "ss or awk failed to run. Not using ss for the port check.");
        }
    }
#endif
    use_netstat = is_program_available("netstat");

    if (!use_ss && !use_netstat) {
        minfo(PORT_TOOLS " not available. Skipping port check.");
        notify_rk(ALERT_SYSTEM_ERR, PORT_TOOLS " not available. "
                 "Skipping port check.");
        return;
    }

    mtdebug1(ARGV0, "Using %s for the port check.",
             use_ss ? (use_netstat ? "ss and netstat" : "ss") : "netstat");

    listing_errors = 0;

    while (i <= 65535) {
        total_ports_tcp[i] = 0;
        total_ports_udp[i] = 0;
        i++;
    }

    /* Test both TCP and UDP ports */
    test_ports(IPPROTO_TCP, &_errors, &_total);
    test_ports(IPPROTO_UDP, &_errors, &_total);

    if (listing_errors > 0) {
        mtwarn(ARGV0, "%d port listing commands failed during the port check.",
               listing_errors);
    }

    if (_errors == 0) {
        char op_msg[OS_SIZE_1024 + 1];

        snprintf(op_msg, OS_SIZE_1024, "No kernel-level rootkit hiding any port."
                 "\n      Netstat is acting correctly."
                 " Analyzed %d ports.", _total);
        notify_rk(ALERT_OK, op_msg);
    }

    return;
}

#else /* WIN32 */

/* Not implemented on Windows */
void check_rc_ports()
{
    return;
}

#endif /* WIN32 */
