/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#include "shared.h"
#include <openssl/ssl.h>
#include "auth.h"
#include "enrollment_op.h"
#include "dll_load_notify.h"

#undef ARGV0
#define ARGV0 "agent-auth"

static void help_agent_auth(char * home_path) __attribute__((noreturn));

/* Print help statement */
static void help_agent_auth(char * home_path)
{
    print_header();
    print_out("  %s: -[Vhdti] [-g group] [-D dir] [-m IP address] [-p port] [-n network-interface] [-A name] [-c ciphers] [-v path] [-x path] [-k path] [-P pass] [-G group] [-I IP address]", ARGV0);
    print_out("    -V                     Version and license message.");
    print_out("    -h                     This help message.");
    print_out("    -d                     Execute in debug mode. This parameter");
    print_out("                           can be specified multiple times");
    print_out("                           to increase the debug level.");
    print_out("    -t                     Test configuration.");
#ifndef WIN32
    print_out("    -g <group>             Group to run as (default: %s).", GROUPGLOBAL);
    print_out("    -D <dir>               Directory to chdir into (default: %s).", home_path);
#endif
    print_out("    -m <addr>              Manager IP address.");
    print_out("    -p <port>              Manager port (default: %d).", DEFAULT_PORT);
    print_out("    -n <network-interface> Network interface to use in an IPv6 connection (only necessary in case of use of link-local address).");
    print_out("    -A <name>              Agent name (default: hostname).");
    print_out("    -c <cipher>            SSL cipher list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>              Full path to CA certificate used to verify the server.");
    print_out("    -x <path>              Full path to agent certificate.");
    print_out("    -k <path>              Full path to agent key.");
    print_out("    -P <pass>              Authorization password.");
    print_out("    -a                     Auto select SSL/TLS method. Default: TLS v1.2 only.");
    print_out("    -G <group>             Assigns the agent to one or more existing groups (separated by commas).");
    print_out("    -I <IP>                Set the agent IP address.");
    print_out("    -i                     Let the agent IP address be set by the manager connection.");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv)
{
#ifdef WIN32
    // This must be always the first instruction
    enable_dll_verification();
#endif

    int c;
    int test_config = 0;
#ifndef WIN32
    gid_t gid = 0;
    const char *group = GROUPGLOBAL;
#endif
    w_enrollment_target *target_cfg = w_enrollment_target_init();
    w_enrollment_cert *cert_cfg = w_enrollment_cert_init();
    char *server_address = NULL;
    uint32_t network_interface = 0;
    bio_err = 0;
    int debug_level = 0;

    /* Set the name */
    OS_SetName(ARGV0);

#ifdef WIN32
    WSADATA wsaData;

    // Move to the directory where this executable lives in
    w_ch_exec_dir();
#else
    // Define current working directory
    char * home_path = w_homedir(argv[0]);
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }
#endif

    while ((c = getopt(argc, argv, "VdhtG:m:p:n:A:c:v:x:k:D:P:aI:i"
#ifndef WIN32
    "g:D:"
#endif
    )) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
#ifndef WIN32
                help_agent_auth(home_path);
#else
                help_agent_auth(NULL);
#endif
                break;
            case 'd':
                debug_level = 1;
                nowDebug();
                break;
#ifndef WIN32
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                mwarn(DEPRECATED_OPTION_WARN, "-D", home_path);
                break;
#endif
            case 't':
                test_config = 1;
                break;
            case 'm':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                server_address = strdup(optarg);
                if (strchr(server_address, ':') != NULL) {
                    os_realloc(server_address, IPSIZE + 1, server_address);
                    OS_ExpandIPv6(server_address, IPSIZE);
                }
                break;
            case 'n':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                int index_numeric = atoi(optarg);
                if (index_numeric <= 0 ) {
                    merror_exit("Invalid network_interface: %s", optarg);
                }
                network_interface = (uint32_t)index_numeric;
                break;
            case 'A':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                target_cfg->agent_name = strdup(optarg);
                break;
            case 'p':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                target_cfg->port = atoi(optarg);
                if (target_cfg->port <= 0 || target_cfg->port >= 65536) {
                    merror_exit("Invalid port: %s", optarg);
                }
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                cert_cfg->ciphers = strdup(optarg);
                break;
            case 'v':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                cert_cfg->ca_cert = strdup(optarg);
                break;
            case 'x':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                cert_cfg->agent_cert = strdup(optarg);
                break;
            case 'k':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                cert_cfg->agent_key = strdup(optarg);
                break;
            case 'P':
                if (!optarg)
                    merror_exit("-%c needs an argument", c);

                cert_cfg->authpass = strdup(optarg);
                break;
            case 'a':
                cert_cfg->auto_method = 1;
                break;
            case 'G':
                if(!optarg){
                    merror_exit("-%c needs an argument",c);
                }
                target_cfg->centralized_group = strdup(optarg);
                break;
            case 'I':
                if(!optarg){
                    merror_exit("-%c needs an argument",c);
                }
                target_cfg->sender_ip = strdup(optarg);
                if (strchr(target_cfg->sender_ip, ':') != NULL) {
                    os_realloc(target_cfg->sender_ip, IPSIZE + 1, target_cfg->sender_ip);
                    OS_ExpandIPv6(target_cfg->sender_ip, IPSIZE);
                }
                break;
            case 'i':
                target_cfg->use_src_ip = 1;
                break;
            default:
#ifndef WIN32
                help_agent_auth(home_path);
#else
                help_agent_auth(NULL);
#endif
                break;
        }
    }

    if (optind < argc) {
        mwarn("Extra arguments detected. They will be ignored.");
    }

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("authd", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

#ifndef WIN32
    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);
#endif

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (target_cfg->sender_ip && target_cfg->use_src_ip) {
        merror("Options '-I' and '-i' are uncompatible.");
        exit(1);
    }

#ifndef WIN32
    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group, strerror(errno), errno);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

#else
    /* Initialize Windows socket stuff */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
        merror_exit("WSAStartup() failed");
    }

#endif /* WIN32 */

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    if (!server_address) {
        merror("Manager IP not set.");
        exit(1);
    }

    // Reading agent's key (if any) to send its hash to the manager
    keystore agent_keys = KEYSTORE_INITIALIZER;
    OS_PassEmptyKeyfile();
    OS_ReadKeys(&agent_keys, W_RAW_KEY, 0);

    w_enrollment_ctx *cfg = w_enrollment_init(target_cfg, cert_cfg, &agent_keys);
    int ret = w_enrollment_request_key(cfg, server_address, network_interface);

    w_enrollment_target_destroy(target_cfg);
    w_enrollment_cert_destroy(cert_cfg);
    w_enrollment_destroy(cfg);
    OS_FreeKeys(&agent_keys);
    os_free(server_address);

    exit((ret == 0) ? 0 : 1);
}
