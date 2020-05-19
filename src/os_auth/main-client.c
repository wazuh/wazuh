/* Copyright (C) 2015-2020, Wazuh Inc.
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

#undef ARGV0
#define ARGV0 "agent-auth"

static void help_agent_auth(void) __attribute__((noreturn));

/* Print help statement */
static void help_agent_auth()
{
    print_header();
    print_out("  %s: -[Vhdti] [-g group] [-D dir] [-m IP address] [-p port] [-A name] [-c ciphers] [-v path] [-x path] [-k path] [-P pass] [-G group] [-I IP address]", ARGV0);
    print_out("    -V          Version and license message.");
    print_out("    -h          This help message.");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration.");
#ifndef WIN32
    print_out("    -g <group>  Group to run as (default: %s).", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s).", DEFAULTDIR);
#endif
    print_out("    -m <addr>   Manager IP address.");
    print_out("    -p <port>   Manager port (default: %d).", DEFAULT_PORT);
    print_out("    -A <name>   Agent name (default: hostname).");
    print_out("    -c <cipher> SSL cipher list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>   Full path to CA certificate used to verify the server.");
    print_out("    -x <path>   Full path to agent certificate.");
    print_out("    -k <path>   Full path to agent key.");
    print_out("    -P <pass>   Authorization password.");
    print_out("    -a          Auto select SSL/TLS method. Default: TLS v1.2 only.");
    print_out("    -G <group>  Assigns the agent to one or more existing groups (separated by commas).");
    print_out("    -I <IP>     Set the agent IP address.");
    print_out("    -i          Let the agent IP address be set by the manager connection.");
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c;
    int test_config = 0;
#ifndef WIN32
    gid_t gid = 0;
    const char *group = GROUPGLOBAL;
#endif
    w_enrollment_target *target_cfg = w_enrollment_target_init();
    w_enrollment_cert *cert_cfg = w_enrollment_cert_init();
    char *server_address = NULL;
    bio_err = 0;
    int debug_level = 0;

#ifdef WIN32
    WSADATA wsaData;

    // Move to the directory where this executable lives in
    w_ch_exec_dir();
#endif

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "VdhtG:m:p:A:c:v:x:k:D:P:aI:i"
#ifndef WIN32
    "g:D:"
#endif
    )) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agent_auth();
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
                    merror_exit("-g needs an argument");
                }
                mwarn(DEPRECATED_OPTION_WARN,"-D");
                break;
#endif
            case 't':
                test_config = 1;
                break;
            case 'm':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                server_address = optarg;
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
                break;
            case 'i':
                target_cfg->use_src_ip = 1;
                break;
            default:
                help_agent_auth();
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

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (target_cfg->sender_ip && target_cfg->use_src_ip) {
        merror("Options '-I' and '-i' are uncompatible.");
        exit(1);
    }

    /* Start daemon */
    mdebug1(STARTED_MSG);

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

    w_enrollment_ctx *cfg = w_enrollment_init(target_cfg, cert_cfg);
    int ret = w_enrollment_request_key(cfg, server_address); 
    
    w_enrollment_target_destroy(target_cfg);
    w_enrollment_cert_destroy(cert_cfg);
    w_enrollment_destroy(cfg);
    
    exit((ret == 0) ? 0 : 1);
}
