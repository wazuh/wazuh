/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* agent daemon */

#include "shared.h"
#include "agentd.h"
#include "enrollment_token.h"
#include <getopt.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#ifndef ARGV0
#define ARGV0 "wazuh-agentd"
#endif

/* Largest enrollment token accepted on stdin. A token that carries a pin is a couple of
 * hundred bytes and one that embeds a CA certificate a few KB, so this is a sanity bound
 * rather than a tight one. */
#define ETOKEN_MAX_TEXT 65536

/* --show-token's exit status when the token itself was rejected. Distinct from every other
 * failure so a caller can tell a bad token from a decoder it never managed to run: a missing
 * binary exits 127, and so does one whose shared libraries cannot be resolved. Reporting the
 * second as "invalid token" sends an operator looking in the wrong place. */
#define ETOKEN_SHOW_REJECTED 2

/* Prototypes */
static void help_agentd(char *home_path) __attribute((noreturn));
static int show_enrollment_token(void);


/* Print help statement */
static void help_agentd(char *home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", WAZUHCONF);
    print_out("    --show-token  Decode the enrollment token on stdin and print what it");
    print_out("                  carries, without its credential.");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

/* Decode an enrollment token and print what it carries, for the package installer to read
 * the address out of and for an operator to inspect one by hand.
 *
 * Read from stdin, never from an argument: a token carries the credential secret, and argv
 * is world-readable through /proc. w_etoken_describe() renders the token without its
 * identifier or secret, so the output is safe to print, log and parse.
 *
 * Decodes with the same w_etoken_decode() the agent itself uses at first boot, so a token
 * this accepts is a token the bootstrap will accept, and a malformed one is reported while
 * the operator is still watching the install rather than at the first start.
 *
 * Returns 0 on success, ETOKEN_SHOW_REJECTED when the token is bad, and 1 when it could not
 * be read at all.
 */
static int show_enrollment_token(void)
{
    char text[ETOKEN_MAX_TEXT + 1] = {'\0'};
    size_t length = fread(text, 1, sizeof(text) - 1, stdin);
    w_etoken_t token;
    w_etoken_error_t error;
    char *description = NULL;

    if (ferror(stdin)) {
        fprintf(stderr, "%s: could not read the enrollment token from stdin.\n", ARGV0);
        return 1;
    }

    if (length == sizeof(text) - 1) {
        fprintf(stderr, "%s: the enrollment token does not fit in %d bytes.\n", ARGV0, ETOKEN_MAX_TEXT);
        return 1;
    }

    /* Piping the token in from a shell appends a newline, which the decoder would read as
     * one more base64url character and reject the whole token over. */
    while (length > 0 && (text[length - 1] == '\n' || text[length - 1] == '\r' ||
                          text[length - 1] == ' ' || text[length - 1] == '\t')) {
        text[--length] = '\0';
    }

    if ((error = w_etoken_decode(text, &token)) != ETOKEN_OK) {
        fprintf(stderr, "%s: invalid enrollment token: %s.\n", ARGV0, w_etoken_strerror(error));
        return ETOKEN_SHOW_REJECTED;
    }

    description = w_etoken_describe(&token);
    w_etoken_free(&token);

    if (description == NULL) {
        fprintf(stderr, "%s: could not render the enrollment token.\n", ARGV0);
        return 1;
    }

    printf("%s", description);
    os_free(description);

    return 0;
}

int main(int argc, char **argv)
{
    /* Decoding a token is a pure function of stdin, so it is answered before the home
     * directory is resolved and before getDefine_Int() reads any configuration. Both of those
     * abort on an installation that is incomplete or momentarily inconsistent, which is
     * exactly the state the package installer calls this from -- it is still rewriting
     * ossec.conf at that point -- and an operator inspecting a token by hand should not need
     * a working install either. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--show-token") == 0) {
            exit(show_enrollment_token());
        }
    }

    int c = 0;
    int test_config = 0;
    int debug_level = 0;
    char *home_path = w_homedir(argv[0]);

    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = WAZUHCONF;
    const char *uninstall_auth_login = NULL;
    const char *uninstall_auth_token = NULL;
    const char *uninstall_auth_host = NULL;
    bool ssl_verify = true;

    uid_t uid;
    gid_t gid;

    run_foreground = 0;

#if defined(__GLIBC__)
    /* Cap the number of malloc arenas.
     *
     * The HTTPS transport runs several allocating threads, and glibc answers
     * that by giving each one its own 64 MiB arena. Those arenas are reserved
     * rather than committed, so most of the cost is address space, and it is
     * what takes this process past 690 MB of virtual size. But each arena also
     * carries its own top chunk and bins, which is real resident memory that is
     * never handed back. Capping the count trades a little allocator contention
     * for that overhead.
     *
     * Set here, before any thread is created: extra arenas are only spawned when
     * a thread finds every existing one locked, so the limit has to be in place
     * before the transport's threads start. Allocations already made on this
     * thread came from the main arena and are unaffected.
     *
     * Skipped when an operator has already chosen a limit. glibc applies
     * MALLOC_ARENA_MAX and the glibc.malloc.arena_max tunable at process start,
     * and mallopt() overrides either of them silently: with MALLOC_ARENA_MAX=1
     * in the environment, an unconditional mallopt(2) leaves the process running
     * two arenas. Honouring the environment keeps the knob usable for tuning and
     * for diagnosing allocator behaviour in the field.
     *
     * The return value is checked rather than discarded, since an unchecked
     * mallopt() is the pattern Coverity reports. Failing startup over an
     * allocator hint would be wrong, so a debug line is the right level. */
    const char *tunables = getenv("GLIBC_TUNABLES");

    if (getenv("MALLOC_ARENA_MAX") == NULL &&
        (tunables == NULL || strstr(tunables, "glibc.malloc.arena_max") == NULL)) {
        if (mallopt(M_ARENA_MAX, 2) != 1) {
            mdebug1("Could not cap the malloc arena count; using the allocator default.");
        }
    }
#endif

    /* Set the name */
    OS_SetName(ARGV0);

	/* Change working directory */
    if (chdir(home_path) == -1) {
        merror(CHDIR_ERROR, home_path, errno, strerror(errno));
        os_free(home_path);
        exit(1);
    }

    agent_debug_level = getDefine_Int("agent", "debug", 0, 2);

    struct option long_opts[] = {
        {"uninstall-auth-login", required_argument, NULL, 1},
        {"uninstall-auth-token", required_argument, NULL, 2},
        {"uninstall-auth-host", required_argument, NULL, 3},
        {"uninstall-ssl-verify", optional_argument, NULL, 4},
        {NULL, no_argument, NULL, 0}
    };

    while ((c = getopt_long(argc, argv, "Vtdfhu:g:c:", long_opts, NULL)) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agentd(home_path);
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    merror_exit("-u needs an argument");
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument.");
                }
                cfg = optarg;
                break;
            case 1:
                if (!optarg) {
                    merror_exit("--uninstall-auth-login needs an argument");
                }
                uninstall_auth_login = optarg;
                break;
            case 2:
                if (!optarg) {
                    merror_exit("--uninstall-auth-token needs an argument");
                }
                uninstall_auth_token = optarg;
                break;
            case 3:
                if (!optarg) {
                    merror_exit("--uninstall-auth-host needs an argument");
                }
                uninstall_auth_host = optarg;
                break;
            case 4:
                if (!optarg || strcmp(optarg, "") == 0 || strcmp(optarg, "true") == 0 || strcmp(optarg, "TRUE") == 0 || strcmp(optarg, "1") == 0) {
                    ssl_verify = true;
                } else if (strcmp(optarg, "false") == 0 || strcmp(optarg, "FALSE") == 0 || strcmp(optarg, "0") == 0) {
                    ssl_verify = false;
                } else {
                    merror_exit("--uninstall-ssl-verify accepts 'true'/'false' or '1'/'0' as arguments");
                }
                break;
            default:
                help_agentd(home_path);
                break;
        }
    }

    /* Anti tampering functionality */
    if ((uninstall_auth_token || uninstall_auth_login) && uninstall_auth_host) {
        exit(package_uninstall_validation(uninstall_auth_token, uninstall_auth_login, uninstall_auth_host, ssl_verify));
    }

    agt = (agent *)calloc(1, sizeof(agent));
    if (!agt) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    atc = (anti_tampering *)calloc(1, sizeof(anti_tampering));
    if (!atc) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        /* Get debug level */
        debug_level = agent_debug_level;
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);
    mdebug1(STARTUP_MSG, (int)getpid());

    /* Read config */
    if (ClientConf(cfg) < 0) {
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!(agt->server && agt->server[0].rip)) {
        merror(AG_INV_IP);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_Address(agt->server)){
        merror(AG_INV_MNGIP, agt->server[0].rip);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_IPv6_Link_Local_Interface(agt->server)){
        merror(AG_INV_INT);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    /* Checked here, before daemonizing, so wazuh-client.sh's sequential daemon-start check
     * (which polls for this process's PID file before starting syscheckd/logcollector/modulesd)
     * halts the whole start instead of launching the other daemons around a transport that will
     * never come up. */
    if (!w_agent_validate_ssl_ca(agt)) {
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (agt->notify_time == 0) {
        agt->notify_time = NOTIFY_TIME;
    }
    if (agt->max_time_reconnect_try == 0 ) {
        agt->max_time_reconnect_try = RECONNECT_TIME;
    }
    if (agt->max_time_reconnect_try <= agt->notify_time) {
        agt->max_time_reconnect_try = (agt->notify_time * 3);
        mdebug1("Max time to reconnect can't be less than notify_time(%d), using notify_time*3 (%d)", agt->notify_time, agt->max_time_reconnect_try);
    }

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Exit if test config */
    if (test_config) {
        exit(0);
    }

    /* Start the signal manipulation */
    StartSIG(ARGV0);

    /* Agentd Start */
    AgentdStart(uid, gid, user, group);

    return (0);
}
