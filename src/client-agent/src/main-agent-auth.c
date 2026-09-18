/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file main-agent-auth.c
 * @brief Entry point for wazuh-agent-auth. Everything worth testing lives in agent_auth_cli.c;
 *        this resolves the install directory, loads the configuration and hands over.
 */

#include "shared.h"
#include "agentd.h"
#include "agent_auth_cli.h"

#define AGENT_AUTH_NAME "wazuh-agent-auth"

int main(int argc, char **argv) {
    agent_auth_opts_t opts;
    int debug_level = 0;
    char *home_path = NULL;
    int c;
    int result;

    w_agent_auth_opts_init(&opts);

#ifndef WIN32
    /* A write to a closed pipe should fail, not kill the command part-way through an enrollment.
     * agentd installs the same handler through StartSIG(); this command has no signal thread to
     * justify the rest of it. */
    signal(SIGPIPE, SIG_IGN);
#endif

    while ((c = getopt_long(argc, argv, "hdn", agent_auth_long_opts, NULL)) != -1) {
        switch (c) {
            case 'h':
                w_agent_auth_help(stdout, AGENT_AUTH_NAME);
                exit(AGENT_AUTH_OK);

            case 'd':
                debug_level++;
                nowDebug();
                break;

            case '?':
                /* getopt_long() has already said what was wrong. This is also where
                 * `--show-token=<token>` lands: the option is declared no_argument precisely so
                 * that a token can never be read out of argv. */
                fprintf(stderr, "%s: run with --help for usage.\n", AGENT_AUTH_NAME);
                exit(AGENT_AUTH_ERR_USAGE);

            default:
                if (w_agent_auth_parse_opt(&opts, c, optarg, stderr) != 0) {
                    exit(AGENT_AUTH_ERR_USAGE);
                }
                break;
        }
    }

    if (w_agent_auth_reject_operands(argc, argv, optind, stderr) != 0) {
        exit(AGENT_AUTH_ERR_USAGE);
    }

    /* Decoding a token is a pure function of its input, so --show-token is answered without
     * resolving the install directory and without reading any configuration. Both of those
     * abort on an installation that is incomplete or momentarily inconsistent, and an operator
     * inspecting a token by hand should not need a working install. */
    if (opts.action == AGENT_AUTH_ACTION_SHOW) {
        exit(w_agent_auth_run(&opts, stdin, stdout, stderr));
    }

#ifndef WIN32
    /* Windows has no equivalent check here: the installer's ACL on the install directory is what
     * keeps an unprivileged user out, and the command fails on the first write if it is not
     * elevated -- there is no uid to compare against. */
    if (getuid() != 0) {
        fprintf(stderr, "%s: must run as root. It installs the agent's trust anchor, which is "
                "owned by root so that the account the agent runs as cannot replace it.\n",
                AGENT_AUTH_NAME);
        exit(AGENT_AUTH_ERR_USAGE);
    }
#endif

    /* Resolved before the chdir() below, or a relative --token-file would mean two different
     * files: the operator's own path for --show-token, which is answered above while the working
     * directory is still theirs, and INSTALLDIR-relative for everything else. Same argument, two
     * files, is not a distinction anyone would expect to have to know about. */
    if (opts.token_file != NULL) {
#ifdef WIN32
        char *resolved = _fullpath(NULL, opts.token_file, 0);
#else
        char *resolved = realpath(opts.token_file, NULL);
#endif

        if (resolved == NULL) {
            fprintf(stderr, "%s: could not read '%s': %s (%d).\n", AGENT_AUTH_NAME,
                    opts.token_file, strerror(errno), errno);
            exit(AGENT_AUTH_ERR_USAGE);
        }

        opts.token_file = resolved;
    }

#ifdef WIN32
    /* w_homedir() is POSIX-only, and its "strip /bin from the executable's path" rule would be
     * wrong here anyway: a Windows agent keeps its files beside the executable rather than in a
     * bin/ subdirectory. GetModuleFileName() rather than argv[0] because argv[0] is whatever the
     * caller chose to pass. */
    {
        char module_path[OS_MAXSTR + 1] = {'\0'};
        char *sep;

        if (GetModuleFileName(NULL, module_path, OS_MAXSTR) == 0) {
            fprintf(stderr, "%s: could not resolve the installation directory: error %lu.\n",
                    AGENT_AUTH_NAME, GetLastError());
            exit(AGENT_AUTH_ERR_USAGE);
        }

        sep = strrchr(module_path, '\\');

        if (sep != NULL) {
            *sep = '\0';
        } else {
            strncpy(module_path, ".", OS_MAXSTR);
        }

        os_strdup(module_path, home_path);
    }
#else
    home_path = w_homedir(argv[0]);
#endif

    if (chdir(home_path) == -1) {
        fprintf(stderr, "%s: could not change working directory to '%s': %s (%d).\n",
                AGENT_AUTH_NAME, home_path, strerror(errno), errno);
        os_free(home_path);
        exit(AGENT_AUTH_ERR_USAGE);
    }

    /* Everything downstream uses paths relative to the install directory, exactly as agentd
     * does once it has chdir()'d there. */
    os_free(home_path);

    OS_SetName(AGENT_AUTH_NAME);

    /* Both globals, not just agt: ClientConf() writes atc->package_uninstallation too, so
     * allocating only one segfaults it (config.c). agentd's own main() allocates the pair for
     * the same reason. */
    os_calloc(1, sizeof(agent), agt);
#ifndef WIN32
    /* There is no anti-tampering configuration on Windows: config.c does not even define the
     * global there. */
    os_calloc(1, sizeof(anti_tampering), atc);
#endif

    if (ClientConf(WAZUHCONF) < 0) {
        fprintf(stderr, "%s: could not read the configuration at '%s'.\n", AGENT_AUTH_NAME,
                WAZUHCONF);
        exit(AGENT_AUTH_ERR_USAGE);
    }

    if (debug_level == 0) {
        /* Same convention as agentd: the configured internal option raises the level when the
         * command line did not. */
        debug_level = getDefine_Int("agent", "debug", 0, 2);

        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    if (debug_level == 0) {
        /* Quiet the terminal, not the record. The shared enrollment core logs through the
         * agent's own merror/minfo, which echo to stderr while daemon_flag is 0 -- useful in a
         * daemon that has no other voice, noise in a command that prints its own summary. The
         * detail still reaches logs/ossec.log either way. Skipped when -d was asked for, since
         * an operator who wants debug output wants it on screen. */
        nowDaemon();
    }

    result = w_agent_auth_run(&opts, stdin, stdout, stderr);

    exit(result);
}
