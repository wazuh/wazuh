/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file agent_auth_cli.h
 * @brief wazuh-agent-auth: enroll, re-enroll, or move an installed agent with one command,
 *        using an enrollment token.
 *
 * The agent consumes a token exactly once, at its first start, and only when nothing has
 * superseded it (see token_bootstrap.h's latches). That covers a fresh install and nothing
 * else: an agent already deployed, one being re-pointed at another manager, or one whose token
 * expired before it first enrolled has no installer run left to carry a token, and with the
 * token the only registration path there is, no other way in either.
 *
 * Split from main-agent-auth.c for the same reason os_auth's token_cli.c is split from
 * main-server.c: nothing here calls exit(), and every message goes to a caller-supplied
 * FILE *, so the whole surface is drivable from a unit test.
 *
 * The token is read from a file or standard input and never from argv -- it carries a
 * credential, and a process's command line is readable by other local processes -- through
 * /proc on Linux, through the process list on Windows.
 */
#ifndef AGENT_AUTH_CLI_H
#define AGENT_AUTH_CLI_H

#include <stdbool.h>
#include <stdio.h>
#include <getopt.h>

/* Exit codes. 0, 1 and 2 keep the meanings wazuh-agentd --show-token already has, because
 * register_configure_agent.sh branches on them and on 127 for a binary it could not run at all.
 * 3, 4 and 5 exist only for enrolling, where "the pin did not match" and "the manager said 401"
 * want different runbooks. */
#define AGENT_AUTH_OK             0  /* Done */
#define AGENT_AUTH_ERR_USAGE      1  /* Could not run: usage, unreadable token, refused guard, or
                                      * a local failure before anything was sent */
#define AGENT_AUTH_ERR_TOKEN      2  /* The token itself was rejected */
#define AGENT_AUTH_ERR_ANCHOR     3  /* The manager's CA could not be established */
#define AGENT_AUTH_ERR_ENROLL     4  /* The manager refused the enrollment */
#define AGENT_AUTH_ERR_COMMIT     5  /* Enrolled, but it could not be written to disk. The agent
                                      * still belongs to its previous manager. */
#define AGENT_AUTH_ERR_CONFIG     6  /* Enrolled and written, but the configuration still points
                                      * at the previous manager. The opposite remediation to 5,
                                      * which is why it is not the same code. */

typedef enum {
    AGENT_AUTH_ACTION_ENROLL = 0,
    AGENT_AUTH_ACTION_SHOW
} agent_auth_action_t;

typedef enum {
    AGENT_AUTH_SOURCE_STDIN = 0,  /**< Default: the token arrives on standard input */
    AGENT_AUTH_SOURCE_FILE        /**< --token-file <path>. Never deleted, whichever path it is */
} agent_auth_source_t;

typedef struct {
    agent_auth_action_t action;
    agent_auth_source_t source;
    const char *token_file;   /**< --token-file's path; NULL when the token comes from stdin */
    /** Authorises replacing an existing registration. The agent receives a NEW id -- the
     *  manager deletes the colliding entry and inserts a fresh one (w_auth_replace_agent()),
     *  so this is not a renewal of the same identity. */
    bool force_enroll;
    /** Point the agent at its manager without registering again: the trust anchor, and the
     *  configured address when the token names a different one. Never the registration. */
    bool certs_only;
    bool dry_run;             /**< Report what would change; contact nothing, write nothing */
} agent_auth_opts_t;

/** Long options. `--show-token` is deliberately no_argument: that is what makes
 *  `--show-token=<token>` a getopt_long() error rather than a code path that reads a
 *  credential out of argv. */
extern const struct option agent_auth_long_opts[];

/** Sets the defaults every run starts from. */
void w_agent_auth_opts_init(agent_auth_opts_t *opts);

/**
 * @brief Folds one getopt_long() result into @p opts.
 * @return 0 when the option was consumed, -1 when it was rejected (a reason is written to
 *         @p err). Options this module does not own are also rejected, so main() can tell.
 */
int w_agent_auth_parse_opt(agent_auth_opts_t *opts, int c, const char *arg, FILE *err);

/**
 * @brief Runs the requested action.
 *
 * Requires ClientConf() to have run and the process to have chdir()'d into the install
 * directory, because the paths it touches are relative.
 *
 * @return one of the AGENT_AUTH_* codes.
 */
int w_agent_auth_run(const agent_auth_opts_t *opts, FILE *in, FILE *out, FILE *err);

/**
 * @brief Refuses any non-option argument left after getopt_long().
 *
 * Separate from main() so it can be tested: this is where a token typed on the command line
 * lands, and the one thing it must never do is repeat it back.
 *
 * @return 0 when there is nothing left over, -1 when there is (a reason is written to @p err).
 */
int w_agent_auth_reject_operands(int argc, char **argv, int optind, FILE *err);

/** Prints the help text. */
void w_agent_auth_help(FILE *out, const char *progname);

#endif /* AGENT_AUTH_CLI_H */
