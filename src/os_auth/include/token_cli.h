/*
 * Wazuh authd - enrollment token command line
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef TOKEN_CLI_H
#define TOKEN_CLI_H

#include <getopt.h>
#include <stdio.h>

#include "enrollment_token.h"

/**
 * @brief The enrollment token utility mode of wazuh-manager-authd (issue #38993).
 *
 * `wazuh-manager-authd --create-enrollment-token --address <host> ...`, `--list-enrollment-tokens`,
 * `--revoke-enrollment-token <id>` and `--show-token` are thin clients of the running daemon: they
 * send the `token_*` verbs over auth.sock, so minting is implemented once (authd) whichever door it
 * comes through (CLI, server API). `--show-token` alone works offline: it decodes a token with the
 * shared codec and prints it without its credential.
 *
 * main() keeps a single getopt_long() loop: it hands every option it does not know to
 * w_token_cli_parse_opt() and, once the loop is over, runs w_token_cli_run() and exits with its
 * return value. Nothing here calls exit(); every message goes to the FILE the caller passes, which
 * is what makes the module unit-testable.
 */

/* Longest reply the CLI reads back from authd. OS_MAXSTR (64 KB), what the socket helpers default
 * to, is not enough: a full-store purge answers with every id it removed (~122 KB for the 5000 the
 * store admits) and --list-enrollment-tokens answers with the tokens themselves. What bounds both
 * is the store, so this is its ceiling plus room for the JSON around it. Undersizing it does not
 * truncate the print: OS_RecvSecureTCP() refuses the message whole, and a purge that already
 * happened would be reported as a failure. */
#define TOKEN_CLI_MAX_REPLY (W_ETOKEN_STORE_MAX_BYTES + OS_MAXSTR)

typedef enum {
    TOKEN_CLI_NONE = 0,
    TOKEN_CLI_CREATE,
    TOKEN_CLI_LIST,
    TOKEN_CLI_REVOKE,
    TOKEN_CLI_PURGE,
    TOKEN_CLI_SHOW
} token_cli_action_t;

typedef struct {
    int requested;                 /**< Any token option was given: run the utility mode */
    token_cli_action_t action;
    /* --create-enrollment-token */
    const char *address;           /**< Mandatory for create */
    long port;                     /**< 0: the listener's configured port */
    const char *prefix;            /**< NULL: the listener's configured prefix */
    long ttl;                      /**< Seconds; 0: authd's default (30 days) */
    long max_uses;                 /**< 0: unlimited */
    const char *description;
    int embed_ca;
    int no_credential;
    /* --revoke-enrollment-token */
    const char *revoke_id;
    /* --purge-enrollment-tokens */
    int purge_all;                 /**< --all: empty the store instead of dropping the unusable tokens */
    int force;                     /**< --force: do not ask for confirmation on a terminal */
    /* --show-token */
    const char *token_text;        /**< --show-token=<token> */
    const char *token_file;        /**< --token-file <path>; when neither is given, stdin */
} token_cli_opts_t;

/** The long options main() appends to its getopt_long() table. Ids start at 256. */
extern const struct option token_cli_long_opts[];

/**
 * @brief Consume one option returned by getopt_long().
 *
 * @param opts Accumulated options.
 * @param c The value getopt_long() returned.
 * @param arg optarg (may be NULL).
 * @param err Where to report a bad value.
 * @return 1 when the option belongs to this module and was consumed, 0 when it is not one of ours,
 *         -1 when it is ours but invalid (already reported to @p err).
 */
int w_token_cli_parse_opt(token_cli_opts_t *opts, int c, const char *arg, FILE *err);

/**
 * @brief Run the requested action.
 *
 * @param opts Parsed options (opts->requested must be set).
 * @param in Where --show-token reads the token from when no text or file was given.
 * @param out The token (create), the table (list), the confirmation (revoke) or the description (show).
 * @param err Diagnostics and the create metadata (id, endpoint, expiry, pin, credential).
 * @return 0 on success, 1 on any failure (usage, connection, or an error answered by authd).
 */
int w_token_cli_run(const token_cli_opts_t *opts, FILE *in, FILE *out, FILE *err);

#endif /* TOKEN_CLI_H */
