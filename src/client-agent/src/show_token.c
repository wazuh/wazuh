/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* --show-token, shared by every agent entry point that answers it. POSIX main(), the Windows
 * agent and wazuh-agent-auth have separate main()s in separate files, and this has to answer
 * identically from all of them: the installers parse its output, and two of them accepting
 * different tokens is exactly the drift the single shared codec exists to prevent.
 *
 * Streams are parameters rather than stdin/stdout because wazuh-agent-auth also reads a token
 * from --token-file, and because a function that writes to fixed streams cannot be asserted on
 * from a unit test. w_agent_show_enrollment_token() is the stdin form the two agent entry points
 * use. */

#include "shared.h"
#include "agentd.h"
#include "enrollment_token.h"
#include "token_bootstrap.h"

#ifndef ARGV0
#define ARGV0 "wazuh-agentd"
#endif

/* --show-token's exit status when the token itself was rejected. Distinct from every other
 * failure so a caller can tell a bad token from a decoder it never managed to run: a missing
 * binary exits 127, and so does one whose shared libraries cannot be resolved. Reporting the
 * second as "invalid token" sends an operator looking in the wrong place. */
#define ETOKEN_SHOW_REJECTED 2

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
int w_agent_show_token(FILE *in, FILE *out, FILE *err, const char *progname)
{
    /* Heap, not stack: since #39321 this bound is sized for an embedded-CA token (see
     * W_ETOKEN_MAX_FILE_BYTES) and 96 KB is far too much to put on a frame. */
    char *text;
    w_etoken_t token;
    w_etoken_error_t error;
    char *description = NULL;
    size_t length;

    /* A terminal will never produce a token, so blocking on it reads as a hang. */
    if (isatty(fileno(in))) {
        fprintf(err, "%s: no token given. Redirect one in, or pipe it:\n", progname);
        fprintf(err, "      %s --show-token < /path/to/token\n", progname);
        return 1;
    }

    os_calloc(W_ETOKEN_MAX_FILE_BYTES + 1, sizeof(char), text);
    length = fread(text, 1, W_ETOKEN_MAX_FILE_BYTES, in);

    if (ferror(in)) {
        fprintf(err, "%s: could not read the enrollment token.\n", progname);
        os_free(text);
        return 1;
    }

    if (length == W_ETOKEN_MAX_FILE_BYTES) {
        fprintf(err, "%s: the enrollment token does not fit in %d bytes.\n", progname, W_ETOKEN_MAX_FILE_BYTES);
        os_free(text);
        return 1;
    }

    /* Piping the token in from a shell appends a newline, which the decoder would read as
     * one more base64url character and reject the whole token over. */
    while (length > 0 && (text[length - 1] == '\n' || text[length - 1] == '\r' ||
                          text[length - 1] == ' ' || text[length - 1] == '\t')) {
        text[--length] = '\0';
    }

    error = w_etoken_decode(text, &token);
    os_free(text);

    if (error != ETOKEN_OK) {
        fprintf(err, "%s: invalid enrollment token: %s.\n", progname, w_etoken_strerror(error));
        return ETOKEN_SHOW_REJECTED;
    }

    description = w_etoken_describe(&token);
    w_etoken_free(&token);

    if (description == NULL) {
        fprintf(err, "%s: could not render the enrollment token.\n", progname);
        return 1;
    }

    fputs(description, out);
    os_free(description);

    return 0;
}

int w_agent_show_enrollment_token(void)
{
    return w_agent_show_token(stdin, stdout, stderr, ARGV0);
}
