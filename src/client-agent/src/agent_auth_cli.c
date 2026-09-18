/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "agent_auth_cli.h"
#include "token_bootstrap.h"
#include "enrollment_token.h"
#include "os_xml.h"

#ifdef WIN32
#include "os_win.h"
#endif
#include <openssl/crypto.h>

#ifdef WAZUH_UNIT_TESTING
    // Remove static qualifier when unit testing
    #define STATIC
#else
    #define STATIC static
#endif

/* Never ARGV0: that macro is set per-directory to "wazuh-agentd" (client-agent/CMakeLists.txt),
 * and the objects this links against were compiled with it. Overriding it for this target would
 * either redefine the macro on the command line or change what agentd's own objects were built
 * with, so this binary carries its own name instead. */
#define AGENT_AUTH_NAME "wazuh-agent-auth"

/* The example path in the help and in the "no token given" hint. A POSIX path printed on Windows
 * is not something an operator can copy. */
#ifdef WIN32
#define AGENT_AUTH_EXAMPLE_TOKEN "C:\\tok.txt"
#else
#define AGENT_AUTH_EXAMPLE_TOKEN "/root/tok"
#endif

enum {
    OPT_SHOW_TOKEN = 256,
    OPT_TOKEN_FILE,
    OPT_FORCE_ENROLL,
    OPT_CERTS_ONLY
};

const struct option agent_auth_long_opts[] = {
    {"show-token",   no_argument,       NULL, OPT_SHOW_TOKEN},
    {"token-file",   required_argument, NULL, OPT_TOKEN_FILE},
    {"force-enroll", no_argument,       NULL, OPT_FORCE_ENROLL},
    {"certs-only",   no_argument,       NULL, OPT_CERTS_ONLY},
    {"dry-run",      no_argument,       NULL, 'n'},
    {"help",         no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
};

void w_agent_auth_opts_init(agent_auth_opts_t *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->action = AGENT_AUTH_ACTION_ENROLL;
    opts->source = AGENT_AUTH_SOURCE_STDIN;
}

void w_agent_auth_help(FILE *out, const char *progname) {
    fprintf(out,
        "\n"
        "%s: enroll, re-enroll or move an installed agent with a token.\n"
        "\n"
        "  %s --token-file %s                 enroll\n"
        "  %s --token-file %s --force-enroll  re-register, new id\n"
        "  %s --token-file %s --certs-only    refresh CA + address\n"
        "  %s --show-token < %s               decode a token\n"
        "\n"
        "  The token is read from --token-file or standard input, never from the\n"
        "  command line: a command line is readable by other processes and lands in\n"
        "  shell history. The file is never modified or deleted, whichever it is.\n"
        "\n"
        "  Actions\n"
        "    --show-token     Decode the token and print what it carries. Nothing\n"
        "                     is written.\n"
        "    --certs-only     Point this agent at its manager without registering\n"
        "                     again: installs the trust anchor, and the configured\n"
        "                     address when the token names a different one. For a\n"
        "                     manager that rotated its CA or changed its name. The\n"
        "                     registration is left alone -- enrolling again would\n"
        "                     mint a new id.\n"
        "    -h, --help       This message.\n"
        "\n"
        "  Options\n"
        "    --force-enroll   Required when this agent already has a key. It is\n"
        "                     registered again and receives a NEW id.\n"
        "    --token-file <path>\n"
        "                     Read the token from <path> ('-' for standard input).\n"
        "    -n, --dry-run    Report what would change. Contacts nothing, writes\n"
        "                     nothing.\n"
        "    -d               Debug output (repeatable).\n"
        "\n"
        "  Refuses while wazuh-agentd is running: stop it first, and start it after.\n"
        "  A restart is needed either way -- the agent loads its identity once, at\n"
        "  startup.\n"
        "\n"
        "  The agent name, groups and address come from <enrollment> in %s,\n"
        "  so a later re-enrollment by the agent itself registers the same way.\n"
        "\n"
        "  Exit codes: 0 done  1 could not run  2 token rejected  3 CA not established\n"
        "              4 enrollment refused  5 not committed  6 config not updated\n"
        "\n",
        progname, progname, AGENT_AUTH_EXAMPLE_TOKEN, progname, AGENT_AUTH_EXAMPLE_TOKEN,
        progname, AGENT_AUTH_EXAMPLE_TOKEN, progname, AGENT_AUTH_EXAMPLE_TOKEN, WAZUHCONF);
}

int w_agent_auth_parse_opt(agent_auth_opts_t *opts, int c, const char *arg, FILE *err) {
    switch (c) {
        case OPT_SHOW_TOKEN:
            opts->action = AGENT_AUTH_ACTION_SHOW;
            return 0;

        case OPT_TOKEN_FILE:
            if (opts->source != AGENT_AUTH_SOURCE_STDIN) {
                fprintf(err, "%s: give only one token source.\n", AGENT_AUTH_NAME);
                return -1;
            }
            /* '-' is the conventional spelling for "standard input" and costs nothing to
             * honour; it keeps --token-file usable in a pipeline. */
            if (arg != NULL && strcmp(arg, "-") != 0) {
                opts->source = AGENT_AUTH_SOURCE_FILE;
                opts->token_file = arg;
            }
            return 0;

        case OPT_FORCE_ENROLL:
            opts->force_enroll = true;
            return 0;

        case OPT_CERTS_ONLY:
            opts->certs_only = true;
            return 0;

        case 'n':
            opts->dry_run = true;
            return 0;

        default:
            return -1;
    }
}

int w_agent_auth_reject_operands(int argc, char **argv, int optind, FILE *err) {
    (void)argv;

    if (optind >= argc) {
        return 0;
    }

    /* The value is deliberately NOT echoed. This is the path a token typed as an operand lands
     * on, and naming it would put the credential in stderr, in the terminal's scrollback and in
     * whatever captures them -- the exposure the command exists to avoid, reintroduced by its own
     * error message. Nothing here can tell a stray word from a token, so neither is printed. */
    fprintf(err, "%s: unexpected argument. The token is never passed on the command line --\n",
            AGENT_AUTH_NAME);
    fprintf(err, "  use --token-file or standard input.\n");

    return -1;
}

/** Wipes a heap-allocated token before releasing it, then frees it. NULL-safe. */
STATIC void w_agent_auth_forget(char *secret) {
    if (secret == NULL) {
        return;
    }

    OPENSSL_cleanse(secret, strlen(secret));
    os_free(secret);
}

#ifdef WIN32
/**
 * @brief Non-zero when the agent service is running.
 *
 * Windows has no pid files: the service control manager is the authority, and
 * CheckServiceRunning() already asks it the same question wazuh-control does. It reports no pid,
 * so the caller prints the service name instead -- which is what an operator needs to stop it
 * anyway.
 */
STATIC pid_t w_agent_auth_agentd_pid(void) {
    return CheckServiceRunning() ? 1 : 0;
}
#else
/**
 * @brief The pid of a running wazuh-agentd, or 0.
 *
 * Mirrors wazuh-control's own check (init/wazuh-client.sh): the pid files are named
 * var/run/wazuh-agentd-<pid>.pid, so the directory listing carries the answer. Unlike
 * wazuh-control, a stale pid file is ignored rather than deleted -- removing one is touching
 * service state, which this command does not do.
 */
STATIC pid_t w_agent_auth_agentd_pid(void) {
    char **entries = wreaddir(OS_PIDFILE);
    pid_t running = 0;

    if (entries == NULL) {
        return 0;
    }

    for (int i = 0; entries[i] != NULL && running == 0; i++) {
        const char *name = entries[i];
        const char *prefix = "wazuh-agentd-";
        size_t prefix_len = strlen(prefix);
        size_t name_len = strlen(name);

        if (strncmp(name, prefix, prefix_len) != 0 || name_len <= prefix_len + 4 ||
            strcmp(name + name_len - 4, ".pid") != 0) {
            continue;
        }

        char digits[16] = {0};
        size_t digits_len = name_len - prefix_len - 4;

        if (digits_len == 0 || digits_len >= sizeof(digits)) {
            continue;
        }

        memcpy(digits, name + prefix_len, digits_len);

        char *end = NULL;
        long pid = strtol(digits, &end, 10);

        if (end == NULL || *end != '\0' || pid <= 0) {
            continue;
        }

        /* EPERM counts as running: a process we may not signal is still a process. */
        if (kill((pid_t)pid, 0) == 0 || errno == EPERM) {
            running = (pid_t)pid;
        }
    }

    free_strarray(entries);

    return running;
}

#endif /* WIN32 */

/** The agent id on the first line of client.keys, or NULL when it holds no entry. */
STATIC char *w_agent_auth_current_id(void) {
    FILE *fp = wfopen(KEYS_FILE, "r");

    if (fp == NULL) {
        return NULL;
    }

    char line[OS_BUFFER_SIZE] = {0};
    char *read_ok = fgets(line, sizeof(line) - 1, fp);
    fclose(fp);

    if (read_ok == NULL) {
        return NULL;
    }

    char *space = strchr(line, ' ');

    if (space == NULL) {
        return NULL;
    }

    *space = '\0';

    if (line[0] == '\0') {
        return NULL;
    }

    char *id;
    os_strdup(line, id);

    return id;
}


/**
 * @brief Reads the token for this run, from wherever the operator pointed us.
 * @return Newly allocated token text, or NULL (a reason is written to @p err).
 */
STATIC char *w_agent_auth_read_token(const agent_auth_opts_t *opts, FILE *in, FILE *err) {
    if (opts->source == AGENT_AUTH_SOURCE_FILE) {
        /* The shared reader refuses a token too long to fit rather than truncating it, so the
         * size is checked here only to say why: it reports the same "could not read" as a file
         * that is missing or empty, and those want different responses. The stdin path below
         * already names this case; this gives the file path the same answer. */
        struct stat token_st;

        if (stat(opts->token_file, &token_st) == 0 && token_st.st_size >= W_ETOKEN_MAX_FILE_BYTES) {
            fprintf(err, "%s: the enrollment token does not fit in %d bytes.\n", AGENT_AUTH_NAME,
                    W_ETOKEN_MAX_FILE_BYTES);
            return NULL;
        }

        char *text = w_agent_token_read_file(opts->token_file);

        if (text == NULL) {
            fprintf(err, "%s: could not read an enrollment token from '%s'.\n", AGENT_AUTH_NAME,
                    opts->token_file);
        }

        return text;
    }

    char text[W_ETOKEN_MAX_FILE_BYTES + 1] = {'\0'};

    /* Reading stdin from a terminal would block on input nobody is going to type, which reads as
     * the command having hung. Say what is wanted instead: a token only ever arrives here from a
     * redirect or a pipe. */
    if (isatty(fileno(in))) {
        fprintf(err, "%s: no token given. Pass --token-file <path>, or redirect one in:\n",
                AGENT_AUTH_NAME);
        fprintf(err, "\n");
        fprintf(err, "      %s --token-file %s\n", AGENT_AUTH_NAME, AGENT_AUTH_EXAMPLE_TOKEN);
        fprintf(err, "      %s < %s\n", AGENT_AUTH_NAME, AGENT_AUTH_EXAMPLE_TOKEN);
        fprintf(err, "\n");
        fprintf(err, "  Run with --help for the full usage.\n");
        return NULL;
    }

    size_t length = fread(text, 1, sizeof(text) - 1, in);

    if (ferror(in)) {
        fprintf(err, "%s: could not read the enrollment token from standard input.\n",
                AGENT_AUTH_NAME);
        return NULL;
    }

    if (length == sizeof(text) - 1) {
        fprintf(err, "%s: the enrollment token does not fit in %d bytes.\n", AGENT_AUTH_NAME,
                W_ETOKEN_MAX_FILE_BYTES);
        return NULL;
    }

    while (length > 0 && (text[length - 1] == '\n' || text[length - 1] == '\r' ||
                          text[length - 1] == ' ' || text[length - 1] == '\t')) {
        text[--length] = '\0';
    }

    if (length == 0) {
        fprintf(err, "%s: the enrollment token is empty. Pass --token-file <path>,\n"
                "  or redirect one on standard input.\n", AGENT_AUTH_NAME);
        return NULL;
    }

    char *owned;
    os_strdup(text, owned);

    return owned;
}

/**
 * @brief Points <agent><manager><endpoint> at @p adr.
 *
 * Only ever a replacement, never an insertion: OS_WriteXML() appends a node it cannot find --
 * after </ossec_config>, and still returning 0 -- so this refuses unless ClientConf() already
 * proved the element is there, and passes the old value as a second guard against that branch.
 *
 * @return 0 on success, -1 on failure (a reason is written to @p err).
 */
STATIC int w_agent_auth_update_endpoint(const char *adr, const char *configured, FILE *err) {
    const char *nodes[] = {"ossec_config", "agent", "manager", "endpoint", NULL};
    File staged = {NULL, NULL};
    struct stat original;
    OS_XML xml;
    char *written = NULL;
    int result = -1;

    /* Whatever the live file is, that is what the rewritten one has to look like. Reading it
     * first means the mode and ownership are preserved rather than reset to whatever this
     * function believes the install default to be. */
    if (stat(WAZUHCONF, &original) != 0) {
        fprintf(err, "%s: could not read '%s': %s (%d).\n", AGENT_AUTH_NAME, WAZUHCONF,
                strerror(errno), errno);
        return -1;
    }

    /* TempFile() rather than a name chosen here: INSTALLDIR/etc is 0770 root:<group>, writable
     * by the account the agent runs as, and this runs as root. A predictable sibling name lets
     * that account pre-plant a symlink and have root write through it -- and then rename the
     * link itself onto ossec.conf. mkstemp() makes the name unpredictable and creates O_EXCL. */
    if (TempFile(&staged, WAZUHCONF, 0) < 0) {
        fprintf(err, "%s: could not stage a rewrite of '%s': %s (%d).\n", AGENT_AUTH_NAME,
                WAZUHCONF, strerror(errno), errno);
        return -1;
    }

    /* Recorded through the descriptor TempFile() still holds, so it names the file we created
     * rather than whatever the path resolves to later. OS_WriteXML() reopens by NAME, which
     * hands the account that can write INSTALLDIR/etc a window: unlink the staged file and plant
     * a symlink at the same name, and root writes through it, then chowns and renames it onto
     * ossec.conf. The unpredictable name makes that a race rather than a certainty; this check
     * is what decides it. */
#ifndef WIN32
    struct stat staged_before;
    bool staged_known = (fstat(fileno(staged.fp), &staged_before) == 0);
#endif

    fclose(staged.fp);

    if (OS_WriteXML(WAZUHCONF, staged.name, nodes, configured, adr) != 0) {
        fprintf(err, "%s: could not rewrite <manager><endpoint> in '%s'.\n", AGENT_AUTH_NAME,
                WAZUHCONF);
        goto done;
    }

    /* OS_WriteXML() reports success for a rewrite that changed nothing: when the node path is
     * absent it copies the file through untouched and still returns 0, and its "replaced" result
     * is not exposed. An agent whose manager address is spelled some other supported way --
     * <agent><manager><address>, <agent><server-ip>, or a 4.x <client><server><address>, all of
     * which populate the same parsed field this was called about -- would therefore be reported
     * as moved while still dialling the old manager. Reading the value back is the only check
     * that distinguishes "replaced" from "did nothing". */
    if (OS_ReadXML(staged.name, &xml) < 0) {
        fprintf(err, "%s: could not re-read the rewritten '%s'.\n", AGENT_AUTH_NAME, WAZUHCONF);
        goto done;
    }

    written = OS_GetOneContentforElement(&xml, nodes);
    OS_ClearXML(&xml);

    if (written == NULL || strcmp(written, adr) != 0) {
        fprintf(err, "%s: '%s' has no <agent><manager><endpoint> to point at '%s'.\n",
                AGENT_AUTH_NAME, WAZUHCONF, adr);
        fprintf(err, "  The manager address is configured some other way there, so it was left\n");
        fprintf(err, "  alone rather than silently reported as changed.\n");
        goto done;
    }

#ifndef WIN32
    {
        struct stat staged_after;

        if (!staged_known || lstat(staged.name, &staged_after) != 0 ||
                !S_ISREG(staged_after.st_mode) || staged_after.st_nlink != 1 ||
                staged_after.st_dev != staged_before.st_dev ||
                staged_after.st_ino != staged_before.st_ino) {
            fprintf(err, "%s: the staged copy of '%s' was replaced while it was being written; "
                    "refusing to install it.\n", AGENT_AUTH_NAME, WAZUHCONF);
            goto done;
        }
    }

    /* Windows carries no uid, gid or permission bits to carry over. What protects the file there
     * is the DACL mkstemp_ex() puts on it -- Administrators and SYSTEM only, set explicitly
     * rather than inherited from the directory (file_op.c) -- which MoveFileEx() then carries
     * onto ossec.conf. */
    if (fchmodat(AT_FDCWD, staged.name, original.st_mode & 07777, 0) != 0 ||
        chown(staged.name, original.st_uid, original.st_gid) != 0) {
        fprintf(err, "%s: could not preserve the permissions of '%s': %s (%d).\n",
                AGENT_AUTH_NAME, WAZUHCONF, strerror(errno), errno);
        goto done;
    }
#endif

    if (OS_MoveFile(staged.name, WAZUHCONF) < 0) {
        fprintf(err, "%s: could not install the rewritten '%s'.\n", AGENT_AUTH_NAME, WAZUHCONF);
        goto done;
    }

    result = 0;

done:
    os_free(written);

    if (result != 0) {
        unlink(staged.name);
    }

    os_free(staged.name);

    return result;
}

/**
 * @brief Whether the token names somewhere other than the agent's configured manager.
 *
 * The two are not the same shape: the configured value has already been split by
 * w_parse_agent_endpoint() into host, port and prefix, while the token's `adr` is the joined
 * form and carries :port and /prefix only when they differ from the defaults. Comparing the
 * token's whole address against the configured HOST therefore gets it wrong in both directions
 * -- a move back to the default port reads as "no change" and is silently skipped, while a
 * re-enrollment against the same manager on a non-default port reads as a move and rewrites
 * <endpoint>, discarding the operator's prefix. Parsing the token's address the same way the
 * configuration was parsed is the only comparison that holds.
 *
 * @return true when the configuration would have to change, false when it already matches.
 */
STATIC bool w_agent_auth_endpoint_differs(const char *adr, const agent_server *configured) {
    char host[HC_MAX_HOST] = {0};
    char endpoint[HC_MAX_ENDPOINT] = {0};
    int port = 0;
    bool port_present = false;
    uint32_t scope_id = 0;

    if (configured == NULL || configured->rip == NULL) {
        return false;
    }

    if (w_parse_agent_endpoint(adr, host, sizeof(host), &port, &port_present, endpoint,
                               sizeof(endpoint), &scope_id) != 0) {
        /* The core rejects this address too, so the enrollment will not get far enough for the
         * configuration to matter. */
        return false;
    }

    /* Read_Agent_Manager() runs the configured address through OS_ExpandIPv6(), so comparing a
     * token's short form against it makes an IPv6 manager differ from itself: --certs-only would
     * rewrite ossec.conf on every run, and the refusal would report a move that is not one.
     * Expanded here too, on a copy, so both sides are in the same spelling. */
    char expanded[IPSIZE + 1] = {0};

    strncpy(expanded, host, sizeof(expanded) - 1);
    OS_ExpandIPv6(expanded, sizeof(expanded));

    if (strcmp(expanded, configured->rip) != 0 || port != configured->port) {
        return true;
    }

    const char *configured_prefix = (configured->endpoint != NULL) ? configured->endpoint : "";

    return strcmp(endpoint, configured_prefix) != 0;
}

/**
 * @brief Points <agent><manager><endpoint> at @p adr, when it does not already name it.
 *
 * Shared by the enrolling path and --certs-only: both leave the agent talking to whatever
 * ossec.conf names, so both have to re-point it or say plainly that they did not.
 *
 * @param succeeded What this run did accomplish, named in the failure message so an operator
 *        knows the part that worked is not in doubt -- only the pointer to it.
 * @return 0, or AGENT_AUTH_ERR_CONFIG when the rewrite was needed and failed.
 */
STATIC int w_agent_auth_point_config(const char *adr, const agent_server *server,
                                     const char *configured, const char *succeeded, FILE *err) {
    if (server == NULL || server->rip == NULL) {
        /* No <manager><endpoint> to replace. OS_WriteXML() cannot insert one -- it appends the
         * node after </ossec_config> and still reports success -- so this says so instead of
         * returning 0 and leaving an enrolled agent with no address to dial, which is the
         * half-done move this whole path exists to prevent. */
        fprintf(err, "  %s, but %s has no <agent><manager><endpoint> to point\n", succeeded,
                WAZUHCONF);
        fprintf(err, "  at '%s'. Add it by hand before restarting.\n", adr);
        return AGENT_AUTH_ERR_CONFIG;
    }

    if (!w_agent_auth_endpoint_differs(adr, server)) {
        return 0;
    }

    if (w_agent_auth_update_endpoint(adr, configured, err) == 0) {
        fprintf(err, "%s now points <manager><endpoint> at '%s'.\n", WAZUHCONF, adr);
        return 0;
    }

    /* What this run did accomplish stands; only the pointer to it failed. Saying so is the whole
     * value here -- an operator who thinks the move completed will not go looking. */
    fprintf(err, "  %s, but %s still names %s. Point\n", succeeded, WAZUHCONF, configured);
    fprintf(err, "  <manager><endpoint> at '%s' by hand before restarting.\n", adr);

    /* Deliberately not the commit code: that one means the agent still belongs to its previous
     * manager, and this one means it belongs to the new one but is still dialling the old. The
     * fixes are opposite, so the codes are too. */
    return AGENT_AUTH_ERR_CONFIG;
}

/** Maps a core status onto this command's exit code. */
STATIC int w_agent_auth_exit_code(w_token_enroll_status_t status) {
    switch (status) {
        case W_TOKEN_ENROLL_OK:
            return AGENT_AUTH_OK;
        case W_TOKEN_ENROLL_ERR_TOKEN:
            return AGENT_AUTH_ERR_TOKEN;
        case W_TOKEN_ENROLL_ERR_ANCHOR:
            return AGENT_AUTH_ERR_ANCHOR;
        /* Local failures, both of them before anything reached the network -- reporting them as
         * "the manager refused" would send an operator to the wrong machine. */
        case W_TOKEN_ENROLL_ERR_CREDENTIAL:
        case W_TOKEN_ENROLL_ERR_REQUEST:
            return AGENT_AUTH_ERR_USAGE;
        case W_TOKEN_ENROLL_ERR_ENROLL:
            return AGENT_AUTH_ERR_ENROLL;
        case W_TOKEN_ENROLL_ERR_STORE:
        case W_TOKEN_ENROLL_ERR_COMMIT:
            return AGENT_AUTH_ERR_COMMIT;
        default:
            return AGENT_AUTH_ERR_ENROLL;
    }
}

STATIC int w_agent_auth_enroll(const agent_auth_opts_t *opts, FILE *in, FILE *out, FILE *err) {
    char *token_text = NULL;
    char *current_id = NULL;
    w_etoken_t token;
    w_etoken_error_t decode_err;
    w_token_enroll_opts_t enroll_opts = {0};
    w_token_enroll_report_t report = {0};
    w_token_enroll_status_t status;
    /* No <manager><endpoint> at all is a legitimate configuration to enroll from -- a
     * token-only install has not been pointed anywhere yet. */
    /* No <manager><endpoint> at all is a legitimate configuration to enroll from -- a token-only
     * install has not been pointed anywhere yet. */
    const agent_server *server = (agt != NULL && agt->server != NULL) ? &agt->server[0] : NULL;
    const char *configured = (server != NULL) ? server->rip : NULL;
    bool registered;
    pid_t agentd_pid;
    int result;

    if ((token_text = w_agent_auth_read_token(opts, in, err)) == NULL) {
        return AGENT_AUTH_ERR_USAGE;
    }

    /* Decoded here as well as inside the core, because the guards below have to tell the
     * operator which manager the token names before anything is contacted. */
    if ((decode_err = w_etoken_decode(token_text, &token)) != ETOKEN_OK) {
        fprintf(err, "%s: invalid enrollment token: %s.\n", AGENT_AUTH_NAME,
                w_etoken_strerror(decode_err));
        /* Cleansed, not merely freed: a token that fails to decode is still the credential in
         * transit, and this is the one exit that used to skip the wipe every other one does. */
        w_agent_auth_forget(token_text);
        return AGENT_AUTH_ERR_TOKEN;
    }

    /* "Already registered" is decided the same way the first-boot latch decides it
     * (token_bootstrap.c), so the two cannot disagree about what an enrolled agent looks like.
     * The id is parsed only to name it in the messages: a client.keys whose first line is a
     * removed-agent marker or a comment still counts as registered. */
    registered = (FileSize(KEYS_FILE) > 0);
    current_id = w_agent_auth_current_id();
    agentd_pid = w_agent_auth_agentd_pid();

    /* Before the guards, not after: a dry run writes nothing and contacts nothing, so there is
     * nothing for a guard to protect -- and refusing to preview the operation the operator is
     * deciding whether to authorise is the wrong way round. */
    if (opts->dry_run) {
        /* The whole preview on one stream. Split across out and err it came out in the wrong
         * order the moment stdout stopped being a terminal: stdout block-buffers and flushes at
         * exit, stderr does not, so the first line arrived last under `> file` or `| less`. The
         * preview is what the operator asked this run to produce, which is what stdout carries
         * here -- on a real run that is the outcome line, and a dry run has no outcome. */
        if (opts->certs_only) {
            fprintf(out, "would install anchor manager=%s\n", token.adr);
        } else {
            fprintf(out, "would enroll with manager=%s\n", token.adr);

            if (registered) {
                fprintf(out, "would REPLACE the registration id=%s with a new one\n",
                        current_id != NULL ? current_id : "unknown");
            }
        }

        /* Outside the branch above: both modes re-point the address, so both have to preview it. */
        if (w_agent_auth_endpoint_differs(token.adr, server)) {
            fprintf(out, "would point <manager><endpoint> at '%s' in %s\n", token.adr, WAZUHCONF);
        }

        fprintf(out, "would %s the trust anchor at %s\n",
                IsFile(AGENT_ANCHOR_CA) == 0 ? "REPLACE" : "install", AGENT_ANCHOR_CA);
        fprintf(out, "nothing was contacted and nothing was written.\n");
        w_etoken_free(&token);
        os_free(current_id);
        w_agent_auth_forget(token_text);
        return AGENT_AUTH_OK;
    }

    /* --certs-only refreshes trust material, so it needs something to refresh. */
    if (opts->certs_only && !registered) {
        fprintf(err, "%s: this agent is not enrolled, so there is no trust to refresh.\n",
                AGENT_AUTH_NAME);
        fprintf(err, "  To enroll it, run without --certs-only.\n");
        goto refuse;
    }

    /* Only the enrolling path replaces a registration; --certs-only leaves it alone, so asking
     * permission for something that is not happening would be noise. */
    if (registered && !opts->certs_only && !opts->force_enroll) {
        fprintf(err, "%s: this agent already has a key (id=%s); nothing was contacted.\n",
                AGENT_AUTH_NAME, current_id != NULL ? current_id : "unknown");

        /* Only worth a line when it carries information. Printing "current: 127.0.0.1 / token:
         * 127.0.0.1" is two lines that say the addresses match, which is the uninteresting case. */
        if (w_agent_auth_endpoint_differs(token.adr, server)) {
            fprintf(err, "  The token points at a different manager: %s -> %s\n",
                    configured != NULL ? configured : "(none configured)", token.adr);
        }

        fprintf(err, "\n");
        fprintf(err, "  Re-run with --force-enroll to register it again. It gets a NEW id.\n");
        fprintf(err, "\n");
        /* The refusal is decided locally, which is not obvious: an operator who has just deleted
         * the agent on the manager expects that to have cleared it. Name the file the check
         * reads rather than referring to "this key", which reads as if one had been printed. */
        fprintf(err, "  This is decided from %s on this host, not from the\n", KEYS_FILE);
        fprintf(err, "  manager -- deleting the agent there does not clear it.\n");
        goto refuse;
    }

    /* No override. The agent loads its identity once at startup and reads the anchor by path on
     * every handshake, so a restart is needed whatever happens here and replacing the anchor
     * under a live agent breaks it at once. There is nothing worth forcing, and this command
     * never touches service state itself. */
    if (agentd_pid > 0) {
        char install_dir[PATH_MAX] = {0};

        if (getcwd(install_dir, sizeof(install_dir)) == NULL) {
            install_dir[0] = '\0';
        }

#ifdef WIN32
        (void)install_dir;
        fprintf(err, "%s: stop the agent first (the Wazuh service is running):\n",
                AGENT_AUTH_NAME);
        fprintf(err, "\n");
        fprintf(err, "      net stop WazuhSvc\n");
#else
        fprintf(err, "%s: stop the agent first (wazuh-agentd is running, pid %d):\n",
                AGENT_AUTH_NAME, (int)agentd_pid);
        fprintf(err, "\n");
        fprintf(err, "      %s%sbin/wazuh-control stop\n", install_dir,
                install_dir[0] != '\0' ? "/" : "");
#endif
        goto refuse;
    }

    enroll_opts.token_text = token_text;
#ifdef WIN32
    /* No privilege drop, no users and no groups: the files are protected by the ACL their
     * directory carries, which is the model the bootstrap already uses there. */
    enroll_opts.uid = -1;
    enroll_opts.gid = -1;
#else
    /* The same user and group the agent itself resolves (main.c). Deliberately not options: the
     * only thing such flags could express is a disagreement with what the agent will run as, and
     * the anchor would then be unreadable to it. The uid matters on a re-enrollment: the manager
     * issues a fresh re-enrollment secret, which this root process writes and the agent has to
     * rewrite on every later rotation -- left root-owned, every one of those rotations fails. */
    enroll_opts.uid = (int)Privsep_GetUser(USER);
    enroll_opts.gid = (int)Privsep_GetGroup(GROUPGLOBAL);
#endif
    enroll_opts.anchor_only = opts->certs_only;
    /* --certs-only has nothing to roll back: it replaces the anchor with a single atomic rename
     * and never touches client.keys, so a failure leaves the previous anchor in place. */
    enroll_opts.transactional = !opts->certs_only && (registered || IsFile(AGENT_ANCHOR_CA) == 0);

#ifndef WIN32
    if (enroll_opts.uid == (int)-1 || enroll_opts.gid == (int)-1) {
        fprintf(err, "%s: no such user '%s' or group '%s'.\n", AGENT_AUTH_NAME, USER,
                GROUPGLOBAL);
        goto refuse;
    }
#endif

    status = w_agent_token_enroll(&enroll_opts, &report);
    result = w_agent_auth_exit_code(status);

    if (status != W_TOKEN_ENROLL_OK) {
        fprintf(err, "%s: %s.\n", AGENT_AUTH_NAME, w_agent_token_enroll_strerror(status));

        /* The class alone is not actionable: "the CA could not be established" is the same
         * sentence for an address that does not resolve and a pin that does not match, and those
         * want opposite responses. The core names the cause; without this it reaches only
         * logs/ossec.log, because this command silences the log's stderr echo. */
        if (report.detail[0] != '\0') {
            fprintf(err, "  %s\n", report.detail);
        }

        if (status == W_TOKEN_ENROLL_ERR_COMMIT || status == W_TOKEN_ENROLL_ERR_STORE) {
            if (report.keys_backup[0] != '\0') {
                fprintf(err, "  Neither the commit nor the rollback completed. A copy of the\n");
                fprintf(err, "  previous agent key is at '%s'. Do not restart the agent until\n",
                        report.keys_backup);
                fprintf(err, "  it has been restored.\n");
            } else if (report.rolled_back) {
                fprintf(err, "  The previous agent key was restored; this agent still talks to\n");
                fprintf(err, "  its former manager.\n");
            } else {
                /* The loudest case gets the most words: enrolled, the key on disk was replaced,
                 * and nothing was put back. Saying only "could not be committed" here would hide
                 * the fact that this agent can now reach no manager at all.
                 *
                 * Deliberately not gated on `registered`, which describes the state before the
                 * run rather than the damage done by it: an agent that has a trust anchor but an
                 * empty client.keys still enrolls transactionally, yet has nothing to snapshot,
                 * so it arrives here with `registered` false and no backup -- the one shape
                 * where every branch above is false and this warning is the only one left. */
                if (registered) {
                    fprintf(err, "  The previous agent key was NOT restored and no backup exists.\n");
                }

                fprintf(err, "  This agent now holds a key for %s while still trusting its\n",
                        report.host[0] != '\0' ? report.host : token.adr);
                fprintf(err, "  former manager, and can reach neither until it is re-enrolled.\n");
            }
        } else {
            if (report.manager_message[0] != '\0') {
                fprintf(err, "  The manager said: %s\n", report.manager_message);
            }

            fprintf(err, "  Nothing was changed.\n");
        }

        goto done;
    }

    if (opts->certs_only) {
        int config_result;

        /* One line, and only what happened. The tool cannot tell "same manager, new address or
         * rotated CA" from "a different manager" -- neither address nor pin identifies one -- so
         * it reports the change and leaves that judgement where it belongs. */
        fprintf(out, "anchor %s manager=%s\n", report.anchor_changed ? "installed" : "unchanged",
                report.host[0] != '\0' ? report.host : token.adr);
        fflush(out);

        /* The address is re-pointed here too, not only on the enrolling path. A manager that
         * changes its name almost always reissues its certificate at the same time, so this is
         * the mode an operator reaches for -- and the line above names the address in the TOKEN,
         * which without this would be an address the agent is not going to dial. The registration
         * is still never touched; that is the whole distinction from the default path. */
        config_result = w_agent_auth_point_config(token.adr, server, configured,
                                                  "The trust anchor is in place", err);

        if (config_result != 0) {
            result = config_result;
        }

        goto done;
    }

    fprintf(out, "enrolled id=%s name=%s manager=%s:%d\n", report.agent_id, report.agent_name,
            report.host, report.port);
    /* The narrative below goes to err, which is unbuffered; without this the outcome line lands
     * after it whenever stdout is redirected. */
    fflush(out);

    if (report.had_anchor) {
        fprintf(err, "The previous trust anchor was %s.\n",
                report.anchor_changed ? "replaced" : "already current");
    } else {
        fprintf(err, "Trust anchor installed at %s.\n", AGENT_ANCHOR_CA);
    }

    /* The id alone, and no advice about it. What became of the previous registration is the
     * manager's business and it does not say: depending on the agent name and its own
     * replacement window it deletes the old one, keeps it, or refuses the enrollment outright as
     * a duplicate. Skipped entirely when the id could not be read -- "id=unknown" is not a fact
     * worth a line. */
    if (registered && current_id != NULL) {
        fprintf(err, "The previous registration was id=%s.\n", current_id);
    }

    {
        int config_result = w_agent_auth_point_config(token.adr, server, configured,
                                                      "The agent is enrolled", err);

        if (config_result != 0) {
            result = config_result;
        }
    }

done:
    w_etoken_free(&token);
    os_free(current_id);
    /* The token text is the credential in transit: base64url of a JSON object carrying the
     * secret. w_etoken_free() cleanses the decoded copy; this is the other one. */
    w_agent_auth_forget(token_text);

    return result;

refuse:
    w_etoken_free(&token);
    os_free(current_id);
    w_agent_auth_forget(token_text);

    return AGENT_AUTH_ERR_USAGE;
}

int w_agent_auth_run(const agent_auth_opts_t *opts, FILE *in, FILE *out, FILE *err) {
    if (opts->action == AGENT_AUTH_ACTION_SHOW) {
        if (opts->source == AGENT_AUTH_SOURCE_FILE) {
            FILE *fp = wfopen(opts->token_file, "r");
            int result;

            if (fp == NULL) {
                fprintf(err, "%s: could not read '%s': %s (%d).\n", AGENT_AUTH_NAME,
                        opts->token_file, strerror(errno), errno);
                return AGENT_AUTH_ERR_USAGE;
            }

            result = w_agent_show_token(fp, out, err, AGENT_AUTH_NAME);
            fclose(fp);

            return result;
        }

        return w_agent_show_token(in, out, err, AGENT_AUTH_NAME);
    }

    return w_agent_auth_enroll(opts, in, out, err);
}

