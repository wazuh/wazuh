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

/* The utility mode of wazuh-manager-authd for enrollment tokens (issue #38993): a client of the
 * running daemon's auth.sock verbs (token_create / token_list / token_revoke, local-server.c), plus
 * an offline --show-token over the shared codec. See token_cli.h for the contract with main().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "os_net.h"
#include "agent_op.h"
#include "authd-config.h"
#include "enrollment_token.h"
#include "enrollment_token_store.h"
#include "token_cli.h"

/* Long option ids: outside the range of any short option character */
enum {
    OPT_CREATE = 256,
    OPT_LIST,
    OPT_REVOKE,
    OPT_SHOW,
    OPT_ADDRESS,
    OPT_PORT,
    OPT_PREFIX,
    OPT_TTL,
    OPT_MAX_USES,
    OPT_DESCRIPTION,
    OPT_EMBED_CA,
    OPT_NO_CREDENTIAL,
    OPT_TOKEN_FILE
};

/* Longest token text --show-token accepts from a file or stdin: an --embed-ca token is ~2.3 KB */
#define TOKEN_CLI_MAX_TOKEN 16384

const struct option token_cli_long_opts[] = {
    {"create-enrollment-token", no_argument, NULL, OPT_CREATE},
    {"list-enrollment-tokens", no_argument, NULL, OPT_LIST},
    {"revoke-enrollment-token", required_argument, NULL, OPT_REVOKE},
    {"show-token", optional_argument, NULL, OPT_SHOW},
    {"address", required_argument, NULL, OPT_ADDRESS},
    {"port", required_argument, NULL, OPT_PORT},
    {"prefix", required_argument, NULL, OPT_PREFIX},
    {"ttl", required_argument, NULL, OPT_TTL},
    {"max-uses", required_argument, NULL, OPT_MAX_USES},
    {"description", required_argument, NULL, OPT_DESCRIPTION},
    {"embed-ca", no_argument, NULL, OPT_EMBED_CA},
    {"no-credential", no_argument, NULL, OPT_NO_CREDENTIAL},
    {"token-file", required_argument, NULL, OPT_TOKEN_FILE},
    {NULL, 0, NULL, 0}
};

/* Exactly one action per invocation */
static int cli_set_action(token_cli_opts_t *opts, token_cli_action_t action, FILE *err)
{
    if (opts->action != TOKEN_CLI_NONE && opts->action != action) {
        fprintf(err, "ERROR: give only one of --create-enrollment-token, --list-enrollment-tokens, "
                     "--revoke-enrollment-token or --show-token\n");
        return -1;
    }

    opts->action = action;
    opts->requested = 1;

    return 1;
}

/* Decimal integer in [min, max]; anything else is reported and refused */
static int cli_parse_long(const char *name, const char *arg, long min, long max, long *out, FILE *err)
{
    char *end = NULL;
    long value;

    if (arg == NULL || *arg == '\0') {
        fprintf(err, "ERROR: %s needs a numeric argument\n", name);
        return -1;
    }

    /* Decimal digits only: no sign, no blanks, no trailing text */
    for (end = (char *) arg; *end >= '0' && *end <= '9'; end++) {
    }

    if (*end != '\0' || end == arg) {
        fprintf(err, "ERROR: %s needs a numeric argument\n", name);
        return -1;
    }

    value = strtol(arg, &end, 10);

    if (*end != '\0' || value < min || value > max) {
        fprintf(err, "ERROR: %s must be between %ld and %ld\n", name, min, max);
        return -1;
    }

    *out = value;

    return 0;
}

int w_token_cli_parse_opt(token_cli_opts_t *opts, int c, const char *arg, FILE *err)
{
    time_t interval = 0;

    if (opts == NULL || err == NULL) {
        return -1;
    }

    switch (c) {
    case OPT_CREATE:
        return cli_set_action(opts, TOKEN_CLI_CREATE, err);
    case OPT_LIST:
        return cli_set_action(opts, TOKEN_CLI_LIST, err);
    case OPT_REVOKE:
        opts->revoke_id = arg;
        return cli_set_action(opts, TOKEN_CLI_REVOKE, err);
    case OPT_SHOW:
        opts->token_text = arg; /* NULL unless written --show-token=<token> */
        return cli_set_action(opts, TOKEN_CLI_SHOW, err);
    case OPT_ADDRESS:
        opts->address = arg;
        opts->requested = 1;
        return 1;
    case OPT_PORT:
        opts->requested = 1;
        return cli_parse_long("--port", arg, 1, 65535, &opts->port, err) == 0 ? 1 : -1;
    case OPT_PREFIX:
        opts->prefix = arg;
        opts->requested = 1;
        return 1;
    case OPT_TTL:
        opts->requested = 1;
        /* The same N[d|h|m|s] grammar as the <force> timers of the configuration */
        if (arg == NULL || get_time_interval((char *) arg, &interval) != 0 || interval <= 0) {
            fprintf(err, "ERROR: --ttl must be a positive duration such as 30d, 12h, 45m or 90s\n");
            return -1;
        }
        opts->ttl = (long) interval;
        return 1;
    case OPT_MAX_USES:
        opts->requested = 1;
        return cli_parse_long("--max-uses", arg, 0, 1000000000L, &opts->max_uses, err) == 0 ? 1 : -1;
    case OPT_DESCRIPTION:
        opts->description = arg;
        opts->requested = 1;
        return 1;
    case OPT_EMBED_CA:
        opts->embed_ca = 1;
        opts->requested = 1;
        return 1;
    case OPT_NO_CREDENTIAL:
        opts->no_credential = 1;
        opts->requested = 1;
        return 1;
    case OPT_TOKEN_FILE:
        opts->token_file = arg;
        opts->requested = 1;
        return 1;
    default:
        return 0;
    }
}

/* ISO 8601 in UTC, so two operators on two hosts read the same expiry */
static void cli_format_time(time_t when, char *buf, size_t size)
{
    struct tm tm;

    if (gmtime_r(&when, &tm) == NULL || strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        snprintf(buf, size, "%ld", (long) when);
    }
}

/* One request over auth.sock. Returns the parsed response (caller deletes) or NULL after reporting
 * the transport failure. Access to the socket is what authorises the caller: root, or a member of
 * the manager group.
 */
static cJSON *cli_request(cJSON *request, FILE *err)
{
    char *text = NULL;
    char *response = NULL;
    cJSON *json = NULL;
    ssize_t length;
    int sock;

    if ((text = cJSON_PrintUnformatted(request)) == NULL) {
        fprintf(err, "ERROR: cannot build the request\n");
        return NULL;
    }

    if ((sock = auth_connect()) < 0) {
        fprintf(err, "ERROR: cannot connect to %s: is wazuh-manager-authd running? "
                     "(run as root or as a member of the %s group)\n", AUTH_LOCAL_SOCK, GROUPGLOBAL);
        os_free(text);
        return NULL;
    }

    if (OS_SendSecureTCP(sock, strlen(text), text) < 0) {
        fprintf(err, "ERROR: cannot send the request to %s: %s\n", AUTH_LOCAL_SOCK, strerror(errno));
        auth_close(sock);
        os_free(text);
        return NULL;
    }

    os_free(text);
    os_calloc(OS_MAXSTR + 1, sizeof(char), response);
    length = OS_RecvSecureTCP(sock, response, OS_MAXSTR);
    auth_close(sock);

    if (length <= 0) {
        fprintf(err, "ERROR: no response from wazuh-manager-authd\n");
        os_free(response);
        return NULL;
    }

    response[length] = '\0';
    json = cJSON_Parse(response);
    OPENSSL_cleanse(response, (size_t) length); /* a token_create response carries the token */
    os_free(response);

    if (json == NULL) {
        fprintf(err, "ERROR: cannot parse the response from wazuh-manager-authd\n");
    }

    return json;
}

/* authd's own verdict. 0 when error is 0; 1 (reported) otherwise */
static int cli_check_error(const cJSON *response, FILE *err)
{
    const cJSON *error = cJSON_GetObjectItem(response, "error");
    const cJSON *message = cJSON_GetObjectItem(response, "message");

    if (!cJSON_IsNumber(error)) {
        fprintf(err, "ERROR: malformed response from wazuh-manager-authd\n");
        return 1;
    }

    if (error->valueint == 0) {
        return 0;
    }

    fprintf(err, "ERROR %d: %s\n", error->valueint, cJSON_IsString(message) ? message->valuestring : "unknown error");

    if (error->valueint == 9015) {
        fprintf(err, "Enrollment tokens are minted and revoked on the master node.\n");
    }

    return 1;
}

static int cli_create(const token_cli_opts_t *opts, FILE *out, FILE *err)
{
    cJSON *request = NULL;
    cJSON *arguments = NULL;
    cJSON *response = NULL;
    cJSON *data = NULL;
    const cJSON *item = NULL;
    char when[32];
    int result = 1;

    if (opts->address == NULL || *opts->address == '\0') {
        fprintf(err, "ERROR: --create-enrollment-token requires --address <host>, the name the agents will connect to\n");
        return 1;
    }

    request = cJSON_CreateObject();
    arguments = cJSON_AddObjectToObject(request, "arguments");
    cJSON_AddStringToObject(request, "function", "token_create");
    cJSON_AddStringToObject(arguments, "address", opts->address);

    if (opts->port > 0) {
        cJSON_AddNumberToObject(arguments, "port", (double) opts->port);
    }

    if (opts->prefix != NULL) {
        cJSON_AddStringToObject(arguments, "prefix", opts->prefix);
    }

    if (opts->ttl > 0) {
        cJSON_AddNumberToObject(arguments, "ttl", (double) opts->ttl);
    }

    if (opts->max_uses > 0) {
        cJSON_AddNumberToObject(arguments, "max_uses", (double) opts->max_uses);
    }

    if (opts->description != NULL) {
        cJSON_AddStringToObject(arguments, "description", opts->description);
    }

    if (opts->embed_ca) {
        cJSON_AddBoolToObject(arguments, "embed_ca", 1);
    }

    if (opts->no_credential) {
        cJSON_AddBoolToObject(arguments, "no_credential", 1);
    }

    response = cli_request(request, err);
    cJSON_Delete(request);

    if (response == NULL) {
        return 1;
    }

    if (cli_check_error(response, err) != 0) {
        goto end;
    }

    data = cJSON_GetObjectItem(response, "data");
    item = cJSON_GetObjectItem(data, "token");

    if (!cJSON_IsString(item)) {
        fprintf(err, "ERROR: malformed response from wazuh-manager-authd\n");
        goto end;
    }

    /* The token alone on stdout, so `WAZUH_ENROLLMENT_TOKEN=$(...)` captures exactly it; everything
     * an operator may want to note goes to stderr. The credential never appears anywhere else. */
    fprintf(out, "%s\n", item->valuestring);

    item = cJSON_GetObjectItem(data, "id");
    fprintf(err, "id: %s\n", cJSON_IsString(item) ? item->valuestring : "?");
    item = cJSON_GetObjectItem(data, "adr");
    fprintf(err, "endpoint: %s\n", cJSON_IsString(item) ? item->valuestring : "?");
    item = cJSON_GetObjectItem(data, "expires");

    if (cJSON_IsNumber(item)) {
        cli_format_time((time_t) item->valuedouble, when, sizeof(when));
        fprintf(err, "expires: %s (%ld)\n", when, (long) item->valuedouble);
    }

    item = cJSON_GetObjectItem(data, "pin_hex");

    if (cJSON_IsString(item)) {
        fprintf(err, "pin: %s\n", item->valuestring);
    }

    fprintf(err, "credential: %s\n", opts->no_credential ? "no" : "yes");
    result = 0;

end:
    cJSON_Delete(response);

    return result;
}

static int cli_list(FILE *out, FILE *err)
{
    cJSON *request = cJSON_CreateObject();
    cJSON *response = NULL;
    const cJSON *data = NULL;
    const cJSON *token = NULL;
    int result = 1;

    cJSON_AddStringToObject(request, "function", "token_list");
    response = cli_request(request, err);
    cJSON_Delete(request);

    if (response == NULL) {
        return 1;
    }

    if (cli_check_error(response, err) != 0) {
        goto end;
    }

    data = cJSON_GetObjectItem(response, "data");

    if (!cJSON_IsArray(data)) {
        fprintf(err, "ERROR: malformed response from wazuh-manager-authd\n");
        goto end;
    }

    if (cJSON_GetArraySize(data) == 0) {
        fprintf(out, "no enrollment tokens\n");
        result = 0;
        goto end;
    }

    fprintf(out, "%-22s  %-32s  %-20s  %-14s  %-7s  %s\n", "ID", "ENDPOINT", "EXPIRES", "USES", "REVOKED", "DESCRIPTION");

    cJSON_ArrayForEach(token, data) {
        const cJSON *id = cJSON_GetObjectItem(token, "id");
        const cJSON *adr = cJSON_GetObjectItem(token, "adr");
        const cJSON *expires = cJSON_GetObjectItem(token, "expires");
        const cJSON *max_uses = cJSON_GetObjectItem(token, "max_uses");
        const cJSON *uses = cJSON_GetObjectItem(token, "uses");
        const cJSON *revoked = cJSON_GetObjectItem(token, "revoked");
        const cJSON *description = cJSON_GetObjectItem(token, "description");
        char when[32] = "?";
        char usage[32];

        if (cJSON_IsNumber(expires)) {
            cli_format_time((time_t) expires->valuedouble, when, sizeof(when));
        }

        if (cJSON_IsNumber(max_uses) && max_uses->valueint > 0) {
            snprintf(usage, sizeof(usage), "%d/%d", cJSON_IsNumber(uses) ? uses->valueint : 0, max_uses->valueint);
        } else {
            snprintf(usage, sizeof(usage), "%d/unlimited", cJSON_IsNumber(uses) ? uses->valueint : 0);
        }

        fprintf(out, "%-22s  %-32s  %-20s  %-14s  %-7s  %s\n",
                cJSON_IsString(id) ? id->valuestring : "?",
                cJSON_IsString(adr) ? adr->valuestring : "?",
                when,
                usage,
                cJSON_IsTrue(revoked) ? "yes" : "no",
                cJSON_IsString(description) ? description->valuestring : "-");
    }

    result = 0;

end:
    cJSON_Delete(response);

    return result;
}

static int cli_revoke(const token_cli_opts_t *opts, FILE *out, FILE *err)
{
    cJSON *request = NULL;
    cJSON *arguments = NULL;
    cJSON *response = NULL;
    int result = 1;

    if (opts->revoke_id == NULL || *opts->revoke_id == '\0') {
        fprintf(err, "ERROR: --revoke-enrollment-token requires the token id\n");
        return 1;
    }

    request = cJSON_CreateObject();
    arguments = cJSON_AddObjectToObject(request, "arguments");
    cJSON_AddStringToObject(request, "function", "token_revoke");
    cJSON_AddStringToObject(arguments, "id", opts->revoke_id);
    response = cli_request(request, err);
    cJSON_Delete(request);

    if (response == NULL) {
        return 1;
    }

    if (cli_check_error(response, err) == 0) {
        fprintf(out, "Enrollment token %s revoked.\n", opts->revoke_id);
        result = 0;
    }

    cJSON_Delete(response);

    return result;
}

/* First non-blank line of a stream, trimmed: the token as an operator pastes or pipes it */
static char *cli_read_token(FILE *stream)
{
    char *buffer = NULL;
    char *start;
    char *end;

    os_calloc(TOKEN_CLI_MAX_TOKEN + 1, sizeof(char), buffer);

    if (fgets(buffer, TOKEN_CLI_MAX_TOKEN + 1, stream) == NULL) {
        os_free(buffer);
        return NULL;
    }

    for (start = buffer; *start == ' ' || *start == '\t' || *start == '\r' || *start == '\n'; start++) {
    }

    for (end = start + strlen(start); end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'); end--) {
    }

    *end = '\0';

    if (start != buffer) {
        memmove(buffer, start, strlen(start) + 1);
    }

    return buffer;
}

static int cli_show(const token_cli_opts_t *opts, FILE *in, FILE *out, FILE *err)
{
    char *owned = NULL;
    const char *text = opts->token_text;
    w_etoken_t token;
    w_etoken_error_t decoded;
    char *description = NULL;
    int result = 1;

    if (text == NULL && opts->token_file != NULL) {
        FILE *fp = wfopen(opts->token_file, "r");

        if (fp == NULL) {
            fprintf(err, "ERROR: cannot read '%s': %s\n", opts->token_file, strerror(errno));
            return 1;
        }

        owned = cli_read_token(fp);
        fclose(fp);
        text = owned;
    } else if (text == NULL) {
        owned = cli_read_token(in);
        text = owned;
    }

    if (text == NULL || *text == '\0') {
        fprintf(err, "ERROR: no token given: pass --show-token=<token>, --token-file <path> or pipe it on stdin\n");
        os_free(owned);
        return 1;
    }

    if (decoded = w_etoken_decode(text, &token), decoded != ETOKEN_OK) {
        fprintf(err, "ERROR: %s\n", w_etoken_strerror(decoded));
    } else if ((description = w_etoken_describe(&token)) == NULL) {
        fprintf(err, "ERROR: cannot describe the token\n");
    } else {
        fputs(description, out);
        result = 0;
    }

    /* The struct holds the secret, the text holds the whole token: neither outlives this call */
    w_etoken_free(&token);
    os_free(description);

    if (owned != NULL) {
        OPENSSL_cleanse(owned, strlen(owned));
        os_free(owned);
    }

    return result;
}

int w_token_cli_run(const token_cli_opts_t *opts, FILE *in, FILE *out, FILE *err)
{
    if (opts == NULL || out == NULL || err == NULL) {
        return 1;
    }

    switch (opts->action) {
    case TOKEN_CLI_CREATE:
        return cli_create(opts, out, err);
    case TOKEN_CLI_LIST:
        return cli_list(out, err);
    case TOKEN_CLI_REVOKE:
        return cli_revoke(opts, out, err);
    case TOKEN_CLI_SHOW:
        return cli_show(opts, in, out, err);
    case TOKEN_CLI_NONE:
    default:
        fprintf(err, "ERROR: an enrollment token option was given without an action: add "
                     "--create-enrollment-token, --list-enrollment-tokens, --revoke-enrollment-token <id> "
                     "or --show-token\n");
        return 1;
    }
}
