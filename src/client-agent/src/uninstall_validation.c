/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Package uninstallation validation (anti_tampering/package_uninstallation).
 *
 * Kept apart from agentd.c, which the Windows build leaves out, so that the deb/rpm scripts
 * (through wazuh-agentd) and the Windows installer (through wazuh-agent.exe) run the same
 * code against the manager API's /agents/uninstall endpoint. */

#include "shared.h"
#include "agentd.h"

bool check_uninstall_permission(const char *token, const char *host, bool ssl_verify) {
    char url[OS_SIZE_8192];
    snprintf(url, sizeof(url), "https://%s/agents/uninstall", host);

    char header[OS_SIZE_8192] = { '\0' };
    snprintf(header, sizeof(header), "Authorization: Bearer %s", token);

    char* headers[] = { NULL, NULL };
    os_strdup(header, headers[0]);

    curl_response *response = wurl_http_request(WURL_GET_METHOD, headers, url, NULL, OS_SIZE_8192, 30, NULL, ssl_verify);

    if (response) {
        if (response->status_code == 200) {
            mdebug1(AG_UNINSTALL_VALIDATION_GRANTED);
            wurl_free_response(response);
            os_free(headers[0]);
            return false;
        } else if (response->status_code == 403) {
            mdebug1(AG_UNINSTALL_VALIDATION_DENIED);
        } else {
            merror(AG_API_ERROR_CODE, response->status_code);
        }
        wurl_free_response(response);
    } else {
        merror(AG_REQUEST_FAIL);
    }

    os_free(headers[0]);
    return true;
}

char* authenticate_and_get_token(const char *userpass, const char *host, bool ssl_verify) {
    char url[OS_SIZE_8192];
    char *token = NULL;
    char* headers[] = { NULL };

    snprintf(url, sizeof(url), "https://%s/security/user/authenticate?raw=true", host);
    curl_response *response = wurl_http_request(WURL_POST_METHOD, headers, url, NULL, OS_SIZE_8192, 30, userpass, ssl_verify);

    if (response) {
        if (response->status_code == 200) {
            os_strdup(response->body, token);
        } else {
            merror(AG_API_ERROR_CODE, response->status_code);
        }
        wurl_free_response(response);
    } else {
        merror(AG_REQUEST_FAIL);
    }

    return token;
}

bool package_uninstall_validation(const char *uninstall_auth_token, const char *uninstall_auth_login, const char *uninstall_auth_host, bool ssl_verify) {
    bool validate_result = true;

    mdebug1(AG_UNINSTALL_VALIDATION_START);
    if (uninstall_auth_token) {
        validate_result = check_uninstall_permission(uninstall_auth_token, uninstall_auth_host, ssl_verify);
        if (validate_result) {
            return validate_result;
        }
    }
    if (uninstall_auth_login) {
        char *new_token = authenticate_and_get_token(uninstall_auth_login, uninstall_auth_host, ssl_verify);
        if (new_token) {
            validate_result = check_uninstall_permission(new_token, uninstall_auth_host, ssl_verify);
            os_free(new_token);
        } else {
            merror(AG_TOKEN_FAIL, uninstall_auth_login);
        }
    }
    return validate_result;
}

/* Value of a "--name=value" or "--name value" argument at argv[*i], or NULL when argv[*i] is not
 * that option. Advances *i past a separate value. */
static const char *uninstall_option_value(int argc, char **argv, int *i, const char *name, bool *matched) {
    const size_t len = strlen(name);

    *matched = false;
    if (strncmp(argv[*i], name, len) != 0) {
        return NULL;
    }
    if (argv[*i][len] == '=') {
        *matched = true;
        return argv[*i] + len + 1;
    }
    if (argv[*i][len] == '\0') {
        *matched = true;
        if (*i + 1 < argc && strncmp(argv[*i + 1], "--", 2) != 0) {
            return argv[++(*i)];
        }
        return NULL;
    }
    return NULL;
}

int w_uninstall_validation_cli(int argc, char **argv) {
    const char *login = NULL;
    const char *token = NULL;
    const char *host = NULL;
    bool ssl_verify = true;

    for (int i = 1; i < argc; i++) {
        bool matched = false;
        const char *value;

        if ((value = uninstall_option_value(argc, argv, &i, "--uninstall-auth-login", &matched)), matched) {
            if (!value || *value == '\0') {
                merror("--uninstall-auth-login needs an argument");
                return 1;
            }
            login = value;
        } else if ((value = uninstall_option_value(argc, argv, &i, "--uninstall-auth-token", &matched)), matched) {
            if (!value || *value == '\0') {
                merror("--uninstall-auth-token needs an argument");
                return 1;
            }
            token = value;
        } else if ((value = uninstall_option_value(argc, argv, &i, "--uninstall-auth-host", &matched)), matched) {
            if (!value || *value == '\0') {
                merror("--uninstall-auth-host needs an argument");
                return 1;
            }
            host = value;
        } else if ((value = uninstall_option_value(argc, argv, &i, "--uninstall-ssl-verify", &matched)), matched) {
            if (!value || *value == '\0' || !strcasecmp(value, "true") || !strcmp(value, "1")) {
                ssl_verify = true;
            } else if (!strcasecmp(value, "false") || !strcmp(value, "0")) {
                ssl_verify = false;
            } else {
                merror("--uninstall-ssl-verify accepts 'true'/'false' or '1'/'0' as arguments");
                return 1;
            }
        } else {
            merror("Unknown option: %s", argv[i]);
            return 1;
        }
    }

    if (!host || (!token && !login)) {
        merror("Uninstallation validation needs --uninstall-auth-host and --uninstall-auth-token or --uninstall-auth-login.");
        return 1;
    }

    /* package_uninstall_validation() returns false when the manager grants the permission. */
    return package_uninstall_validation(token, login, host, ssl_verify) ? 1 : 0;
}
