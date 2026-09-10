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
#include "enrollment.h"
#include "reenroll_secret.h"
#include "sec.h"
#include "cJSON.h"
#include "enrollment_token.h"

#include <openssl/crypto.h>

#ifdef WAZUH_UNIT_TESTING
    // Remove static qualifier when unit testing
    #define STATIC

    // Redefine wazuh_version
    #undef __wazuh_version
    #define __wazuh_version "v5.0.0"
#else
    #define STATIC static
#endif

STATIC char *w_enrollment_extract_agent_name(void);
STATIC int w_enrollment_resolve_ip(const char **ip_value);
STATIC char *w_enrollment_load_password(const char *path);
STATIC int w_enrollment_store_key_entry(const char *line);
STATIC int w_enrollment_load_reenroll_credential(w_enroll_request_t *out);

int w_enrollment_build_request(w_enroll_request_t *out) {
    assert(out != NULL);
    out->body_json = NULL;
    out->password = NULL;
    out->enroll_kid = NULL;
    out->enroll_key_hex = NULL;

    char *agent_name = w_enrollment_extract_agent_name();
    if (!agent_name) {
        return -1;
    }

    const char *ip_value = NULL;
    if (w_enrollment_resolve_ip(&ip_value) != 0) {
        if (agent_name != agt->enrollment.agent_name) {
            os_free(agent_name);
        }
        return -1;
    }

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "name", agent_name);
    cJSON_AddStringToObject(body, "version", __wazuh_version);

    if (agt->enrollment.groups) {
        cJSON_AddStringToObject(body, "groups", agt->enrollment.groups);
    }
    if (ip_value) {
        cJSON_AddStringToObject(body, "ip", ip_value);
    }

    /* key_hash (#38465): present only when an entry already exists (a
     * re-enrollment, or an agent that lost the manager's copy but kept its
     * own) -- absent on a genuine first enrollment. Same SHA1(id,name,raw_key)
     * the legacy K:'<hash>' field carried; the manager's force-replace logic
     * (key_mismatch) reads it the same way regardless of wire format. */
    if (keys.keysize > 0 && keys.keyentries && keys.keyentries[0]) {
        os_sha1 hash;
        if (w_get_key_hash(keys.keyentries[0], hash) == OS_SUCCESS) {
            cJSON_AddStringToObject(body, "key_hash", hash);
        }
    }

    char *json_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    if (agent_name != agt->enrollment.agent_name) {
        os_free(agent_name);
    }

    if (!json_str) {
        merror("Failed to build the enrollment request body.");
        return -1;
    }

    out->body_json = json_str;

    /* This agent's own credential first (#39064). Re-read per attempt like the password below,
     * and for the same reason: a rotation replaces the file while the daemon is running. */
    if (w_enrollment_load_reenroll_credential(out) == 1) {
        minfo("Re-enrolling with this agent's own re-enrollment secret.");
        return 0;
    }

    /* Re-read on every attempt (#38465 D6), never cached: rotating
     * etc/authd.pass this way doesn't need an agent restart. */
    out->password = w_enrollment_load_password(agt->enrollment.authorization_pass_path);
    if (out->password) {
        minfo("Using password specified on file: %s", agt->enrollment.authorization_pass_path);
    } else {
        minfo("No authentication password provided");
    }

    return 0;
}

/**
 * @brief Loads the re-enrollment secret and turns it into the `kid` + derived key the transport
 *        mints the bearer from.
 *
 * The `kid` is the agent's own canonical id, taken from the SECRET STORE and not from
 * client.keys: the store is what the manager verifies against, and the case this credential
 * exists for is precisely the one where client.keys is gone. When both exist and disagree, the
 * store wins and the disagreement is logged -- presenting the other id would only ever be
 * refused as `unknown_agent`.
 *
 * Deriving here rather than in the module keeps the label with the credential that chose it: the
 * transport is handed a finished key and a `kid`, and has no notion of which of the two
 * `wazuh-enroll+jwt` credential kinds it is carrying.
 *
 * @param out Receives enroll_kid/enroll_key_hex on success.
 * @return 1 when a credential was loaded, 0 when this agent holds none (never an error: the
 *         normal state of a first enrollment, a legacy install, or a manager that issues none).
 */
STATIC int w_enrollment_load_reenroll_credential(w_enroll_request_t *out) {
    char id[W_REENROLL_ID_SIZE];
    char secret_hex[W_REENROLL_SECRET_SIZE];
    uint8_t secret[W_REENROLL_SECRET_BYTES];
    uint8_t key[W_ETOKEN_KEY_BYTES];
    char key_hex[W_ETOKEN_KEY_BYTES * 2 + 1];
    int result = 0;
    size_t i;

    if (!w_reenroll_secret_load(id, sizeof(id), secret_hex, sizeof(secret_hex))) {
        return 0;
    }

    if (keys.keysize > 0 && keys.keyentries && keys.keyentries[0] && keys.keyentries[0]->id &&
            strcmp(keys.keyentries[0]->id, id) != 0) {
        mwarn("The re-enrollment secret is stored for agent '%s' but client.keys holds '%s'; "
              "re-enrolling as '%s', which is the id the manager verifies the secret against.",
              id, keys.keyentries[0]->id, id);
    }

    /* The store validated the shape on the way out, so this only fails on a hex digit the
     * validator accepts and the decoder does not -- which cannot happen, but is not worth
     * assuming. */
    for (i = 0; i < sizeof(secret); i++) {
        unsigned int byte;

        if (sscanf(secret_hex + (i * 2), "%2x", &byte) != 1) {
            merror("Could not decode the stored re-enrollment secret.");
            goto end;
        }

        secret[i] = (uint8_t)byte;
    }

    if (w_reenroll_derive_key(secret, key) != 0) {
        merror("Could not derive the re-enrollment signing key.");
        goto end;
    }

    for (i = 0; i < sizeof(key); i++) {
        snprintf(key_hex + (i * 2), 3, "%02x", key[i]);
    }

    os_strdup(id, out->enroll_kid);
    os_strdup(key_hex, out->enroll_key_hex);
    result = 1;

end:
    OPENSSL_cleanse(secret_hex, sizeof(secret_hex));
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(key_hex, sizeof(key_hex));

    return result;
}

void w_enroll_request_destroy(w_enroll_request_t *request) {
    if (!request) {
        return;
    }
    os_free(request->body_json);
    os_free(request->password);

    /* Wiped before it is freed: unlike the password (which the agent keeps on disk anyway while
     * it is configured), this is a derived signing key that exists only for the length of one
     * attempt, and leaving it in a freed heap block would outlive the reason it was created. */
    if (request->enroll_key_hex) {
        OPENSSL_cleanse(request->enroll_key_hex, strlen(request->enroll_key_hex));
    }

    os_free(request->enroll_kid);
    os_free(request->enroll_key_hex);
}

w_enroll_status_t w_enrollment_process_response(const hc_enroll_result_t *result) {
    assert(result != NULL);

    if (result->http_code == 0) {
        /* Enrollment is the first thing an agent does, so a misconfigured CA or an
         * unreachable manager surfaces here before anything else. */
        merror("Enrollment request could not be sent: %s.",
               result->transport_error[0] != '\0' ? result->transport_error
                                                 : "transport or configuration error");
        return W_ENROLL_ERR_TRANSPORT;
    }

    if (result->http_code == 200) {
        cJSON *response = cJSON_Parse(result->body);
        if (!response) {
            merror("Enrollment response is not valid JSON.");
            return W_ENROLL_ERR_SERVER;
        }

        cJSON *id = cJSON_GetObjectItem(response, "id");
        cJSON *name = cJSON_GetObjectItem(response, "name");
        cJSON *ip = cJSON_GetObjectItem(response, "ip");
        cJSON *key = cJSON_GetObjectItem(response, "key");
        /* Optional fifth field (#38993): omitted, not empty, when the manager issues none -- an
         * older manager, or a path that does not mint one. */
        cJSON *reenroll_secret = cJSON_GetObjectItem(response, "reenroll_secret");

        if (!cJSON_IsString(id) || !cJSON_IsString(name) || !cJSON_IsString(ip) || !cJSON_IsString(key) ||
                !OS_IsValidID(id->valuestring) || !OS_IsValidName(name->valuestring) ||
                !OS_IsValidIP(ip->valuestring, NULL) || !OS_IsValidName(key->valuestring)) {
            merror("Enrollment response has a missing or invalid field.");
            cJSON_Delete(response);
            return W_ENROLL_ERR_SERVER;
        }

        /* A field that is present but unusable is refused outright, unlike an absent one:
         * accepting the key while dropping the secret is exactly how an agent ends up enrolled
         * but unrecoverable, and the manager has already rotated its own copy by the time it
         * answers, so a secret we cannot store is one nobody holds any more. */
        if (reenroll_secret != NULL &&
                (!cJSON_IsString(reenroll_secret) || !OS_IsValidReenrollSecret(reenroll_secret->valuestring))) {
            merror("Enrollment response carries a malformed re-enrollment secret.");
            cJSON_Delete(response);
            return W_ENROLL_ERR_SERVER;
        }

        /* Before client.keys, never after (#39064). The manager rotated both when it answered, so
         * the only crash window that leaves the agent recoverable is one where the secret landed
         * and the key did not: it re-enrolls with the secret and gets a fresh key. The reverse
         * leaves a usable key and a dead secret, and the next recovery needs an operator. */
        if (reenroll_secret != NULL &&
                w_reenroll_secret_store(id->valuestring, reenroll_secret->valuestring) != 0) {
            /* w_reenroll_secret_store() logged the reason. */
            cJSON_Delete(response);
            return W_ENROLL_ERR_SERVER;
        }

        char line[OS_SIZE_65536 + OS_SIZE_4096];
        snprintf(line, sizeof(line) - 1, "%s %s %s %s", id->valuestring, name->valuestring,
                 ip->valuestring, key->valuestring);
        cJSON_Delete(response);

        if (w_enrollment_store_key_entry(line) != 0) {
            return W_ENROLL_ERR_SERVER;
        }

        minfo("Valid key received");
        return W_ENROLL_OK;
    }

    /* {"error":{"code":N,"message":"..."}} per the #38438 contract -- logged
     * when present, but the status mapping is driven by http_code alone. */
    const char *manager_message = NULL;
    cJSON *error_response = cJSON_Parse(result->body);
    cJSON *error_obj = error_response ? cJSON_GetObjectItem(error_response, "error") : NULL;
    cJSON *message = error_obj ? cJSON_GetObjectItem(error_obj, "message") : NULL;
    manager_message = cJSON_GetStringValue(message);

    w_enroll_status_t status;
    switch (result->http_code) {
        case 400:
            merror("Enrollment rejected by the manager: invalid request.%s%s",
                   manager_message ? " " : "", manager_message ? manager_message : "");
            status = W_ENROLL_ERR_INVALID_REQUEST;
            break;
        case 401:
            merror("Enrollment rejected by the manager: invalid or missing authentication.%s%s",
                   manager_message ? " " : "", manager_message ? manager_message : "");
            status = W_ENROLL_ERR_AUTH;
            break;
        case 403:
            /* Administratively disabled, not a transport hiccup -- the
             * caller must not blind-retry this the same way (#38465 R12). */
            minfo("Enrollment is disabled on the manager.%s%s", manager_message ? " " : "",
                  manager_message ? manager_message : "");
            status = W_ENROLL_ERR_DISABLED;
            break;
        case 409:
            merror("Enrollment rejected by the manager: duplicate agent.%s%s",
                   manager_message ? " " : "", manager_message ? manager_message : "");
            status = W_ENROLL_ERR_DUPLICATE;
            break;
        default:
            merror("Enrollment failed with unexpected HTTP status %ld.%s%s", result->http_code,
                   manager_message ? " " : "", manager_message ? manager_message : "");
            status = W_ENROLL_ERR_SERVER;
            break;
    }

    if (error_response) {
        cJSON_Delete(error_response);
    }

    return status;
}

/**
 * @brief Resolves the agent name for the enrollment request: the configured
 *        <agent_name>, or the local hostname when unset.
 * @return A pointer the caller must free UNLESS it equals agt->enrollment.agent_name
 *         (a borrowed, configured value) -- mirrors the legacy
 *         w_enrollment_extract_agent_name()'s ownership convention.
 */
STATIC char *w_enrollment_extract_agent_name(void) {
    char *agent_name = NULL;

    if (agt->enrollment.agent_name == NULL) {
        os_malloc(513, agent_name);
        agent_name[512] = '\0';
        if (gethostname(agent_name, 512 - 1) != 0) {
            merror("Unable to extract hostname. Custom agent name not set.");
            os_free(agent_name);
            return NULL;
        }
        OS_ConvertToValidAgentName(agent_name);
    } else {
        agent_name = agt->enrollment.agent_name;
    }

    if (!OS_IsValidName(agent_name)) {
        merror("Invalid agent name \"%s\". Please pick a valid name.", agent_name);
        if (agent_name != agt->enrollment.agent_name) {
            os_free(agent_name);
        }
        return NULL;
    }

    return agent_name;
}

/**
 * @brief Resolves the "ip" body field per #38465's 3-case mapping of the
 *        legacy IP:'...' field:
 *        - agent_address configured (and use_source_ip=no) -> the explicit IP.
 *        - use_source_ip=yes (no agent_address) -> the literal "src" (a plain
 *          string value, same sentinel the legacy wire protocol used -- no
 *          special contract support needed, confirmed with the server team).
 *        - neither configured (default) -> *ip_value left NULL: the field is
 *          omitted and the manager decides via its own config, same as today.
 * @return 0 on success; -1 on an invalid/incompatible configuration (nothing sent).
 */
STATIC int w_enrollment_resolve_ip(const char **ip_value) {
    *ip_value = NULL;

    if (agt->enrollment.agent_address && agt->enrollment.use_source_ip) {
        merror("Incompatible agent_address/use_source_ip options: forcing an IP "
               "while also requesting the connection's source IP.");
        return -1;
    }

    if (agt->enrollment.agent_address) {
        if (!OS_IsValidIP(agt->enrollment.agent_address, NULL)) {
            merror("Invalid IP address provided for agent_address.");
            return -1;
        }
        *ip_value = agt->enrollment.agent_address;
    } else if (agt->enrollment.use_source_ip) {
        *ip_value = "src";
    }

    return 0;
}

/**
 * @brief Loads the enrollment password from `path`, re-read on every call
 *        (#38465 D6: no caching, so rotating the file needs no restart).
 * @return A newly allocated password, or NULL when the file is missing/empty
 *         (mTLS/open mode -- not an error).
 */
STATIC char *w_enrollment_load_password(const char *path) {
    if (!path) {
        return NULL;
    }

    FILE *fp = wfopen(path, "r");
    if (!fp) {
        return NULL;
    }

    char buf[4096];
    char *read_ok = fgets(buf, sizeof(buf) - 1, fp);
    fclose(fp);

    if (!read_ok || strlen(buf) <= 2) {
        return NULL;
    }

    if (buf[strlen(buf) - 1] == '\n') {
        buf[strlen(buf) - 1] = '\0';
    }

    char *password;
    os_strdup(buf, password);
    return password;
}

/**
 * @brief Stores one "ID NAME IP KEY" line to client.keys.
 *
 * Platform split preserved verbatim from the legacy
 * enrollment_op.c:w_enrollment_store_key_entry() (#38465 -- do not unify):
 * Linux writes atomically (temp file + chmod 0640 + rename); Windows writes
 * the file directly, without atomicity.
 */
STATIC int w_enrollment_store_key_entry(const char *line) {
    assert(line != NULL);

#ifdef WIN32
    FILE *fp = wfopen(KEYS_FILE, "w");

    if (!fp) {
        merror(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
        return -1;
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);

#else /* !WIN32 */
    File file;

    if (TempFile(&file, KEYS_FILE, 0) < 0) {
        merror(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
        return -1;
    }

    if (chmod(file.name, 0640) == -1) {
        merror(CHMOD_ERROR, file.name, errno, strerror(errno));
        fclose(file.fp);
        unlink(file.name);
        os_free(file.name);
        return -1;
    }

    fprintf(file.fp, "%s\n", line);
    fclose(file.fp);

    if (OS_MoveFile(file.name, KEYS_FILE) < 0) {
        os_free(file.name);
        return -1;
    }
    os_free(file.name);

#endif /* !WIN32 */

    return 0;
}
