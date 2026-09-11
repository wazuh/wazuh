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
#include "token_bootstrap.h"
#include "enrollment.h"
#include "enrollment_token.h"

#ifdef WIN32

/* Windows has no privilege-drop step in this codebase, so there is no safe point to fix up
 * ownership of files written here while still elevated -- left unwired on Windows for now, an
 * explicit scope decision (see token_bootstrap.h's own doc comment). */
int w_agent_token_bootstrap(int uid, int gid) {
    (void)uid;
    (void)gid;
    return 0;
}

#else /* !WIN32 */

#ifdef WAZUH_UNIT_TESTING
    // Remove static qualifier when unit testing
    #define STATIC
#else
    #define STATIC static
#endif

STATIC char *w_token_bootstrap_read_token(const char *path);
STATIC void w_token_bootstrap_hex(const uint8_t *in, size_t len, char *out);
STATIC void w_token_bootstrap_ensure_parent_dir(const char *path, int gid);

/**
 * @brief Reads the one-shot enrollment token file, mirroring
 *        w_enrollment_load_password()'s fopen/fgets read style (enrollment.c), sized for a
 *        token instead of a short password.
 * @return A newly allocated, trimmed copy of the file's first line, or NULL when the file is
 *         missing, empty, or unreadable.
 */
STATIC char *w_token_bootstrap_read_token(const char *path) {
    FILE *fp = wfopen(path, "r");

    if (!fp) {
        return NULL;
    }

    char buf[W_ETOKEN_MAX_FILE_BYTES];
    char *read_ok = fgets(buf, sizeof(buf) - 1, fp);
    fclose(fp);

    if (!read_ok) {
        return NULL;
    }

    size_t len = strlen(buf);

    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    if (len == 0) {
        return NULL;
    }

    char *token;
    os_strdup(buf, token);
    return token;
}

/* Lowercase hexadecimal of a byte string. `out` needs 2 * len + 1 bytes. Not worth pulling in a
 * shared helper for: enrollment_token.c has an identical static one of its own, scoped the same
 * way. */
STATIC void w_token_bootstrap_hex(const uint8_t *in, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0F];
    }

    out[len * 2] = '\0';
}

/**
 * @brief Ensures the directory holding @p path exists, creating it (and any of its own missing
 *        ancestors) if not -- mkdir_ex() creates @a path itself as a directory too, not just its
 *        ancestors, so this trims the final ('/'-separated) component off first. Needed because
 *        AGENT_ANCHOR_CA's directory (etc/certs) is created only by the manager's own installer,
 *        never the agent's (see its own doc comment in defs.h): a stock agent install has no
 *        such directory yet, and TempFile()'s mkstemp() needs it to already exist.
 *
 *        Left 0750 root:@p gid. mkdir_ex() creates it 0770 owned by whoever is running, which
 *        here is root -- and a root:root directory cannot be searched by the unprivileged user
 *        after the privilege drop, so the anchor inside becomes unopenable however permissive
 *        its own mode is, and the agent refuses to start on the next boot over a CA file that
 *        is sitting right there. Group-read rather than group-write for the same reason the
 *        anchor itself is not writable by the runtime user: nothing that runs as that user has
 *        any business replacing the certificate authority it verifies its manager against.
 */
STATIC void w_token_bootstrap_ensure_parent_dir(const char *path, int gid) {
    char dir[OS_FLSIZE + 1];
    char *slash;

    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';

    if ((slash = strrchr(dir, '/')) != NULL) {
        *slash = '\0';
        mkdir_ex(dir);

        if (chown(dir, 0, gid) != 0) {
            merror("Token bootstrap: could not set ownership of '%s': %s (%d).", dir,
                   strerror(errno), errno);
        }

        if (chmod(dir, 0750) == -1) {
            merror("Token bootstrap: could not set permissions on '%s': %s (%d).", dir,
                   strerror(errno), errno);
        }
    }
}

int w_agent_token_bootstrap(int uid, int gid) {
    w_etoken_t token;
    char *token_text = NULL;
    w_etoken_error_t decode_err;
    char host[HC_MAX_HOST] = {0};
    char endpoint[HC_MAX_ENDPOINT] = {0};
    int port = 0;
    bool port_present = false;
    uint32_t scope_id = 0;
    const char *candidate_pem = NULL;
    size_t candidate_len = 0;
    hc_cacerts_result_t fetch_result;
    /* The pin-matched certificate on its own, extracted from the fetched bundle. Sized like the
     * body it comes out of, which one certificate can never exceed. */
    char pinned_pem[HC_MAX_CACERTS_BODY] = {0};
    File anchor_file = {NULL, NULL};
    w_enroll_request_t built_request = {NULL, NULL};
    hc_config_t enroll_config;
    hc_enroll_request_t enroll_request;
    hc_enroll_result_t enroll_result;

    /* Both latches below discard the token on their way out. It is a one-shot credential, and
     * once either of these is true it can never be used again -- but it was only ever deleted
     * on the success path, so a reinstall over an enrolled agent left it sitting at rest
     * indefinitely with nothing left that would consume it. Removing it is not conditional on
     * having used it; it is conditional on it no longer being usable. */
    if (IsFile(AGENT_ANCHOR_CA) == 0) {
        /* Latch: an anchor already on disk means a previous boot already completed the
         * bootstrap. Never re-fetch once one is committed. */
        unlink(AGENT_ENROLLMENT_TOKEN_FILE);
        return 0;
    }

    if (FileSize(KEYS_FILE) > 0) {
        /* Already enrolled: nothing left to do. IsFile() alone can't tell this apart from
         * the empty placeholder client.keys the package installs by default -- only a
         * non-empty file means a real ID/NAME/IP/KEY entry exists. */
        unlink(AGENT_ENROLLMENT_TOKEN_FILE);
        return 0;
    }

    if (IsFile(AGENT_ENROLLMENT_TOKEN_FILE) != 0) {
        /* Legacy install, no token provided: not an error. */
        return 0;
    }

    if ((token_text = w_token_bootstrap_read_token(AGENT_ENROLLMENT_TOKEN_FILE)) == NULL) {
        merror("Token bootstrap: could not read the enrollment token file '%s'.",
               AGENT_ENROLLMENT_TOKEN_FILE);
        return -1;
    }

    decode_err = w_etoken_decode(token_text, &token);
    os_free(token_text);

    if (decode_err != ETOKEN_OK) {
        merror("Token bootstrap: could not decode the enrollment token: %s.",
               w_etoken_strerror(decode_err));
        return -1;
    }

    if (w_parse_agent_endpoint(token.adr, host, sizeof(host), &port, &port_present, endpoint,
                               sizeof(endpoint), &scope_id) != 0) {
        merror("Token bootstrap: the enrollment token's address is invalid.");
        w_etoken_free(&token);
        return -1;
    }

    memset(&fetch_result, 0, sizeof(fetch_result));

    if (token.has_pin) {
        hc_config_t fetch_config;
        hc_cacerts_request_t fetch_request;
        char *pin_b64 = NULL;
        bool fetched;

        memset(&fetch_config, 0, sizeof(fetch_config));
        strncpy(fetch_config.server_host, host, sizeof(fetch_config.server_host) - 1);
        fetch_config.server_port = (uint16_t)port;
        fetch_config.server_scope_id = scope_id;
        strncpy(fetch_config.server_endpoint, endpoint, sizeof(fetch_config.server_endpoint) - 1);

        memset(&fetch_request, 0, sizeof(fetch_request));
        fetch_request.log = mtLoggingFunctionsWrapper;

        fetched = hc_fetch_cacerts(&fetch_config, &fetch_request, &fetch_result);

        if (!fetched || fetch_result.http_code != 200) {
            if (fetch_result.http_code != 0) {
                merror("Token bootstrap: fetching /cacerts from the manager failed: manager "
                       "returned HTTP %ld instead of 200%s%s.", fetch_result.http_code,
                       fetch_result.transport_error[0] != '\0' ? ": " : "",
                       fetch_result.transport_error[0] != '\0' ? fetch_result.transport_error : "");
            } else {
                merror("Token bootstrap: fetching /cacerts from the manager failed%s%s.",
                       fetch_result.transport_error[0] != '\0' ? ": " : "",
                       fetch_result.transport_error[0] != '\0' ? fetch_result.transport_error : "");
            }

            w_etoken_free(&token);
            return -1;
        }

        /* Checked before the pin compare, which cannot tell the two apart: a certificate cut
         * off by this buffer hashes to nothing the token names, and would be reported as a
         * mismatch -- the message that says an attacker may be answering. A body this end
         * could not hold is our limit, not the manager's identity. */
        if (fetch_result.body_truncated) {
            merror("Token bootstrap: the manager's /cacerts response is larger than the %d bytes "
                   "this agent can read, so it cannot be checked against the enrollment token's "
                   "pin.", HC_MAX_CACERTS_BODY);
            w_etoken_free(&token);
            return -1;
        }

        if ((pin_b64 = w_b64url_encode(token.pin, W_ETOKEN_PIN_BYTES)) == NULL) {
            merror("Token bootstrap: could not encode the enrollment token's pin.");
            w_etoken_free(&token);
            return -1;
        }

        candidate_len = strnlen(fetch_result.body, sizeof(fetch_result.body));

        /* Only the certificate the pin actually named becomes the anchor -- never the body it
         * arrived in. That body came over a connection nothing had verified yet, so anything
         * else in it was chosen by whoever answered: a bundle of [attacker CA, genuine CA]
         * satisfies the pin on its genuine half, and installing the whole thing would make the
         * attacker's half a trust anchor too, which the verified reconnect would then happily
         * accept a chain against. */
        if (!hc_spki_pinned_certificate(fetch_result.body, candidate_len, pin_b64, pinned_pem,
                                        sizeof(pinned_pem))) {
            merror("Token bootstrap: fetched CA does not match the enrollment token's pin -- "
                   "refusing to trust it.");
            os_free(pin_b64);
            w_etoken_free(&token);
            return -1;
        }

        os_free(pin_b64);
        candidate_pem = pinned_pem;
        candidate_len = strlen(pinned_pem);
    } else {
        candidate_pem = token.ca_pem;
        candidate_len = strlen(token.ca_pem);
    }

    /* etc/certs doesn't exist on a stock install; see w_token_bootstrap_ensure_parent_dir(). */
    w_token_bootstrap_ensure_parent_dir(AGENT_ANCHOR_CA, gid);

    if (TempFile(&anchor_file, AGENT_ANCHOR_CA, 0) < 0) {
        merror("Token bootstrap: could not create a temporary file for the trust anchor: %s (%d).",
               strerror(errno), errno);
        w_etoken_free(&token);
        return -1;
    }

    /* 0640, not 0644: the anchor is world-readable in neither sense that matters, and the
     * group bit is the whole access the runtime user gets -- read, never write. TempFile()
     * leaves 0600 behind its own umask, so this widens it exactly as far as the drop below
     * needs and no further. */
    if (chmod(anchor_file.name, 0640) == -1) {
        merror("Token bootstrap: could not set permissions on '%s': %s (%d).", anchor_file.name,
               strerror(errno), errno);
        fclose(anchor_file.fp);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    if (fwrite(candidate_pem, 1, candidate_len, anchor_file.fp) != candidate_len) {
        merror("Token bootstrap: could not write the trust anchor to '%s'.", anchor_file.name);
        fclose(anchor_file.fp);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    fclose(anchor_file.fp);

    if (w_enrollment_build_request(&built_request) != 0) {
        /* w_enrollment_build_request() already logged the specific reason. */
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    memset(&enroll_config, 0, sizeof(enroll_config));
    strncpy(enroll_config.server_host, host, sizeof(enroll_config.server_host) - 1);
    enroll_config.server_port = (uint16_t)port;
    enroll_config.server_scope_id = scope_id;
    strncpy(enroll_config.server_endpoint, endpoint, sizeof(enroll_config.server_endpoint) - 1);
    enroll_config.verify_mode = HC_VERIFY_FULL;
    strncpy(enroll_config.ca_path, anchor_file.name, sizeof(enroll_config.ca_path) - 1);

    memset(&enroll_request, 0, sizeof(enroll_request));
    strncpy(enroll_request.body_json, built_request.body_json, sizeof(enroll_request.body_json) - 1);
    enroll_request.log = mtLoggingFunctionsWrapper;
    /* Never the configured authd.pass here: a token-based enrollment must not sign with a
     * possibly-unrelated password (built_request.password is discarded below, unused).
     *
     * A credential-less token (token.has_key == false) does NOT fall back to
     * WAZUH_REGISTRATION_PASSWORD/authd.pass either -- enrollment goes out with no credential
     * at all. Confirmed against the manager's own EnrollmentAuthenticator
     * (remoted/remoted_module/src/enrollment/enrollmentAuthenticator.hpp on
     * enhancement/38991-identity): it has no notion of a "credential-less token" distinct from
     * "no credential presented" -- sending no Authorization header falls through to whatever
     * requirePassword is already configured, exactly like a classic no-password attempt.
     * Silently reusing a configured password here would misrepresent to the manager (and any
     * audit trail) what actually authenticated the request. */

    if (token.has_key) {
        uint8_t derived_key[W_ETOKEN_KEY_BYTES];
        char *kid = NULL;
        bool credential_ready = false;

        /* A credential the token carries but the agent cannot prepare aborts the bootstrap. It
         * used to log and carry on, which left token_kid and token_key_hex empty and enrolled
         * anonymously instead -- and against a manager that does not require a password that
         * succeeds, so the agent would be enrolled without the credential the operator issued
         * it, with only a log line to say so. */
        if (w_etoken_derive_key(token.secret, derived_key) != 0) {
            merror("Token bootstrap: could not derive the enrollment token's signing key.");
        } else if ((kid = w_b64url_encode(token.id, W_ETOKEN_ID_BYTES)) == NULL) {
            merror("Token bootstrap: could not encode the enrollment token's identifier.");
        } else {
            strncpy(enroll_request.token_kid, kid, sizeof(enroll_request.token_kid) - 1);
            os_free(kid);
            w_token_bootstrap_hex(derived_key, sizeof(derived_key), enroll_request.token_key_hex);
            credential_ready = true;
        }

        memset(derived_key, 0, sizeof(derived_key));

        if (!credential_ready) {
            w_enroll_request_destroy(&built_request);
            unlink(anchor_file.name);
            os_free(anchor_file.name);
            w_etoken_free(&token);
            return -1;
        }
    }

    memset(&enroll_result, 0, sizeof(enroll_result));

    if (!hc_enroll(&enroll_config, &enroll_request, &enroll_result) || enroll_result.http_code == 0) {
        merror("Token bootstrap: the verified enrollment request could not be sent%s%s.",
               enroll_result.transport_error[0] != '\0' ? ": " : "",
               enroll_result.transport_error[0] != '\0' ? enroll_result.transport_error : "");
        w_enroll_request_destroy(&built_request);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    if (w_enrollment_process_response(&enroll_result) != W_ENROLL_OK) {
        /* w_enrollment_process_response() already logged the specific reason. */
        w_enroll_request_destroy(&built_request);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    w_enroll_request_destroy(&built_request);

    if (OS_MoveFile(anchor_file.name, AGENT_ANCHOR_CA) < 0) {
        merror("Token bootstrap: could not install the trust anchor at '%s'.", AGENT_ANCHOR_CA);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    os_free(anchor_file.name);

    /* Both files were just written while still root (this runs before Privsep_SetGroup()/
     * Privsep_SetUser() in AgentdStart()): without this, they are unreadable by the
     * unprivileged user once the process drops privileges, silently breaking the very first
     * restart after a successful bootstrap. Logged, not fatal: the anchor and the enrollment
     * already succeeded.
     *
     * The anchor keeps root as its owner and only hands the group across, so the user the
     * agent runs as can read the certificate authority it verifies the manager against but
     * cannot rewrite it -- otherwise anything that took over that user could point the agent
     * at a manager of its own choosing. client.keys is deliberately different: it is the
     * agent's own credential, the runtime user rewrites it on every re-enrollment, and the
     * installer already creates it owned by that user. */
    if (chown(AGENT_ANCHOR_CA, 0, gid) != 0) {
        merror("Token bootstrap: could not change ownership of '%s': %s (%d).", AGENT_ANCHOR_CA,
               strerror(errno), errno);
    }

    if (chown(KEYS_FILE, uid, gid) != 0) {
        merror("Token bootstrap: could not change ownership of '%s': %s (%d).", KEYS_FILE,
               strerror(errno), errno);
    }

    unlink(AGENT_ENROLLMENT_TOKEN_FILE);
    w_etoken_free(&token);
    minfo("Token bootstrap: enrollment succeeded; the manager's CA is now the agent's trust anchor.");

    return 0;
}

#endif /* WIN32 */
