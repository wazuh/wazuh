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
#include "reenroll_secret.h"

#ifdef WAZUH_UNIT_TESTING
    // Remove static qualifier when unit testing
    #define STATIC
#else
    #define STATIC static
#endif

STATIC char *w_token_bootstrap_read_token(const char *path);
STATIC void w_token_bootstrap_hex(const uint8_t *in, size_t len, char *out);
STATIC int w_token_bootstrap_split_dir_filename(const char *path, char *buf, size_t buf_size,
                                                 const char **filename);
STATIC void w_token_bootstrap_ensure_parent_dir(const char *path, int gid);
#ifndef WIN32
STATIC int w_token_bootstrap_open_and_chown_keys(int gid);
#endif
STATIC void w_token_bootstrap_chown_keys_file(int gid, bool quiet_on_failure);

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
 * @brief Splits @p path into its directory and filename components, using @p buf as backing
 *        storage for the directory (the last '/' is replaced with '\0' in place). Shared by
 *        w_token_bootstrap_ensure_parent_dir() and w_token_bootstrap_open_and_chown_keys() so
 *        this split only has to be kept correct in one place.
 * @param buf Backing storage for the directory component; must be at least @p buf_size bytes
 *        and outlives the string @p filename points into.
 * @param filename When non-NULL, set to the filename component (a pointer into @p buf).
 * @return 0 on success, -1 if @p path has no '/' (errno set to EINVAL).
 */
STATIC int w_token_bootstrap_split_dir_filename(const char *path, char *buf, size_t buf_size,
                                                 const char **filename) {
    char *slash;

    strncpy(buf, path, buf_size - 1);
    buf[buf_size - 1] = '\0';

    if ((slash = strrchr(buf, '/')) == NULL) {
        errno = EINVAL;
        return -1;
    }

    *slash = '\0';

    if (filename != NULL) {
        *filename = slash + 1;
    }

    return 0;
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
 *
 *        Windows has neither half of that reasoning: no privilege drop for the ownership to
 *        survive, and no uid/gid to express it with. The directory is left with what it
 *        inherits from the installation directory, which the installer has already narrowed to
 *        read-and-execute for everyone who is not an administrator -- enough here, since the
 *        anchor is a public certificate and what has to be prevented is replacing it, not
 *        reading it. Only mkdir_ex() runs there, and it still has to: the MSI does not ship a
 *        certs directory either, so TempFile()'s mkstemp() would have nowhere to land.
 */
STATIC void w_token_bootstrap_ensure_parent_dir(const char *path, int gid) {
    char dir[OS_FLSIZE + 1];

#ifdef WIN32
    (void)gid;
#endif

    if (w_token_bootstrap_split_dir_filename(path, dir, sizeof(dir), NULL) != 0) {
        return;
    }

    mkdir_ex(dir);

#ifndef WIN32
    if (chown(dir, 0, gid) != 0) {
        merror("Token bootstrap: could not set ownership of '%s': %s (%d).", dir,
               strerror(errno), errno);
    }

    if (chmod(dir, 0750) == -1) {
        merror("Token bootstrap: could not set permissions on '%s': %s (%d).", dir,
               strerror(errno), errno);
    }
#endif /* !WIN32 */
}

#ifndef WIN32

/**
 * @brief chown()s KEYS_FILE to root:@p gid without following a symlink planted in its parent
 *        directory. Unlike AGENT_ANCHOR_CA's own directory (0750 root:gid), KEYS_FILE lives in
 *        INSTALLDIR/etc, which is 0770 root:wazuh -- the runtime user this chown is trying to
 *        keep out can otherwise replace client.keys with a symlink to an arbitrary root-owned
 *        file (e.g. /etc/shadow) and have this root-privileged call chown() the link's target
 *        instead, handing its own group write/read access to whatever that target is. The open
 *        and vetting (O_NOFOLLOW, regular-file and hard-link checks) is delegated to
 *        w_openat_nofollow_vetted() (file_op.c), the same helper w_fopen_nofollow() and
 *        w_gzopen_nofollow() use, so this hardening logic only has to be kept correct in one
 *        place.
 * @return 0 on success, -1 on error (errno set: from open()/openat(), EINVAL when the resolved
 *         path is not a regular file, or EMLINK when it is a hard-linked one).
 */
STATIC int w_token_bootstrap_open_and_chown_keys(int gid) {
    char dir[OS_FLSIZE + 1];
    const char *filename;
    int fd;
    int saved_errno;

    if (w_token_bootstrap_split_dir_filename(KEYS_FILE, dir, sizeof(dir), &filename) != 0) {
        return -1;
    }

    if ((fd = w_openat_nofollow_vetted(dir, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0)) < 0) {
        return -1;
    }

    if (fchown(fd, 0, gid) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    close(fd);
    return 0;
}

/**
 * @brief w_token_bootstrap_open_and_chown_keys() plus the error log every one of its three call
 *        sites in this file would otherwise have to repeat identically.
 * @param quiet_on_failure When true, a failure is logged at debug level instead of merror(). Set
 *        by the two repair call sites that run on every single boot for as long as the failure's
 *        cause (e.g. a namespaced container without CAP_CHOWN) persists -- an unqualified
 *        merror() there would flood the log forever for a condition that will not self-resolve.
 *        The fresh-enrollment call site passes false: that chown runs once per enrollment, not
 *        once per boot, so a failure there stays a one-time, visible error.
 */
STATIC void w_token_bootstrap_chown_keys_file(int gid, bool quiet_on_failure) {
    if (w_token_bootstrap_open_and_chown_keys(gid) != 0) {
        if (quiet_on_failure) {
            mdebug1("Token bootstrap: could not change ownership of '%s' (will retry on a later "
                    "boot): %s (%d).", KEYS_FILE, strerror(errno), errno);
        } else {
            merror("Token bootstrap: could not change ownership of '%s': %s (%d).", KEYS_FILE,
                   strerror(errno), errno);
        }
    }
}

#else /* WIN32 */

/* Nothing to restore: the Windows agent runs as one service account from start to finish, so
 * client.keys is never written by a user the process later stops being. The symlink hardening
 * above has no Windows counterpart either -- w_openat_nofollow_vetted() is itself POSIX-only
 * (file_op.h). Kept as a real function rather than a macro so the three call sites below read
 * identically on both platforms. */
STATIC void w_token_bootstrap_chown_keys_file(int gid, bool quiet_on_failure) {
    (void)gid;
    (void)quiet_on_failure;
}

#endif /* WIN32 */

/**
 * @brief Documents, not implements, the only reset that works today: a fresh bootstrap only
 *        re-runs once AGENT_ANCHOR_CA is removed, client.keys is emptied or removed, AND a new
 *        enrollment-token file is placed -- each latch (anchor exists / keys non-empty / no
 *        token file) independently blocks it otherwise, so clearing any one or two alone is not
 *        enough. This is today's actual behavior; it has no dedicated interface or name of its
 *        own.
 */
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

    /* Kept for signature symmetry with AgentdStart()'s uid/gid pair (see this function's own
     * doc comment in token_bootstrap.h): neither file this function writes is chowned to it. */
    (void)uid;

#ifdef WIN32
    /* On Windows nothing is chowned at all, so the gid is unused too -- local_start() passes
     * 0/0 because there is no privilege drop for either file to survive. */
    (void)gid;
#endif

    /* Both latches below discard the token on their way out. It is a one-shot credential, and
     * once either of these is true it can never be used again -- but it was only ever deleted
     * on the success path, so a reinstall over an enrolled agent left it sitting at rest
     * indefinitely with nothing left that would consume it. Removing it is not conditional on
     * having used it; it is conditional on it no longer being usable. */
    if (IsFile(AGENT_ANCHOR_CA) == 0) {
        /* Latch: an anchor already on disk means a previous boot already completed the
         * bootstrap. Never re-fetch once one is committed.
         *
         * Also repairs client.keys's group here, not just in the "already enrolled" branch
         * below: enrollment writes client.keys, the anchor is renamed into place, and only then
         * is client.keys chowned (see the final chown's own comment) -- so a crash between the
         * rename and that chown leaves the anchor committed with client.keys still root:root.
         * Every later boot trips this latch and returns before ever reaching the branch below,
         * so this is the only place left that can retry the fix. */
        if (FileSize(KEYS_FILE) > 0) {
            w_token_bootstrap_chown_keys_file(gid, true);
        }

        unlink(AGENT_ENROLLMENT_TOKEN_FILE);
        return 0;
    }

    if (FileSize(KEYS_FILE) > 0) {
        /* Reached when client.keys already has content but no anchor was ever installed -- most
         * often because the agent was enrolled by some means other than this token bootstrap
         * (classic authd, manual registration), but also reachable from a crash inside this very
         * flow: if this function dies after enrollment writes client.keys but before the anchor
         * is renamed into place further down, the next boot lands here too. Either way, repairs
         * client.keys's group defensively, since enrollment.c's own replace has the same
         * group-loss gap (see the final chown's own comment); done unconditionally since it's
         * cheap and idempotent. */
        w_token_bootstrap_chown_keys_file(gid, true);

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

#ifdef WIN32
    /* TempFile() is unusable on Windows: mkstemp() is stubbed out to a constant 0 there
     * (file_op.c), so it creates no file, hands fdopen() what is actually stdin, and returns the
     * template unexpanded -- the enrollment ends up pointed at a literal 'root-ca.pem.XXXXXX'
     * that does not exist. enrollment.c:309 forks for the same reason when it writes
     * client.keys. A fixed sibling name keeps what the temp file was for: the anchor is still
     * committed by the rename below and only after the enrollment succeeded, so a failed
     * bootstrap leaves nothing for the next boot's anchor latch to trip on. The latch also
     * guarantees AGENT_ANCHOR_CA does not exist yet, which is what lets the rename work here --
     * on Windows it would fail over an existing destination. */
    os_strdup(AGENT_ANCHOR_CA ".tmp", anchor_file.name);

    if ((anchor_file.fp = wfopen(anchor_file.name, "w")) == NULL) {
        merror("Token bootstrap: could not create a temporary file for the trust anchor: %s (%d).",
               strerror(errno), errno);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }
#else
    if (TempFile(&anchor_file, AGENT_ANCHOR_CA, 0) < 0) {
        merror("Token bootstrap: could not create a temporary file for the trust anchor: %s (%d).",
               strerror(errno), errno);
        w_etoken_free(&token);
        return -1;
    }
#endif

    /* 0640, not 0644: the anchor is world-readable in neither sense that matters, and the
     * group bit is the whole access the runtime user gets -- read, never write. TempFile()
     * leaves 0600 behind its own umask, so this widens it exactly as far as the drop below
     * needs and no further.
     *
     * Skipped on Windows: there is no drop to widen for, and the file's protection there is
     * the inherited ACL of the directory w_token_bootstrap_ensure_parent_dir() created (see
     * its own comment), not a mode. */
#ifndef WIN32
    if (chmod(anchor_file.name, 0640) == -1) {
        merror("Token bootstrap: could not set permissions on '%s': %s (%d).", anchor_file.name,
               strerror(errno), errno);
        fclose(anchor_file.fp);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }
#endif /* !WIN32 */

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
     * possibly-unrelated password. Nor any credential w_enrollment_build_request() resolved for
     * itself -- its password AND the re-enrollment credential it may have loaded (#39064) are
     * both discarded, and only body_json is taken from it. The token is the only thing that may
     * authenticate this request: it is the one credential the operator handed to this endpoint
     * for this purpose.
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
         * used to log and carry on, which left enroll_kid and enroll_key_hex empty and enrolled
         * anonymously instead -- and against a manager that does not require a password that
         * succeeds, so the agent would be enrolled without the credential the operator issued
         * it, with only a log line to say so. */
        if (w_etoken_derive_key(token.secret, derived_key) != 0) {
            merror("Token bootstrap: could not derive the enrollment token's signing key.");
        } else if ((kid = w_b64url_encode(token.id, W_ETOKEN_ID_BYTES)) == NULL) {
            merror("Token bootstrap: could not encode the enrollment token's identifier.");
        } else {
            strncpy(enroll_request.enroll_kid, kid, sizeof(enroll_request.enroll_kid) - 1);
            os_free(kid);
            w_token_bootstrap_hex(derived_key, sizeof(derived_key), enroll_request.enroll_key_hex);
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

    if (w_enrollment_process_response(&enroll_result, built_request.enroll_kid) != W_ENROLL_OK) {
        /* w_enrollment_process_response() already logged the specific reason. */
        w_enroll_request_destroy(&built_request);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    w_enroll_request_destroy(&built_request);

    /* Written while still root; without fixing the group, the unprivileged `wazuh` user can't
     * read it after AgentdStart()'s privilege drop, breaking the first restart. Fixed up on the
     * temp file, before the rename below: a crash between them would leave AGENT_ANCHOR_CA on
     * disk with the wrong group, and IsFile(AGENT_ANCHOR_CA) == 0 unconditionally latches the
     * bootstrap off on every later boot, so it must land before the rename, never after.
     *
     * Skipped on Windows for the same reason as the mode above: one service account throughout,
     * nothing to hand the file over to. */
#ifndef WIN32
    if (chown(anchor_file.name, 0, gid) != 0) {
        merror("Token bootstrap: could not change ownership of '%s': %s (%d).", anchor_file.name,
               strerror(errno), errno);
    }
#endif

    if (OS_MoveFile(anchor_file.name, AGENT_ANCHOR_CA) < 0) {
        merror("Token bootstrap: could not install the trust anchor at '%s'.", AGENT_ANCHOR_CA);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return -1;
    }

    os_free(anchor_file.name);

    /* enrollment.c's TempFile()+OS_MoveFile() replace only chmod()s client.keys to a fixed 0640
     * on the temp file, never its group, so it inherits this root process's group instead of
     * root:wazuh -- chown to root:gid (not uid:gid, mirroring the anchor's ownership model)
     * restores read access without handing the credential to the runtime user. If this fails
     * (e.g. a namespaced container without CAP_CHOWN), the anchor above is already committed, so
     * client.keys stays root:root here -- but the anchor-latch branch above retries this same
     * chown on every later boot, so this is not a one-shot chance to fix it. A no-op on
     * Windows, where there is no second user to restore access for. */
    w_token_bootstrap_chown_keys_file(gid, false);

    /* The re-enrollment secret (#39064) is written here too, as root, by
     * w_enrollment_process_response() on the way through. Unlike the anchor it also has to be
     * WRITABLE by the unprivileged user afterwards, since every rotation happens in the running
     * daemon after the privilege drop -- a root-owned secret would survive exactly one
     * enrollment and then fail every rotation, with nothing to show for it in a log. FileSize()
     * rather than IsFile() for the same reason client.keys needs it: only a non-empty file is a
     * real store. */
    if (FileSize(AGENT_REENROLL_SECRET) > 0 && chown(AGENT_REENROLL_SECRET, uid, gid) != 0) {
        merror("Token bootstrap: could not change ownership of '%s': %s (%d).",
               AGENT_REENROLL_SECRET, strerror(errno), errno);
    }

    unlink(AGENT_ENROLLMENT_TOKEN_FILE);
    w_etoken_free(&token);
    minfo("Token bootstrap: enrollment succeeded; the manager's CA is now the agent's trust anchor.");

    return 0;
}
