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
STATIC int w_token_bootstrap_split_dir_filename(const char *path, char *buf, size_t buf_size,
                                                 const char **filename);
STATIC void w_token_bootstrap_ensure_parent_dir(const char *path, int gid);
STATIC void w_token_bootstrap_mark_anchor_committed(int gid);
#ifndef WIN32
STATIC int w_token_bootstrap_open_and_chown(const char *path, uid_t owner, gid_t group);
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
 *        Left 01770 root:@p gid. mkdir_ex() creates it 0770 owned by whoever is running, which
 *        here is root -- and a root:root directory cannot be searched by the unprivileged user
 *        after the privilege drop, so the anchor inside becomes unopenable however permissive
 *        its own mode is, and the agent refuses to start on the next boot over a CA file that
 *        is sitting right there.
 *
 *        This was 0750 until #39321, on the reasoning that nothing running as the runtime user
 *        has any business replacing the CA it verifies its manager against. That is no longer
 *        true of the agent itself: a CA rotation is published by the manager and adopted by the
 *        agent, which is unprivileged by the time it adopts anything, so it must be able to
 *        replace this file. Group write is what rename(2) needs -- it never consults the target
 *        file's own mode, only the directory's -- and it is the same permission that already
 *        lets the runtime user replace a root-owned etc/client.keys, the more sensitive of the
 *        two files by some distance.
 *
 *        The sticky bit is what keeps the grant no wider than that. It restricts unlink and
 *        rename-over to the owner of the file, so the agent can replace the anchor it owns and
 *        still cannot touch anything root-owned in the same directory. Plain 0770 would hand it
 *        the whole directory. The manager's own etc/certs is 01770 for the same reason
 *        (inst-functions.sh, SetIndexerCertsOwnership).
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

    /* 01770, not 0750: the agent replaces this anchor at runtime when the manager publishes a new
     * CA bundle (#39321), and it is the unprivileged `wazuh` user by then. rename(2) never
     * consults the target file's own mode -- replacing a file is an operation on the directory
     * entry -- so group write here is the whole permission that refresh needs, exactly as it is
     * what already lets the runtime user replace a root-owned etc/client.keys.
     *
     * The sticky bit is what keeps that from being a wider grant than intended: it restricts
     * unlink and rename-over to the owner of the file, so the agent can replace its own anchor
     * and still cannot touch anything root-owned that shares this directory -- the marker this
     * bootstrap writes beside the anchor among them. Same shape the manager already uses for its
     * own etc/certs (inst-functions.sh, SetIndexerCertsOwnership). */
    if (chmod(dir, 01770) == -1) {
        merror("Token bootstrap: could not set permissions on '%s': %s (%d).", dir,
               strerror(errno), errno);
    }
#endif /* !WIN32 */
}

#ifndef WIN32

/**
 * @brief chown()s @p path to @p owner:@p group without following a symlink planted in its parent
 *        directory. Both files this is used for live in INSTALLDIR/etc, which is 0770 root:wazuh
 *        -- unlike AGENT_ANCHOR_CA's own directory (0750 root:gid), the runtime user can create
 *        entries there. So it can replace the target with a symlink to an arbitrary root-owned
 *        file (e.g. /etc/shadow) and have this root-privileged call chown() the link's target
 *        instead, handing its own group -- or, where @p owner is that user, itself outright --
 *        access to whatever that target is. The open and vetting (O_NOFOLLOW, regular-file and
 *        hard-link checks) is delegated to w_openat_nofollow_vetted() (file_op.c), the same
 *        helper w_fopen_nofollow() and w_gzopen_nofollow() use, so this hardening logic only has
 *        to be kept correct in one place.
 * @return 0 on success, -1 on error (errno set: from open()/openat(), EINVAL when the resolved
 *         path is not a regular file, or EMLINK when it is a hard-linked one).
 */
STATIC int w_token_bootstrap_open_and_chown(const char *path, uid_t owner, gid_t group) {
    char dir[OS_FLSIZE + 1];
    const char *filename;
    int fd;
    int saved_errno;

    if (w_token_bootstrap_split_dir_filename(path, dir, sizeof(dir), &filename) != 0) {
        return -1;
    }

    if ((fd = w_openat_nofollow_vetted(dir, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0)) < 0) {
        return -1;
    }

    if (fchown(fd, owner, group) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    close(fd);
    return 0;
}

/**
 * @brief w_token_bootstrap_open_and_chown() for KEYS_FILE, to root:@p gid. Named so the three
 *        client.keys call sites read as one operation rather than repeating the owner pair.
 * @return 0 on success, -1 on error (errno set as w_token_bootstrap_open_and_chown()).
 */
STATIC int w_token_bootstrap_open_and_chown_keys(int gid) {
    return w_token_bootstrap_open_and_chown(KEYS_FILE, 0, (gid_t) gid);
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
/**
 * @brief Records that this install has committed a trust anchor, by creating AGENT_ANCHOR_MARKER
 *        if it is not already there.
 *
 * Root-owned 0640 in a sticky etc/certs, so the runtime user cannot remove it even though it
 * owns the anchor beside it. Only existence matters, so the file is left empty and an existing
 * one is never rewritten.
 *
 * Best effort: a marker that could not be written costs the deletion guard in
 * w_agent_validate_ssl_ca(), not the bootstrap, so a failure is logged and swallowed. Called
 * both after a fresh commit and from the latch, so an install that predates #39321 -- or one
 * whose marker write failed once -- picks one up on a later boot.
 */
STATIC void w_token_bootstrap_mark_anchor_committed(int gid) {
    int fd;

    if (IsFile(AGENT_ANCHOR_MARKER) == 0) {
        return;
    }

    if (fd = open(AGENT_ANCHOR_MARKER, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0640), fd < 0) {
        /* EEXIST is the benign race of two starts at once, not a problem worth a line. */
        if (errno != EEXIST) {
            mdebug1("Token bootstrap: could not write '%s': %s (%d).", AGENT_ANCHOR_MARKER,
                    strerror(errno), errno);
        }

        return;
    }

#ifndef WIN32
    if (fchown(fd, 0, gid) != 0) {
        mdebug1("Token bootstrap: could not set ownership of '%s': %s (%d).", AGENT_ANCHOR_MARKER,
                strerror(errno), errno);
    }
#else
    /* No second user to hand it to: the installation directory's own ACL already keeps
     * non-administrators out of certs\\, which is the whole protection the marker needs. */
    (void)gid;
#endif

    close(fd);
}

#ifndef WIN32

/**
 * @brief Brings an anchor committed before #39321 up to the permissions the runtime refresh
 *        needs: etc/certs 01770 root:@p gid and the anchor itself @p uid:@p gid.
 *
 * An agent that bootstrapped under the old scheme has a 0750 directory and a root-owned anchor,
 * and would silently never be able to adopt a published CA bundle -- the refresh would fail at
 * mkstemp() on every attempt, which reads as a manager problem rather than a local one. Runs on
 * every boot that trips the anchor latch, while still root, so an upgrade fixes itself.
 *
 * The mode is left alone; only ownership and the directory bits move. Idempotent, and quiet
 * about a chown that fails in a namespaced container without CAP_CHOWN -- the agent still works,
 * it just cannot refresh, and the refresh path logs that for itself when it tries.
 */
STATIC void w_token_bootstrap_repair_anchor_ownership(int uid, int gid) {
    char dir[OS_FLSIZE + 1];

    if (chown(AGENT_ANCHOR_CA, uid, gid) != 0) {
        mdebug1("Token bootstrap: could not repair ownership of '%s': %s (%d).", AGENT_ANCHOR_CA,
                strerror(errno), errno);
    }

    if (w_token_bootstrap_split_dir_filename(AGENT_ANCHOR_CA, dir, sizeof(dir), NULL) != 0) {
        return;
    }

    if (chown(dir, 0, gid) != 0) {
        mdebug1("Token bootstrap: could not repair ownership of '%s': %s (%d).", dir,
                strerror(errno), errno);
    }

    if (chmod(dir, 01770) == -1) {
        mdebug1("Token bootstrap: could not repair permissions on '%s': %s (%d).", dir,
                strerror(errno), errno);
    }

    /* Last, so the marker only appears once the directory can actually hold it root-owned. */
    w_token_bootstrap_mark_anchor_committed(gid);
}

#endif /* !WIN32 */

w_token_bootstrap_result_t w_agent_token_bootstrap(int uid, int gid) {
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


#ifdef WIN32
    /* On Windows nothing is chowned at all, so both are unused -- local_start() passes 0/0
     * because there is no privilege drop for either file to survive. */
    (void)uid;
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

#ifndef WIN32
        /* Same idea for the anchor itself: an agent that bootstrapped before #39321 holds a
         * root-owned anchor under a 0750 directory and could never adopt a published CA bundle.
         * Repaired here rather than at the write below, because an existing install never
         * reaches the write again. */
        w_token_bootstrap_repair_anchor_ownership(uid, gid);
#endif

        unlink(AGENT_ENROLLMENT_TOKEN_FILE);
        return W_TOKEN_BOOTSTRAP_DONE;
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
        return W_TOKEN_BOOTSTRAP_DONE;
    }

    if (IsFile(AGENT_ENROLLMENT_TOKEN_FILE) != 0) {
        /* Legacy install, no token provided: not an error. */
        return W_TOKEN_BOOTSTRAP_DONE;
    }

    if ((token_text = w_token_bootstrap_read_token(AGENT_ENROLLMENT_TOKEN_FILE)) == NULL) {
        merror("Token bootstrap: could not read the enrollment token file '%s'.",
               AGENT_ENROLLMENT_TOKEN_FILE);
        return W_TOKEN_BOOTSTRAP_PERMANENT;
    }

    decode_err = w_etoken_decode(token_text, &token);
    os_free(token_text);

    if (decode_err != ETOKEN_OK) {
        merror("Token bootstrap: could not decode the enrollment token: %s.",
               w_etoken_strerror(decode_err));
        return W_TOKEN_BOOTSTRAP_PERMANENT;
    }

    if (w_parse_agent_endpoint(token.adr, host, sizeof(host), &port, &port_present, endpoint,
                               sizeof(endpoint), &scope_id) != 0) {
        merror("Token bootstrap: the enrollment token's address is invalid.");
        w_etoken_free(&token);
        return W_TOKEN_BOOTSTRAP_PERMANENT;
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
            /* The four-way /cacerts taxonomy (#39062): each cause gets its own greppable name,
             * so a misprovisioned manager (ca_mismatch) is never read as the one abort that
             * actually is hostile (a pin mismatch, logged separately below once a body is in
             * hand to compare). adr_unreachable and ca_mismatch may clear on their own (no
             * response at all, or a 5xx); not_found is the manager's settled answer -- it has
             * no CA to serve, provisioned or not, and repeating the request cannot change that. */
            w_token_bootstrap_result_t fetch_class;

            if (fetch_result.http_code == 0) {
                fetch_class = W_TOKEN_BOOTSTRAP_TRANSIENT;
                merror("Token bootstrap: /cacerts adr_unreachable -- could not reach the "
                       "manager to fetch the certificate authority%s%s.",
                       fetch_result.transport_error[0] != '\0' ? ": " : "",
                       fetch_result.transport_error[0] != '\0' ? fetch_result.transport_error : "");
            } else if (fetch_result.http_code == 404) {
                fetch_class = W_TOKEN_BOOTSTRAP_PERMANENT;
                merror("Token bootstrap: /cacerts not_found -- the manager has no certificate "
                       "authority configured (it may predate this feature).");
            } else if (fetch_result.http_code == 503) {
                fetch_class = W_TOKEN_BOOTSTRAP_TRANSIENT;
                merror("Token bootstrap: /cacerts ca_mismatch -- the manager's configured "
                       "certificate authority does not sign its own listener certificate "
                       "(misprovisioned, not necessarily hostile).");
            } else {
                fetch_class = (fetch_result.http_code >= 500) ? W_TOKEN_BOOTSTRAP_TRANSIENT
                                                               : W_TOKEN_BOOTSTRAP_PERMANENT;
                merror("Token bootstrap: fetching /cacerts from the manager failed: manager "
                       "returned HTTP %ld instead of 200%s%s.", fetch_result.http_code,
                       fetch_result.transport_error[0] != '\0' ? ": " : "",
                       fetch_result.transport_error[0] != '\0' ? fetch_result.transport_error : "");
            }

            w_etoken_free(&token);
            return fetch_class;
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
            return W_TOKEN_BOOTSTRAP_PERMANENT;
        }

        if ((pin_b64 = w_b64url_encode(token.pin, W_ETOKEN_PIN_BYTES)) == NULL) {
            merror("Token bootstrap: could not encode the enrollment token's pin.");
            w_etoken_free(&token);
            return W_TOKEN_BOOTSTRAP_PERMANENT;
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
            merror("Token bootstrap: pin_mismatch -- fetched CA does not match the enrollment "
                   "token's pin, refusing to trust it.");
            os_free(pin_b64);
            w_etoken_free(&token);
            return W_TOKEN_BOOTSTRAP_PERMANENT;
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
        return W_TOKEN_BOOTSTRAP_PERMANENT;
    }
#else
    if (TempFile(&anchor_file, AGENT_ANCHOR_CA, 0) < 0) {
        merror("Token bootstrap: could not create a temporary file for the trust anchor: %s (%d).",
               strerror(errno), errno);
        w_etoken_free(&token);
        return W_TOKEN_BOOTSTRAP_PERMANENT;
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
        return W_TOKEN_BOOTSTRAP_PERMANENT;
    }
#endif /* !WIN32 */

    if (fwrite(candidate_pem, 1, candidate_len, anchor_file.fp) != candidate_len) {
        merror("Token bootstrap: could not write the trust anchor to '%s'.", anchor_file.name);
        fclose(anchor_file.fp);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_BOOTSTRAP_PERMANENT;
    }

    fclose(anchor_file.fp);

    if (w_enrollment_build_request(&built_request) != 0) {
        /* w_enrollment_build_request() already logged the specific reason. */
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_BOOTSTRAP_PERMANENT;
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
            print_hex_string((const char *) derived_key, (unsigned int) sizeof(derived_key),
                             enroll_request.enroll_key_hex, (unsigned int) sizeof(enroll_request.enroll_key_hex));
            credential_ready = true;
        }

        memset(derived_key, 0, sizeof(derived_key));

        if (!credential_ready) {
            w_enroll_request_destroy(&built_request);
            unlink(anchor_file.name);
            os_free(anchor_file.name);
            w_etoken_free(&token);
            return W_TOKEN_BOOTSTRAP_PERMANENT;
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
        return W_TOKEN_BOOTSTRAP_TRANSIENT;
    }

    /* The kid this request actually signed with is the one on enroll_request: the enrollment
     * token's, derived and set above. built_request.enroll_kid is the RE-ENROLLMENT secret's, which
     * w_enrollment_build_request() leaves NULL whenever there is no secret on disk -- which is
     * always true here, since this is the first-boot token path and a secret only exists after an
     * enrollment has succeeded. Passing it named "unknown" in the one 403 an operator most needs to
     * act on: the one telling them which enrollment token to re-mint. */
    w_enroll_status_t enroll_status = w_enrollment_process_response(&enroll_result, enroll_request.enroll_kid);

    if (enroll_status != W_ENROLL_OK) {
        /* w_enrollment_process_response() already logged the specific reason. TRANSPORT/SERVER
         * are the manager's or the network's problem and may clear on their own; the manager has
         * already made a final decision about this exact request in every other case (malformed
         * request, bad credential, enrollment disabled, duplicate agent), and repeating it
         * verbatim cannot change that. */
        w_token_bootstrap_result_t enroll_class =
            (enroll_status == W_ENROLL_ERR_TRANSPORT || enroll_status == W_ENROLL_ERR_SERVER)
                ? W_TOKEN_BOOTSTRAP_TRANSIENT
                : W_TOKEN_BOOTSTRAP_PERMANENT;

        /* A fatal refusal is authd's verdict on a bearer whose signature the manager already
         * verified: the token is unknown, revoked, or out of uses, and re-presenting it cannot
         * change any of that. Nothing else on this path clears it -- the anchor is never installed
         * (OS_MoveFile is further down) and client.keys is never written, so neither latch at the
         * top of this function trips on the next boot -- and a PERMANENT result ends the start.
         * Keeping the token would therefore hand the same dead credential to the same fatal
         * refusal on every restart, which is the retry loop #39064 exists to end, only measured in
         * process lifetimes instead of HTTP attempts.
         *
         * Keyed on the status, deliberately, and NOT on the classification just above: every
         * fatal refusal is PERMANENT, but so is a malformed request, an enrollment the manager has
         * disabled, and a duplicate agent -- all of which must keep their token. Those can succeed
         * on a later boot without anyone touching the endpoint (enrollment re-enabled, a manager
         * still syncing the token, a clock that resyncs), and discarding a one-shot credential
         * over a condition that clears itself is the more expensive mistake: it needs an operator
         * and a newly minted token to undo.
         *
         * The result stays PERMANENT either way -- this boot refuses to enroll unverified, exactly
         * as before. What changes is that the next one starts with no token at all and takes the
         * "legacy install" path instead of repeating this. */
        if (enroll_status == W_ENROLL_ERR_AUTH_FATAL) {
            unlink(AGENT_ENROLLMENT_TOKEN_FILE);
        }

        w_enroll_request_destroy(&built_request);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return enroll_class;
    }

    w_enroll_request_destroy(&built_request);

    /* Written while still root; without fixing the ownership, the unprivileged `wazuh` user can't
     * read it after AgentdStart()'s privilege drop, breaking the first restart. Fixed up on the
     * temp file, before the rename below: a crash between them would leave AGENT_ANCHOR_CA on
     * disk with the wrong owner, and IsFile(AGENT_ANCHOR_CA) == 0 unconditionally latches the
     * bootstrap off on every later boot, so it must land before the rename, never after.
     *
     * uid:gid rather than root:gid, which is what it was before #39321. The mode stays 0640; what
     * changes is who owns it, and it changes because etc/certs is sticky (see
     * w_token_bootstrap_ensure_parent_dir): under the sticky bit only the file's owner may
     * rename over it, so a root-owned anchor is one the agent could never refresh. client.keys
     * keeps root:gid deliberately -- the runtime user has no business owning the credential, and
     * nothing needs to replace it under a sticky directory.
     *
     * Skipped on Windows for the same reason as the mode above: one service account throughout,
     * nothing to hand the file over to. */
#ifndef WIN32
    if (chown(anchor_file.name, uid, gid) != 0) {
        merror("Token bootstrap: could not change ownership of '%s': %s (%d).", anchor_file.name,
               strerror(errno), errno);
    }
#endif

    if (OS_MoveFile(anchor_file.name, AGENT_ANCHOR_CA) < 0) {
        merror("Token bootstrap: could not install the trust anchor at '%s'.", AGENT_ANCHOR_CA);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_BOOTSTRAP_PERMANENT;
    }

    os_free(anchor_file.name);

    /* Only now: the marker says an anchor has been committed, so it must not appear before one
     * has. */
    w_token_bootstrap_mark_anchor_committed(gid);

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
     * real store.
     *
     * Through the same vetted open as client.keys, and for a sharper version of the same reason.
     * This file shares client.keys's 0770 root:wazuh directory, so the runtime user can plant a
     * symlink here too -- and where client.keys's chown hands that user's GROUP access to the
     * link's target, this one names the user itself as the owner, so following a link would hand
     * it outright ownership of whatever the link points at. FileSize() above still resolves the
     * path, but it only decides whether to try: the vetted open is what refuses the link.
     *
     * Guarded like the anchor chown above, and for the same reason: one service account
     * throughout on Windows, so there is nobody to hand the file to. The guard is on the call and
     * not only on the definition -- w_token_bootstrap_open_and_chown() takes uid_t/gid_t and lives
     * inside the same #ifndef, so an unguarded call here links on Linux and fails at link time on
     * winagent, which no Linux-side test can catch. */
#ifndef WIN32
    if (FileSize(AGENT_REENROLL_SECRET) > 0 &&
            w_token_bootstrap_open_and_chown(AGENT_REENROLL_SECRET, (uid_t) uid, (gid_t) gid) != 0) {
        merror("Token bootstrap: could not change ownership of '%s': %s (%d).",
               AGENT_REENROLL_SECRET, strerror(errno), errno);
    }
#endif

    unlink(AGENT_ENROLLMENT_TOKEN_FILE);
    w_etoken_free(&token);
    minfo("Token bootstrap: enrollment succeeded; the manager's CA is now the agent's trust anchor.");

    return W_TOKEN_BOOTSTRAP_DONE;
}
