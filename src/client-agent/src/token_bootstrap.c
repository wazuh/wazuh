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

STATIC int w_token_bootstrap_split_dir_filename(const char *path, char *buf, size_t buf_size,
                                                 const char **filename);
STATIC void w_token_bootstrap_ensure_parent_dir(const char *path, int gid);
STATIC void w_token_bootstrap_mark_anchor_committed(int gid);
#ifndef WIN32
STATIC int w_token_bootstrap_open_and_chown(const char *path, uid_t owner, gid_t group);
STATIC int w_token_bootstrap_open_and_chown_keys(int gid);
STATIC void w_token_bootstrap_repair_anchor_ownership(int uid, int gid);
#endif
STATIC void w_token_bootstrap_chown_keys_file(int gid, bool quiet_on_failure);

/**
 * @brief Reads the one-shot enrollment token file, mirroring
 *        w_enrollment_load_password()'s fopen/fgets read style (enrollment.c), sized for a
 *        token instead of a short password.
 * @return A newly allocated, trimmed copy of the file's first line, or NULL when the file is
 *         missing, empty, unreadable, or holds a first line too long to fit.
 */
char *w_agent_token_read_file(const char *path) {
    FILE *fp = wfopen(path, "r");

    if (!fp) {
        return NULL;
    }

    char buf[W_ETOKEN_MAX_FILE_BYTES];
    char *read_ok = fgets(buf, sizeof(buf), fp);

    /* fgets() stops at a newline, at end of file, or because the buffer filled, and reports all
     * three the same way. Only the last is a problem: the token arrives quietly cut short and is
     * then refused as malformed, which sends whoever reads that message off to inspect a token
     * that is merely too big. Asking whether anything is left to read is what separates the
     * buffer filling from the line simply ending. */
    bool truncated = (read_ok != NULL && strchr(buf, '\n') == NULL && fgetc(fp) != EOF);

    fclose(fp);

    if (!read_ok || truncated) {
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
        merror("Could not set ownership of '%s': %s (%d).", dir,
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
        merror("Could not set permissions on '%s': %s (%d).", dir,
               strerror(errno), errno);
    }
#endif /* !WIN32 */
}

#ifndef WIN32

/**
 * @brief chown()s @p path to @p owner:@p group without following a symlink planted in its parent
 *        directory. Both files this is used for live in INSTALLDIR/etc, which is 0770 root:wazuh
 *        -- the runtime user can create entries there, and since #39321 the same is true of
 *        AGENT_ANCHOR_CA's own directory (01770 root:gid), so the reasoning below covers both.
 *        That user can replace the target with a symlink to an arbitrary root-owned
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
            mdebug1("Could not change ownership of '%s' (will retry on a later "
                    "boot): %s (%d).", KEYS_FILE, strerror(errno), errno);
        } else {
            merror("Could not change ownership of '%s': %s (%d).", KEYS_FILE,
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

/** One short, operator-facing sentence per failing step. Never NULL. */
const char *w_agent_token_enroll_strerror(w_token_enroll_status_t status) {
    switch (status) {
        case W_TOKEN_ENROLL_OK:
            return "enrolled";
        case W_TOKEN_ENROLL_ERR_TOKEN:
            return "the enrollment token was rejected";
        case W_TOKEN_ENROLL_ERR_ANCHOR:
            return "the manager's certificate authority could not be established";
        case W_TOKEN_ENROLL_ERR_CREDENTIAL:
            return "the token's credential could not be prepared";
        case W_TOKEN_ENROLL_ERR_REQUEST:
            return "the enrollment request could not be built";
        case W_TOKEN_ENROLL_ERR_ENROLL:
            return "the manager refused the enrollment";
        case W_TOKEN_ENROLL_ERR_STORE:
            return "the manager accepted the enrollment, but its answer could not be stored";
        case W_TOKEN_ENROLL_ERR_COMMIT:
            return "enrolled, but the result could not be committed to disk";
        default:
            return "unknown error";
    }
}

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

/**
 * @brief Whether the anchor already on disk is byte-for-byte what this token would install.
 *
 * Lets the caller say "unchanged" instead of silently rewriting identical bytes, and lets
 * --certs-only return without touching anything at all. Compares content rather than a pin,
 * because a pin only says the certificate is the right one -- not that the file holding it is.
 */
static bool token_anchor_matches(const char *candidate, size_t candidate_len) {
    FILE *fp = wfopen(AGENT_ANCHOR_CA, "r");
    bool same = false;

    if (fp == NULL) {
        return false;
    }

    char *installed = NULL;
    os_calloc(candidate_len + 2, sizeof(char), installed);
    size_t read = fread(installed, 1, candidate_len + 1, fp);
    fclose(fp);

    same = (read == candidate_len) && (memcmp(installed, candidate, candidate_len) == 0);
    os_free(installed);

    return same;
}

/**
 * @brief The one file a transactional enrollment can need to put back.
 *
 * Only client.keys: the anchor is installed by the rename that is the last thing to happen, so a
 * failure there leaves the previous anchor already in place with nothing to restore. An earlier
 * version snapshotted the anchor too and never restored it -- dead weight, and a second copy of
 * the trust anchor at rest for no benefit.
 */
typedef struct {
    char *keys_backup;   /**< mkstemp()-chosen path, or NULL when nothing was copied aside */
} token_snapshot_t;

/**
 * @brief Copies client.keys aside so a failed commit can put it back.
 *
 * Uses TempFile() rather than a name this function chooses: INSTALLDIR/etc is 0770 root:<group>
 * (inst-functions.sh), i.e. writable by the very account the agent runs as, and this runs as
 * root. A predictable name there -- `client.keys.bak-<pid>` was the first attempt -- lets that
 * account pre-plant a symlink and have root truncate, write and chmod whatever it points at.
 * mkstemp() closes that: the name is unpredictable and the file is created O_EXCL at 0600, so
 * there is no window in which the secret sits at the umask's mode either.
 *
 * @return 0 on success, -1 when a backup was needed but could not be taken.
 */
static int token_snapshot(const w_token_enroll_opts_t *opts, token_snapshot_t *snapshot) {
    File backup = {NULL, NULL};

    snapshot->keys_backup = NULL;

    if (!opts->transactional || FileSize(KEYS_FILE) <= 0) {
        return 0;
    }

    if (TempFile(&backup, KEYS_FILE, 1) < 0) {
        merror("Could not copy the current agent key aside: %s (%d).",
               strerror(errno), errno);
        return -1;
    }

    fclose(backup.fp);
    snapshot->keys_backup = backup.name;

    return 0;
}

/**
 * @brief Puts client.keys back after a commit that failed with the new key already written.
 *
 * Restores by copying out of the backup rather than renaming it in: OS_MoveFile() unlinks its
 * source on the copy fallback, so a restore that consumed the backup would destroy the last copy
 * of the old key if it then failed itself. The copy goes through TempFile()+OS_MoveFile() so
 * client.keys is replaced atomically, like every other write to it in this module.
 */
/**
 * @brief Whether @p path is still the file whose identity @p before recorded.
 *
 * A staged file is created through a descriptor and then handed to helpers that reopen it by
 * name; this is what makes that reopen safe in a directory the runtime user can write.
 * Always true on Windows, which has no inode to compare and whose staged files carry an explicit
 * Administrators/SYSTEM DACL instead (mkstemp_ex()).
 */
static bool token_staged_file_is_ours(const char *path, const struct stat *before, bool known) {
#ifdef WIN32
    (void)path;
    (void)before;
    (void)known;
    return true;
#else
    struct stat after;

    return known && lstat(path, &after) == 0 && S_ISREG(after.st_mode) && after.st_nlink == 1 &&
           after.st_dev == before->st_dev && after.st_ino == before->st_ino;
#endif
}

static void token_rollback(const w_token_enroll_opts_t *opts, token_snapshot_t *snapshot,
                           w_token_enroll_report_t *report) {
    File restored = {NULL, NULL};

    if (snapshot->keys_backup == NULL) {
        /* Nothing was copied aside, so there is nothing to put back. The caller reports this as
         * the unrecoverable case it is. */
        return;
    }

    if (TempFile(&restored, KEYS_FILE, 0) < 0) {
        merror("Could not stage the previous agent key for restore: %s (%d).",
               strerror(errno), errno);
        goto keep_backup;
    }

    /* Same window as the config rewrite in agent_auth_cli.c: w_copy_file() reopens by NAME, so
     * the account that can write INSTALLDIR/etc could swap the staged file for a symlink between
     * the close and that reopen and have root restore through it. Recorded from the descriptor
     * TempFile() still holds, and checked below before the rename. */
    struct stat restored_before;
    bool restored_known = (fstat(fileno(restored.fp), &restored_before) == 0);

    fclose(restored.fp);

    if (w_copy_file(snapshot->keys_backup, restored.name, 'b', NULL, 1) != 0 ||
        !token_staged_file_is_ours(restored.name, &restored_before, restored_known) ||
        OS_MoveFile(restored.name, KEYS_FILE) < 0) {
        merror("Could not restore the previous agent key. The agent now holds a "
               "key the configured manager does not know.");
        unlink(restored.name);
        os_free(restored.name);
        goto keep_backup;
    }

    os_free(restored.name);

    if (opts->gid != -1) {
        w_token_bootstrap_chown_keys_file(opts->gid, true);
    }

    unlink(snapshot->keys_backup);
    os_free(snapshot->keys_backup);
    snapshot->keys_backup = NULL;

    if (report != NULL) {
        report->rolled_back = true;
    }

    return;

keep_backup:
    /* The backup outlives this process on purpose: it is the only remaining copy of a working
     * credential, and the caller prints its path so an operator can put it back by hand. */
    if (report != NULL) {
        strncpy(report->keys_backup, snapshot->keys_backup, sizeof(report->keys_backup) - 1);
    }

    os_free(snapshot->keys_backup);
    snapshot->keys_backup = NULL;
}

/** Removes the backup once the enrollment has committed and it can no longer be needed. */
static void token_snapshot_discard(token_snapshot_t *snapshot) {
    if (snapshot->keys_backup == NULL) {
        return;
    }

    unlink(snapshot->keys_backup);
    os_free(snapshot->keys_backup);
    snapshot->keys_backup = NULL;
}

/**
 * @brief Lifts the agent id and name out of the enrollment response, for a caller that has to
 *        tell an operator which registration they just got. Re-parses the body rather than
 *        widening w_enrollment_process_response()'s signature: a second parse of a small
 *        response costs less than the blast radius on enrollment.h and its tests.
 */
static void token_report_identity(const hc_enroll_result_t *result,
                                  w_token_enroll_report_t *report) {
    if (report == NULL) {
        return;
    }

    cJSON *response = cJSON_Parse(result->body);

    if (response == NULL) {
        return;
    }

    const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(response, "id"));
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(response, "name"));

    if (id != NULL) {
        strncpy(report->agent_id, id, sizeof(report->agent_id) - 1);
    }

    if (name != NULL) {
        strncpy(report->agent_name, name, sizeof(report->agent_name) - 1);
    }

    cJSON_Delete(response);
}

/**
 * @brief merror() the message and keep a copy in @p report for the caller to show an operator.
 *
 * One call per failure rather than a merror() beside a strncpy(), so the line the operator reads
 * and the line in the log cannot drift apart. NULL-safe in @p report: agentd passes none.
 */
STATIC void token_report_fail(w_token_enroll_report_t *report, const char *fmt, ...) {
    char text[256];
    va_list args;

    va_start(args, fmt);
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);

    merror("%s", text);

    if (report != NULL) {
        strncpy(report->detail, text, sizeof(report->detail) - 1);
    }
}

w_token_enroll_status_t w_agent_token_enroll(const w_token_enroll_opts_t *opts,
                                             w_token_enroll_report_t *report) {
    w_etoken_t token;
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
    token_snapshot_t snapshot = {NULL};
    bool anchor_changed = false;

    assert(opts != NULL);
    assert(opts->token_text != NULL);

    if (report != NULL) {
        memset(report, 0, sizeof(*report));
        report->had_anchor = (IsFile(AGENT_ANCHOR_CA) == 0);
        report->had_keys = (FileSize(KEYS_FILE) > 0);
    }

    decode_err = w_etoken_decode(opts->token_text, &token);

    if (decode_err != ETOKEN_OK) {
        merror("Could not decode the enrollment token: %s.",
               w_etoken_strerror(decode_err));
        return W_TOKEN_ENROLL_ERR_TOKEN;
    }

    if (w_parse_agent_endpoint(token.adr, host, sizeof(host), &port, &port_present, endpoint,
                               sizeof(endpoint), &scope_id) != 0) {
        token_report_fail(report, "The enrollment token's address is invalid.");
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_ERR_TOKEN;
    }

    if (report != NULL) {
        strncpy(report->host, host, sizeof(report->host) - 1);
        strncpy(report->endpoint, endpoint, sizeof(report->endpoint) - 1);
        report->port = port;
        report->used_pin = token.has_pin;
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
            /* The four-way /cacerts taxonomy: each cause gets its own greppable name, so a
             * misprovisioned manager (ca_mismatch) is never read as the one abort that actually
             * is hostile (a pin mismatch, logged separately below once a body is in hand to
             * compare). adr_unreachable and ca_mismatch may clear on their own (no response at
             * all, or a 5xx); not_found is the manager's settled answer -- it has no CA to
             * serve, provisioned or not, and repeating the request cannot change that. */
            bool fetch_transient;

            if (fetch_result.http_code == 0) {
                fetch_transient = true;
                token_report_fail(report, "/cacerts adr_unreachable -- could not reach the "
                       "manager to fetch the certificate authority%s%s.",
                       fetch_result.transport_error[0] != '\0' ? ": " : "",
                       fetch_result.transport_error[0] != '\0' ? fetch_result.transport_error : "");
            } else if (fetch_result.http_code == 404) {
                fetch_transient = false;
                token_report_fail(report, "/cacerts not_found -- the manager has no certificate "
                       "authority configured (it may predate this feature).");
            } else if (fetch_result.http_code == 503) {
                fetch_transient = true;
                token_report_fail(report, "/cacerts ca_mismatch -- the manager's configured "
                       "certificate authority does not sign its own listener certificate "
                       "(misprovisioned, not necessarily hostile).");
            } else {
                fetch_transient = (fetch_result.http_code >= 500);
                token_report_fail(report, "Fetching /cacerts from the manager failed: manager "
                       "returned HTTP %ld instead of 200%s%s.", fetch_result.http_code,
                       fetch_result.transport_error[0] != '\0' ? ": " : "",
                       fetch_result.transport_error[0] != '\0' ? fetch_result.transport_error : "");
            }

            if (report != NULL) {
                report->transient = fetch_transient;
            }

            w_etoken_free(&token);
            return W_TOKEN_ENROLL_ERR_ANCHOR;
        }

        /* Checked before the pin compare, which cannot tell the two apart: a certificate cut
         * off by this buffer hashes to nothing the token names, and would be reported as a
         * mismatch -- the message that says an attacker may be answering. A body this end
         * could not hold is our limit, not the manager's identity. */
        if (fetch_result.body_truncated) {
            token_report_fail(report, "The manager's /cacerts response is larger than the %d bytes "
                   "this agent can read, so it cannot be checked against the enrollment token's "
                   "pin.", HC_MAX_CACERTS_BODY);
            w_etoken_free(&token);
            return W_TOKEN_ENROLL_ERR_ANCHOR;
        }

        if ((pin_b64 = w_b64url_encode(token.pin, W_ETOKEN_PIN_BYTES)) == NULL) {
            merror("Could not encode the enrollment token's pin.");
            w_etoken_free(&token);
            return W_TOKEN_ENROLL_ERR_ANCHOR;
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
            token_report_fail(report, "pin_mismatch -- fetched CA does not match the "
                   "enrollment token's pin, refusing to trust it.");
            os_free(pin_b64);
            w_etoken_free(&token);
            return W_TOKEN_ENROLL_ERR_ANCHOR;
        }

        os_free(pin_b64);
        candidate_pem = pinned_pem;
        candidate_len = strlen(pinned_pem);
    } else {
        candidate_pem = token.ca_pem;
        candidate_len = strlen(token.ca_pem);
    }

    anchor_changed = !token_anchor_matches(candidate_pem, candidate_len);

    if (report != NULL) {
        report->anchor_changed = anchor_changed;
    }

    /* Nothing to install and nothing to enroll: the anchor already holds exactly this
     * certificate. Returning here is what makes the command idempotent in a configuration
     * management loop rather than rewriting the same bytes on every run. */
    if (opts->anchor_only && !anchor_changed) {
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_OK;
    }

    /* etc/certs doesn't exist on a stock install; see w_token_bootstrap_ensure_parent_dir(). */
    w_token_bootstrap_ensure_parent_dir(AGENT_ANCHOR_CA, opts->gid);

    /* An unpredictable name, not a fixed sibling: the directory this writes into is readable by
     * the account the agent runs as, and a predictable name there is a symlink waiting to be
     * planted. The anchor is committed by the rename below, and only once the enrollment has
     * succeeded, so a failed run leaves the installed anchor untouched. */
    if (TempFile(&anchor_file, AGENT_ANCHOR_CA, 0) < 0) {
        merror("Could not create a temporary file for the trust anchor: %s (%d).",
               strerror(errno), errno);
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_ERR_ANCHOR;
    }

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
        merror("Could not set permissions on '%s': %s (%d).", anchor_file.name,
               strerror(errno), errno);
        fclose(anchor_file.fp);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_ERR_ANCHOR;
    }
#endif /* !WIN32 */

    if (fwrite(candidate_pem, 1, candidate_len, anchor_file.fp) != candidate_len) {
        merror("Could not write the trust anchor to '%s'.", anchor_file.name);
        fclose(anchor_file.fp);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_ERR_ANCHOR;
    }

    fclose(anchor_file.fp);

    /* --certs-only stops here. The anchor is committed straight away rather than after an
     * enrollment, because there is no enrollment to wait for: the whole point of this mode is to
     * refresh what the agent verifies against while leaving its registration alone. Ownership is
     * fixed before the rename for the same reason it is on the enrolling path -- a crash between
     * them would leave the anchor on disk with the wrong group. */
    if (opts->anchor_only) {
#ifndef WIN32
        /* uid, not root: under the sticky etc/certs only the file's owner may rename over it,
         * so an anchor this path installs root-owned is one the runtime refresh (#39321) could
         * never replace. chown() reads -1 as "leave this one alone", which is exactly what the
         * opts contract already means by it. */
        if ((opts->uid != -1 || opts->gid != -1) &&
                chown(anchor_file.name, opts->uid, opts->gid) != 0) {
            merror("Could not change ownership of '%s': %s (%d).",
                   anchor_file.name, strerror(errno), errno);
        }
#endif

        if (OS_MoveFile(anchor_file.name, AGENT_ANCHOR_CA) < 0) {
            merror("Could not install the trust anchor at '%s'.",
                   AGENT_ANCHOR_CA);
            unlink(anchor_file.name);
            os_free(anchor_file.name);
            w_etoken_free(&token);
            return W_TOKEN_ENROLL_ERR_ANCHOR;
        }

        os_free(anchor_file.name);
        w_etoken_free(&token);

        /* Only now: the marker says an anchor has been committed, so it must not appear before
         * one has. */
        w_token_bootstrap_mark_anchor_committed(opts->gid);

        minfo("The manager's CA is now the agent's trust anchor.");

        return W_TOKEN_ENROLL_OK;
    }

    if (w_enrollment_build_request(&built_request) != 0) {
        /* w_enrollment_build_request() already logged the specific reason. */
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_ERR_REQUEST;
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
     * itself -- its password AND the re-enrollment credential it may have loaded are both
     * discarded, and only body_json is taken from it. The token is the only thing that may
     * authenticate this request: it is the one credential the operator handed to this endpoint
     * for this purpose.
     *
     * A credential-less token (token.has_key == false) does NOT fall back to a configured
     * authd.pass either -- enrollment goes out with no credential at all.
     * Confirmed against the manager's own EnrollmentAuthenticator
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
            merror("Could not derive the enrollment token's signing key.");
        } else if ((kid = w_b64url_encode(token.id, W_ETOKEN_ID_BYTES)) == NULL) {
            merror("Could not encode the enrollment token's identifier.");
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
            return W_TOKEN_ENROLL_ERR_CREDENTIAL;
        }
    }

    memset(&enroll_result, 0, sizeof(enroll_result));

    /* Last point before anything on disk can change: w_enrollment_process_response() below
     * replaces client.keys outright, and the anchor rename follows it. Every failure up to here
     * has left both untouched, so there was nothing worth copying until now. Refuses rather than
     * enrolling blind -- without a backup a failed commit strands the agent with no way back. */
    if (token_snapshot(opts, &snapshot) != 0) {
        /* Local, and nothing to do with the manager: the CA was fetched and pin-checked long
         * before this. The class stays ERR_ANCHOR because the anchor is what was not installed
         * and the exit codes are a published contract, but without naming the cause the operator
         * is sent to investigate a manager that is behaving perfectly. */
        token_report_fail(report, "Could not copy the current agent key aside before enrolling, "
                          "so the enrollment was not attempted: %s (%d).", strerror(errno), errno);
        w_enroll_request_destroy(&built_request);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_ERR_ANCHOR;
    }

    if (!hc_enroll(&enroll_config, &enroll_request, &enroll_result) || enroll_result.http_code == 0) {
        merror("The verified enrollment request could not be sent%s%s.",
               enroll_result.transport_error[0] != '\0' ? ": " : "",
               enroll_result.transport_error[0] != '\0' ? enroll_result.transport_error : "");

        if (report != NULL) {
            /* Nothing answered, or the manager answered with its own trouble. Either may clear. */
            report->transient = (enroll_result.http_code == 0 || enroll_result.http_code >= 500);
        }

        w_enroll_request_destroy(&built_request);
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        token_snapshot_discard(&snapshot);
        w_etoken_free(&token);
        return (enroll_result.http_code == 200) ? W_TOKEN_ENROLL_ERR_STORE
                                                : W_TOKEN_ENROLL_ERR_ENROLL;
    }

    if (report != NULL) {
        report->http_code = enroll_result.http_code;

        if (enroll_result.http_code != 200) {
            cJSON *body = cJSON_Parse(enroll_result.body);
            cJSON *error = body ? cJSON_GetObjectItem(body, "error") : NULL;
            const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(error, "message"));

            if (text != NULL) {
                strncpy(report->manager_message, text, sizeof(report->manager_message) - 1);
            }

            cJSON_Delete(body);
        }
    }

    /* The kid this request actually signed with is the one on enroll_request: the enrollment
     * token's, derived and set above. built_request.enroll_kid is the RE-ENROLLMENT secret's, which
     * w_enrollment_build_request() leaves NULL whenever there is no secret on disk. Passing it
     * named "unknown" in the one 403 an operator most needs to act on: the one telling them which
     * enrollment token to re-mint. */
    w_enroll_status_t enroll_status = w_enrollment_process_response(&enroll_result,
                                                                   enroll_request.enroll_kid);

    if (enroll_status != W_ENROLL_OK) {
        /* w_enrollment_process_response() already logged the specific reason. TRANSPORT/SERVER
         * are the manager's or the network's problem and may clear on their own; the manager has
         * already made a final decision about this exact request in every other case (malformed
         * request, bad credential, enrollment disabled, duplicate agent), and repeating it
         * verbatim cannot change that. */
        if (report != NULL) {
            report->transient = (enroll_status == W_ENROLL_ERR_TRANSPORT ||
                                 enroll_status == W_ENROLL_ERR_SERVER);
            /* Keyed on the status, deliberately, and NOT on `transient`: every fatal refusal is
             * permanent, but so is a malformed request, an enrollment the manager has disabled,
             * and a duplicate agent -- all of which may succeed later with the same token. This
             * is authd's verdict on a bearer whose signature it already verified: unknown,
             * revoked, or out of uses. Only the caller acts on it, because only the caller owns
             * the token. */
            report->token_rejected = (enroll_status == W_ENROLL_ERR_AUTH_FATAL);
        }

        w_enroll_request_destroy(&built_request);
        unlink(anchor_file.name);
        os_free(anchor_file.name);

        /* A 200 means the manager accepted and it is the LOCAL store that failed -- and by then
         * client.keys may already be gone: enrollment.c's Windows branch opens it "w" outright,
         * and OS_MoveFile()'s copy fallback truncates its destination before streaming into it.
         * Discarding the backup there deletes the last copy of a working key and then reports
         * that none was ever taken. Anything else is the manager refusing, which writes nothing
         * locally, so the backup is genuinely surplus. */
        if (enroll_result.http_code == 200) {
            token_rollback(opts, &snapshot, report);
        } else {
            token_snapshot_discard(&snapshot);
        }

        w_etoken_free(&token);
        return (enroll_result.http_code == 200) ? W_TOKEN_ENROLL_ERR_STORE
                                                : W_TOKEN_ENROLL_ERR_ENROLL;
    }

    w_enroll_request_destroy(&built_request);

    /* Written while still root; without fixing the ownership, the unprivileged `wazuh` user can't
     * read it after AgentdStart()'s privilege drop, breaking the first restart. Fixed up on the
     * temp file, before the rename below: a crash between them would leave AGENT_ANCHOR_CA on
     * disk with the wrong owner, and IsFile(AGENT_ANCHOR_CA) == 0 unconditionally latches the
     * bootstrap off on every later boot, so it must land before the rename, never after.
     *
     * uid:gid rather than root:gid since #39321. The mode stays 0640; what changes is who owns
     * it, and it changes because etc/certs is sticky (see w_token_bootstrap_ensure_parent_dir):
     * under the sticky bit only the file's owner may rename over it, so a root-owned anchor is
     * one the agent could never refresh. client.keys keeps root:gid deliberately -- the runtime
     * user has no business owning the credential, and nothing needs to replace it here.
     *
     * Skipped on Windows for the same reason as the mode above: one service account throughout,
     * nothing to hand the file over to. */
#ifndef WIN32
    if (chown(anchor_file.name, opts->uid, opts->gid) != 0) {
        merror("Could not change ownership of '%s': %s (%d).", anchor_file.name,
               strerror(errno), errno);
    }
#endif

    if (OS_MoveFile(anchor_file.name, AGENT_ANCHOR_CA) < 0) {
        merror("Could not install the trust anchor at '%s'.", AGENT_ANCHOR_CA);
        token_rollback(opts, &snapshot, report);
        /* The rename is what failed, so the staged anchor is still on disk holding the new CA.
         * Every other failure branch in this function removes it; this one did not, leaving one
         * behind in the certs directory on each attempt. */
        unlink(anchor_file.name);
        os_free(anchor_file.name);
        w_etoken_free(&token);
        return W_TOKEN_ENROLL_ERR_COMMIT;
    }

    os_free(anchor_file.name);

    /* Only now: the marker says an anchor has been committed, so it must not appear before one
     * has. */
    w_token_bootstrap_mark_anchor_committed(opts->gid);

    /* enrollment.c's TempFile()+OS_MoveFile() replace only chmod()s client.keys to a fixed 0640
     * on the temp file, never its group, so it inherits this root process's group instead of
     * root:wazuh -- chown to root:gid (not uid:gid, mirroring the anchor's ownership model)
     * restores read access without handing the credential to the runtime user. If this fails
     * (e.g. a namespaced container without CAP_CHOWN), the anchor above is already committed, so
     * client.keys stays root:root here -- but the anchor-latch branch above retries this same
     * chown on every later boot, so this is not a one-shot chance to fix it. A no-op on
     * Windows, where there is no second user to restore access for. */
    w_token_bootstrap_chown_keys_file(opts->gid, false);

    /* The re-enrollment secret is written here too, as root, by w_enrollment_process_response()
     * on the way through. Unlike the anchor it also has to be WRITABLE by the unprivileged user
     * afterwards, since every rotation happens in the running daemon after the privilege drop --
     * a root-owned secret would survive exactly one enrollment and then fail every rotation.
     * This is the one file the core chowns to the runtime user rather than to root, which is why
     * opts carries a uid at all. FileSize() rather than IsFile(): only a non-empty file is a
     * real store.
     *
     * Through the same vetted open as client.keys, and for a sharper version of the same reason.
     * This file shares client.keys's 0770 root:wazuh directory, so the runtime user can plant a
     * symlink here too -- and where client.keys's chown hands that user's GROUP access to the
     * link's target, this one names the user itself as the owner, so following a link would hand
     * it outright ownership of whatever the link points at.
     *
     * Skipped when the caller passed no uid: wazuh-agent-auth runs long after the install and has
     * no privilege drop of its own to prepare for, so it leaves the ownership the daemon already
     * established alone rather than guessing at it. */
#ifndef WIN32
    if (opts->uid != -1 && FileSize(AGENT_REENROLL_SECRET) > 0 &&
            w_token_bootstrap_open_and_chown(AGENT_REENROLL_SECRET, (uid_t) opts->uid,
                                             (gid_t) opts->gid) != 0) {
        merror("Could not change ownership of '%s': %s (%d).", AGENT_REENROLL_SECRET,
               strerror(errno), errno);
    }
#endif

    token_report_identity(&enroll_result, report);
    token_snapshot_discard(&snapshot);
    w_etoken_free(&token);
    /* The "Token bootstrap: " prefix is not decoration. The end-to-end check in
     * engine/tools/devContainer/e2e/agents/verify_agents.sh greps ossec.log for this exact
     * phrase to decide whether an agent enrolled over POST /enroll. */
    minfo(anchor_changed
              ? "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's trust anchor."
              : "Token bootstrap: enrollment succeeded; the agent's trust anchor is unchanged.");

    return W_TOKEN_ENROLL_OK;
}

/**
 * @brief Documents, not implements, the only reset that works today: a fresh bootstrap only
 *        re-runs once AGENT_ANCHOR_CA is removed, client.keys is emptied or removed, AND a new
 *        enrollment-token file is placed -- each latch (anchor exists / keys non-empty / no
 *        token file) independently blocks it otherwise, so clearing any one or two alone is not
 *        enough. This is today's actual behavior; it has no dedicated interface or name of its
 *        own.
 */
w_token_bootstrap_result_t w_agent_token_bootstrap(int uid, int gid) {
    w_token_enroll_opts_t opts = {0};
    w_token_enroll_report_t report = {0};
    char *token_text = NULL;

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

    if ((token_text = w_agent_token_read_file(AGENT_ENROLLMENT_TOKEN_FILE)) == NULL) {
        merror("Could not read the enrollment token file '%s'.",
               AGENT_ENROLLMENT_TOKEN_FILE);
        return W_TOKEN_BOOTSTRAP_PERMANENT;
    }

    opts.token_text = token_text;
    opts.uid = uid;
    opts.gid = gid;
    /* Nothing to roll back to: this path only runs when there is no anchor and no key. */
    opts.transactional = false;

    if (w_agent_token_enroll(&opts, &report) != W_TOKEN_ENROLL_OK) {
        os_free(token_text);

        /* The token file is kept, so a retry within this boot -- or a later one -- still has
         * something to enroll with. The one exception is a token the manager has finally refused:
         * unknown, revoked, or out of uses. Nothing on this path clears it (the anchor is never
         * installed and client.keys never written, so neither latch above trips next boot), so
         * keeping it would hand the same dead credential to the same refusal on every restart.
         * Disposal is the caller's business, which is why the core only reports the verdict. */
        if (report.token_rejected) {
            unlink(AGENT_ENROLLMENT_TOKEN_FILE);
        }

        /* Unchanged either way: this boot still refuses to enroll unverified. What changes is
         * that the next one starts with no token and takes the "legacy install" path. */
        return report.transient ? W_TOKEN_BOOTSTRAP_TRANSIENT : W_TOKEN_BOOTSTRAP_PERMANENT;
    }

    os_free(token_text);
    unlink(AGENT_ENROLLMENT_TOKEN_FILE);

    return W_TOKEN_BOOTSTRAP_DONE;
}
