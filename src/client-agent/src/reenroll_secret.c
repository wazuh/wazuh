/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "reenroll_secret.h"

#include <openssl/crypto.h>

/* "<id> <secret>\n": the widest id OS_IsValidID() accepts, a space, 64 hex characters, a newline
 * and the NUL, with room to spare so a hand-edited file is read and rejected rather than
 * truncated into something that happens to validate. */
#define W_REENROLL_LINE_SIZE 128

int w_reenroll_secret_store(const char *id, const char *secret) {
    if (id == NULL || secret == NULL) {
        return -1;
    }

    /* Validated before anything is written, never after: a store holding values the verifier will
     * refuse is worse than no store at all, because the agent would present a bearer nobody can
     * check instead of falling back to a credential that still works. */
    if (!OS_IsValidID(id)) {
        merror("Re-enrollment secret not stored: the manager answered with an invalid agent id.");
        return -1;
    }

    if (!OS_IsValidReenrollSecret(secret)) {
        merror("Re-enrollment secret not stored: the manager answered with a malformed secret.");
        return -1;
    }

#ifdef WIN32
    /* Non-atomic, exactly like w_enrollment_store_key_entry()'s Windows branch: the platform split
     * is inherited on purpose (#38465) rather than unified here. */
    FILE *fp = wfopen(AGENT_REENROLL_SECRET, "w");

    if (!fp) {
        merror(FOPEN_ERROR, AGENT_REENROLL_SECRET, errno, strerror(errno));
        return -1;
    }

    fprintf(fp, "%s %s\n", id, secret);
    fclose(fp);

#else /* !WIN32 */
    File file;

    if (TempFile(&file, AGENT_REENROLL_SECRET, 0) < 0) {
        merror(FOPEN_ERROR, AGENT_REENROLL_SECRET, errno, strerror(errno));
        return -1;
    }

    /* Same mode as client.keys: this credential is the key's equal, not the anchor's (see
     * reenroll_secret.h). TempFile()'s mkstemp() creates 0600, so without this the daemon could
     * not read back a secret written in the root window of w_agent_token_bootstrap(). */
    if (chmod(file.name, 0640) == -1) {
        merror(CHMOD_ERROR, file.name, errno, strerror(errno));
        fclose(file.fp);
        unlink(file.name);
        os_free(file.name);
        return -1;
    }

    fprintf(file.fp, "%s %s\n", id, secret);
    fclose(file.fp);

    if (OS_MoveFile(file.name, AGENT_REENROLL_SECRET) < 0) {
        /* OS_MoveFile() logs the reason. The previous secret, if any, is untouched: that is the
         * point of writing through a temporary file. */
        os_free(file.name);
        return -1;
    }

    os_free(file.name);

#endif /* !WIN32 */

    mdebug1("Re-enrollment secret stored for agent '%s'.", id);
    return 0;
}

int w_reenroll_secret_load(char *id, size_t id_size, char *secret, size_t secret_size) {
    char line[W_REENROLL_LINE_SIZE];
    const char *id_text;
    const char *secret_text;
    char *separator;
    FILE *fp;
    char *read_ok;
    size_t len;
    int result = 0;

    if (id == NULL || secret == NULL || id_size == 0 || secret_size == 0) {
        return 0;
    }

    id[0] = '\0';
    secret[0] = '\0';

    if ((fp = wfopen(AGENT_REENROLL_SECRET, "r")) == NULL) {
        /* Missing is the normal state of a legacy install, an agent that has never enrolled
         * against a 5.0 manager, or one whose manager issues no secret. Never an error. */
        return 0;
    }

    read_ok = fgets(line, sizeof(line), fp);
    fclose(fp);

    if (read_ok == NULL) {
        return 0; /* Empty file: same as absent. */
    }

    len = strlen(line);

    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }

    if (len == 0) {
        return 0;
    }

    /* Split on the one space the store writes, and refuse anything else.
     *
     * Deliberately not sscanf("%15s %64s"): given a single long token -- a file holding only the
     * secret, which is exactly the shape a hand-edited or half-migrated store has -- a
     * width-bounded %s silently cuts it in two and hands back a plausible-looking id/secret pair,
     * so the store would be reported as holding an invalid id rather than as malformed. Both
     * answers refuse the credential, but only one of them tells the operator what is actually
     * wrong with the file. */
    separator = strchr(line, ' ');

    if (separator == NULL || separator == line || strchr(separator + 1, ' ') != NULL) {
        merror("Re-enrollment secret store '%s' is malformed; ignoring it.", AGENT_REENROLL_SECRET);
        goto end;
    }

    *separator = '\0';
    id_text = line;
    secret_text = separator + 1;

    if (*secret_text == '\0') {
        merror("Re-enrollment secret store '%s' is malformed; ignoring it.", AGENT_REENROLL_SECRET);
        goto end;
    }

    if (!OS_IsValidID(id_text) || !OS_IsValidReenrollSecret(secret_text)) {
        merror("Re-enrollment secret store '%s' holds an invalid id or secret; ignoring it.",
               AGENT_REENROLL_SECRET);
        goto end;
    }

    if (strlen(id_text) >= id_size || strlen(secret_text) >= secret_size) {
        merror("Re-enrollment secret store '%s' does not fit the caller's buffers; ignoring it.",
               AGENT_REENROLL_SECRET);
        goto end;
    }

    strncpy(id, id_text, id_size - 1);
    id[id_size - 1] = '\0';
    strncpy(secret, secret_text, secret_size - 1);
    secret[secret_size - 1] = '\0';
    result = 1;

end:
    /* Every exit path, including the failures: the secret reached this buffer either way. */
    OPENSSL_cleanse(line, sizeof(line));

    if (result == 0) {
        id[0] = '\0';
        secret[0] = '\0';
    }

    return result;
}

void w_reenroll_secret_clear(void) {
    FILE *fp;
    off_t size = FileSize(AGENT_REENROLL_SECRET);

    if (size < 0) {
        return; /* Nothing to clear. */
    }

    /* Best-effort overwrite before the unlink: it removes the obvious plaintext copy, and that is
     * all it does -- see w_reenroll_secret_clear()'s doc comment on why this is not erasure. */
    if ((fp = wfopen(AGENT_REENROLL_SECRET, "r+")) != NULL) {
        off_t written;

        for (written = 0; written < size; written++) {
            if (fputc('0', fp) == EOF) {
                break;
            }
        }

        fflush(fp);
        fclose(fp);
    }

    if (unlink(AGENT_REENROLL_SECRET) != 0) {
        merror(UNLINK_ERROR, AGENT_REENROLL_SECRET, errno, strerror(errno));
        return;
    }

    minfo("The re-enrollment secret was rejected by the manager and has been removed.");
}
