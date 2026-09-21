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
#include "https_client_bridge.h"
#include "shred_file.h"
#include "cJSON.h"

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
    if (FileSize(AGENT_REENROLL_SECRET) < 0) {
        return; /* Nothing to clear. */
    }

    /* Best-effort overwrite before the unlink: it removes the obvious plaintext copy, and that is
     * all it does -- see w_reenroll_secret_clear()'s doc comment on why this is not erasure. The
     * result is deliberately ignored: the unlink below is what takes the credential off the disk,
     * and w_shred_file_in_place() has already logged anything worth knowing. It is shared with the
     * MSI's --shred-enrollment-password rather than written twice -- two copies of "overwrite
     * without truncating" are two places to get the open mode wrong, and the wrong one is silent. */
    (void) w_shred_file_in_place(AGENT_REENROLL_SECRET);

    if (unlink(AGENT_REENROLL_SECRET) != 0) {
        merror(UNLINK_ERROR, AGENT_REENROLL_SECRET, errno, strerror(errno));
        return;
    }

    minfo("The re-enrollment secret was rejected by the manager and has been removed.");
}

/* Longest wait before the one request of this start.
 *
 * The population this bootstrap exists for is a 4.x fleet upgraded to 5.0 over WPK: every one of
 * those agents restarts at roughly the same moment and would otherwise ask at the same instant. The
 * manager paces that with a 429 -- the route shares POST /enroll's rate limit -- and a 429 is
 * answered by simply trying again on the next start, so without a spread the fleet just
 * re-synchronizes on every boot. Spending up to a minute here costs nothing: this credential is for
 * a FUTURE recovery, and nothing in this process waits on it. */
#define W_REENROLL_BOOTSTRAP_JITTER_SEC 60

#ifdef WIN32
static DWORD WINAPI w_reenroll_secret_bootstrap_thread(LPVOID arg)
#else
static void *w_reenroll_secret_bootstrap_thread(void *arg)
#endif
{
    (void) arg;

    /* The sign is masked off before the modulo, not after: os_random() returns a plain int and can
     * be negative, and a negative remainder cast to unsigned would sleep for decades. */
    sleep((unsigned int)(os_random() & 0x7FFFFFFF) % (W_REENROLL_BOOTSTRAP_JITTER_SEC + 1));
    w_reenroll_secret_bootstrap();

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

void w_reenroll_secret_bootstrap_async(void) {
    /* Deliberately not w_create_thread(): that macro merror_exit()s when the spawn fails, and this
     * credential is for a future recovery -- an agent that cannot spare a thread for it is no worse
     * off than one whose manager refused the request, and must not be taken down over it. */
#ifdef WIN32
    HANDLE thread = CreateThread(NULL, 0, w_reenroll_secret_bootstrap_thread, NULL, 0, NULL);

    if (thread == NULL) {
        mdebug1("Could not start the re-enrollment secret bootstrap thread; retrying on the next start.");
        return;
    }

    /* The thread is never joined, so the handle is closed straight away: keeping it would leak one
     * per start for a thread nothing waits on. Closing it does not stop the thread. */
    CloseHandle(thread);
#else
    if (!CreateThread(w_reenroll_secret_bootstrap_thread, NULL)) {
        mdebug1("Could not start the re-enrollment secret bootstrap thread; retrying on the next start.");
    }
#endif
}

void w_reenroll_secret_bootstrap(void) {
    char stored_id[W_REENROLL_ID_SIZE];
    char stored_secret[W_REENROLL_SECRET_SIZE];
    hc_secret_result_t result;
    cJSON *response = NULL;
    cJSON *j_id = NULL;
    cJSON *j_secret = NULL;

    /* Asked first, so an agent that already has a credential costs the manager nothing at all --
     * which is every 5.0 agent, since its own enrollment handed it one. A malformed store reads as
     * absent (w_reenroll_secret_load()'s contract), so this also repairs one by replacing it. */
    if (w_reenroll_secret_load(stored_id, sizeof(stored_id), stored_secret, sizeof(stored_secret))) {
        OPENSSL_cleanse(stored_secret, sizeof(stored_secret));
        mdebug2("A re-enrollment secret is already stored; not requesting one.");
        return;
    }

    memset(&result, 0, sizeof(result));

    /* Never fatal, on any path below: this credential is for a FUTURE recovery, so nothing the
     * agent does now depends on having it, and a failure is simply retried by the next start. */
    if (!w_https_client_fetch_reenroll_secret(&result)) {
        mdebug1("Could not request a re-enrollment secret: %s.",
                result.transport_error[0] != '\0' ? result.transport_error : "no request was sent");
        goto end;
    }

    if (result.http_code != 200) {
        switch (result.http_code) {
        case 401:
            /* The manager did not accept the key this agent holds. Worth a warning rather than a
             * debug line: the agent can still talk on that key until the manager stops accepting it
             * elsewhere too, but it now has no way to recover on its own, and the operator is the
             * one who can fix that -- with an enrollment token. */
            mwarn("The manager rejected this agent's key while requesting a re-enrollment secret; "
                  "no secret was obtained.");
            break;
        case 409:
            mdebug1("A credential rotation for this agent is already in flight; no re-enrollment "
                    "secret was obtained this start.");
            break;
        case 429:
        case 503:
            /* The two expected answers during a fleet-wide upgrade wave, and deliberately handled
             * identically: the manager is pacing or temporarily cannot record the transition. One
             * line, no retry in this process -- the jittered attempt on the next start is the
             * retry. */
            mdebug1("The manager is not issuing re-enrollment secrets right now (HTTP %ld); "
                    "retrying on the next start.", result.http_code);
            break;
        default:
            mdebug1("Re-enrollment secret request answered with HTTP %ld; retrying on the next start.",
                    result.http_code);
            break;
        }
        goto end;
    }

    response = cJSON_Parse(result.body);
    if (!response) {
        merror("The re-enrollment secret response is not valid JSON.");
        goto end;
    }

    j_id = cJSON_GetObjectItem(response, "id");
    j_secret = cJSON_GetObjectItem(response, "reenroll_secret");

    /* Both fields are mandatory here, unlike /enroll's optional fifth field: this route exists only
     * to produce a secret, so an answer without one is a protocol disagreement, not a manager that
     * issues none. w_reenroll_secret_store() validates them again before writing anything. */
    if (!cJSON_IsString(j_id) || !cJSON_IsString(j_secret)) {
        merror("The re-enrollment secret response has a missing or invalid field.");
        goto end;
    }

    if (w_reenroll_secret_store(j_id->valuestring, j_secret->valuestring) != 0) {
        /* w_reenroll_secret_store() logged the reason. */
        goto end;
    }

    minfo("Re-enrollment secret obtained from the manager for agent '%s'.", j_id->valuestring);

end:
    /* NULL first: cJSON_IsString() is opaque to the static analyser, which then reads the
     * dereference below as a possible null one. */
    if (j_secret && cJSON_IsString(j_secret) && j_secret->valuestring) {
        OPENSSL_cleanse(j_secret->valuestring, strlen(j_secret->valuestring));
    }
    cJSON_Delete(response);
    /* The raw body held the secret in the clear whether or not it parsed. */
    OPENSSL_cleanse(result.body, sizeof(result.body));
}
