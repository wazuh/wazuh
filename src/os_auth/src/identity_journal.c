/* Identity transition journal
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The credential the manager already handed out, written down before it is handed out.
 *
 * An enrollment or a re-enrollment answers with a key and a re-enrollment secret long before the
 * writer puts them in global.db, and until now a failure there -- wazuh-db down, a socket timeout,
 * a crash between the two -- was logged and forgotten: the agent kept credentials the database had
 * never seen (issue #39078, H03). This journal is the record that lets the writer finish the job
 * later, or the next process start pick it up.
 *
 * It holds the credential in the clear, not a hash, because the verifier derives the signing key
 * from the real secret (reenroll_verify.cpp) and client.keys does not store it: a hash would prove
 * the transition happened and still leave nothing to restore.
 *
 * Three properties are deliberate:
 *
 *   - Appending is O(1) -- one line, no rewrite -- because it sits on the request path, in front of
 *     the answer. Compaction rewrites the file, and only the writer compacts.
 *   - A failed append REFUSES the operation. The deletion journal may lose a line and carry on
 *     (auth.c), since its entries can be rebuilt from client.keys; here the secret exists nowhere
 *     else, so an unrecorded transition is one we must not perform.
 *   - No fsync. What this recovers from is a process crash and a wazuh-db outage, not a power cut
 *     with the page still in cache; an fsync per enrollment would be paid by every agent
 *     (issue #39078, D13).
 */

#include <shared.h>
#include <stdio.h>
#include <sys/stat.h>
#include "auth.h"
#include "defs.h"
#include "os_err.h"

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

typedef struct identity_node {
    identity_journal_entry_t entry;
    struct identity_node *next;
} identity_node_t;

static identity_node_t *identity_journal = NULL;
static identity_node_t **identity_journal_tail = &identity_journal;
static size_t identity_journal_size = 0;
static long long identity_last_seq = 0;
static char *identity_path = NULL;
static pthread_mutex_t mutex_identity = PTHREAD_MUTEX_INITIALIZER;

/// The path, resolved once. Its own setter exists for the tests, which run in a temporary tree.
static const char* identity_file(void) {
    return identity_path ? identity_path : PENDING_IDENTITIES_FILE;
}

static void identity_entry_clear(identity_journal_entry_t *entry);

void identity_journal_init(const char *path) {
    identity_node_t *node;

    w_mutex_lock(&mutex_identity);

    os_free(identity_path);
    identity_path = NULL;
    if (path) {
        os_strdup(path, identity_path);
    }

    /* Also a reset: production never calls this, and a test that repoints the journal wants the
     * memory to start empty too -- otherwise entries leak from one case into the next. */
    for (node = identity_journal; node;) {
        identity_node_t *next = node->next;
        identity_entry_clear(&node->entry);
        os_free(node);
        node = next;
    }

    identity_journal = NULL;
    identity_journal_tail = &identity_journal;
    identity_journal_size = 0;
    identity_last_seq = 0;

    w_mutex_unlock(&mutex_identity);
}

/// Free one entry's strings, wiping the credential rather than merely releasing it.
static void identity_entry_clear(identity_journal_entry_t *entry) {
    if (!entry) {
        return;
    }

    if (entry->key) {
        OPENSSL_cleanse(entry->key, strlen(entry->key));
    }
    if (entry->secret) {
        OPENSSL_cleanse(entry->secret, strlen(entry->secret));
    }

    os_free(entry->id);
    os_free(entry->name);
    os_free(entry->ip);
    os_free(entry->key);
    os_free(entry->secret);
}

void identity_journal_free(identity_journal_entry_t *entries, size_t count) {
    size_t i;

    if (!entries) {
        return;
    }

    for (i = 0; i < count; i++) {
        identity_entry_clear(&entries[i]);
    }

    os_free(entries);
}

/// Serialize one entry as the single JSON line the file is made of. JSON, and not the space
/// separated fields of the deletion journal, because names and IPs are free text and ids are not.
static char* identity_entry_to_line(const identity_journal_entry_t *entry) {
    cJSON *object = cJSON_CreateObject();
    char *line;

    if (!object) {
        return NULL;
    }

    cJSON_AddNumberToObject(object, "seq", (double)entry->seq);
    cJSON_AddStringToObject(object, "id", entry->id);
    cJSON_AddBoolToObject(object, "rotate", entry->rotate);
    cJSON_AddNumberToObject(object, "ts", (double)entry->requested_at);
    cJSON_AddStringToObject(object, "name", entry->name ? entry->name : "");
    cJSON_AddStringToObject(object, "ip", entry->ip ? entry->ip : "");
    cJSON_AddStringToObject(object, "key", entry->key ? entry->key : "");
    cJSON_AddStringToObject(object, "secret", entry->secret ? entry->secret : "");

    line = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);

    return line;
}

/// Rewrite the whole file from what is held in memory. mutex_identity must be held.
///
/// Temporary plus rename, like OS_WriteKeys() and the deletion journal: a partial file can then
/// never be read back. Only the writer reaches this -- appending does not -- so the O(n) is paid
/// once per cycle and never on the request path.
static bool identity_file_compact_locked(void) {
    File file;
    identity_node_t *node;
    bool ok = true;

    if (TempFile(&file, identity_file(), 0) < 0) {
        mwarn("Could not open a temporary file for '%s': %s. The recorded identity transitions are "
              "still held in memory.", identity_file(), strerror(errno));
        return false;
    }

    if (chmod(file.name, 0640) < 0) {
        mwarn("Could not set the permissions of '%s': %s.", file.name, strerror(errno));
    }

    for (node = identity_journal; node && ok; node = node->next) {
        char *line = identity_entry_to_line(&node->entry);

        if (!line) {
            ok = false;
            break;
        }

        ok = fprintf(file.fp, "%s\n", line) >= 0;
        OPENSSL_cleanse(line, strlen(line));
        os_free(line);
    }

    if (!ok) {
        fclose(file.fp);
        unlink(file.name);
        os_free(file.name);
        mwarn("Could not write '%s'. The recorded identity transitions are still held in memory.",
              identity_file());
        return false;
    }

    if (fclose(file.fp) != 0 || OS_MoveFile(file.name, identity_file()) < 0) {
        unlink(file.name);
        os_free(file.name);
        mwarn("Could not replace '%s'. The recorded identity transitions are still held in memory.",
              identity_file());
        return false;
    }

    os_free(file.name);
    return true;
}

/// Whether the file's last byte is something other than a newline, i.e. an append that was cut
/// short. The stream is opened for append, so its position is already the end of the file.
static bool identity_file_needs_newline(FILE *fp) {
    int last;

    if (fseek(fp, 0, SEEK_END) != 0 || ftell(fp) <= 0) {
        return false;
    }

    if (fseek(fp, -1, SEEK_END) != 0) {
        return false;
    }

    last = fgetc(fp);
    fseek(fp, 0, SEEK_END);

    return last != '\n';
}

bool identity_journal_append(const char *id,
                             const char *name,
                             const char *ip,
                             const char *key,
                             const char *secret,
                             bool rotate,
                             long long *seq) {
    identity_node_t *node;
    char *line;
    FILE *fp;
    mode_t old_umask;
    bool written;

    if (!id || !key || !secret) {
        return false;
    }

    w_mutex_lock(&mutex_identity);

    /* The admission bound. Past it the answer is a refusal, not a silent drop of an older entry:
     * every line here is a credential some agent already holds, so the only thing that may be
     * refused is a transition that has not happened yet. */
    if (identity_journal_size >= IDENTITY_JOURNAL_MAX_ENTRIES) {
        w_mutex_unlock(&mutex_identity);
        mwarn("Refusing the identity transition of agent '%s': %d transitions are still waiting to "
              "reach the database, which is the limit. Retry once the backlog drains.",
              id, IDENTITY_JOURNAL_MAX_ENTRIES);
        return false;
    }

    os_calloc(1, sizeof(identity_node_t), node);
    node->entry.seq = ++identity_last_seq;
    node->entry.rotate = rotate;
    node->entry.requested_at = time(NULL);
    os_strdup(id, node->entry.id);
    os_strdup(name ? name : "", node->entry.name);
    os_strdup(ip ? ip : "", node->entry.ip);
    os_strdup(key, node->entry.key);
    os_strdup(secret, node->entry.secret);

    line = identity_entry_to_line(&node->entry);

    if (!line) {
        identity_entry_clear(&node->entry);
        os_free(node);
        w_mutex_unlock(&mutex_identity);
        return false;
    }

    /* 0640 from the first byte: the file carries credentials, so there must be no window in which
     * it exists with the process umask. Append, never rewrite -- this runs in front of the answer. */
    old_umask = umask(0137);
    /* "a+" and not "a": the fragment check below has to READ the last byte, and a stream opened
     * write-only answers EOF to it. Writes still always land at the end. */
    fp = wfopen(identity_file(), "a+");
    umask(old_umask);

    /* A write cut short by a full disk or a crash leaves a line with no newline. Starting the new
     * entry with one keeps that fragment a line of its own -- ignored on load, as any malformed
     * line is -- instead of gluing the two together and losing BOTH on the next start. */
    written = fp && fprintf(fp, "%s%s\n", identity_file_needs_newline(fp) ? "\n" : "", line) >= 0 &&
              fflush(fp) == 0;

    if (fp) {
        fclose(fp);
    }

    OPENSSL_cleanse(line, strlen(line));
    os_free(line);

    if (!written) {
        merror("Could not record the identity transition of agent '%s' in '%s': %s. The operation "
               "is refused rather than performed unrecorded.", id, identity_file(), strerror(errno));
        identity_entry_clear(&node->entry);
        os_free(node);
        w_mutex_unlock(&mutex_identity);
        return false;
    }

    if (seq) {
        *seq = node->entry.seq;
    }

    (*identity_journal_tail) = node;
    identity_journal_tail = &node->next;
    identity_journal_size++;

    w_mutex_unlock(&mutex_identity);

    return true;
}

bool identity_journal_full(void) {
    bool full;

    w_mutex_lock(&mutex_identity);
    full = identity_journal_size >= IDENTITY_JOURNAL_MAX_ENTRIES;
    w_mutex_unlock(&mutex_identity);

    if (full) {
        mwarn("Refusing the operation: %d identity transitions are still waiting to reach the "
              "database, which is the limit. Retry once the backlog drains.",
              IDENTITY_JOURNAL_MAX_ENTRIES);
    }

    return full;
}

long long identity_journal_last_seq(void) {
    long long seq;

    w_mutex_lock(&mutex_identity);
    seq = identity_last_seq;
    w_mutex_unlock(&mutex_identity);

    return seq;
}

size_t identity_journal_pending(void) {
    size_t size;

    w_mutex_lock(&mutex_identity);
    size = identity_journal_size;
    w_mutex_unlock(&mutex_identity);

    return size;
}

identity_journal_entry_t* identity_journal_snapshot(size_t max, long long upto_seq, size_t *count) {
    identity_journal_entry_t *entries = NULL;
    identity_node_t *node;
    size_t i = 0;

    if (count) {
        *count = 0;
    }

    w_mutex_lock(&mutex_identity);

    if (identity_journal_size > 0) {
        const size_t wanted = (max > 0 && max < identity_journal_size) ? max : identity_journal_size;

        os_calloc(wanted, sizeof(identity_journal_entry_t), entries);

        for (node = identity_journal; node && i < wanted; node = node->next) {
            /* Entries newer than the caller's mark are skipped: they were appended while the
             * writer was already working, so their keys have not reached client.keys yet and
             * their own queue nodes have not been processed. Applying and forgetting one here
             * would leave a credential the next start could not recover (issue #39078, review
             * round). Zero means "everything". */
            if (upto_seq > 0 && node->entry.seq > upto_seq) {
                continue;
            }

            entries[i].seq = node->entry.seq;
            entries[i].rotate = node->entry.rotate;
            entries[i].requested_at = node->entry.requested_at;
            os_strdup(node->entry.id, entries[i].id);
            os_strdup(node->entry.name, entries[i].name);
            os_strdup(node->entry.ip, entries[i].ip);
            os_strdup(node->entry.key, entries[i].key);
            os_strdup(node->entry.secret, entries[i].secret);
            i++;
        }
    }

    w_mutex_unlock(&mutex_identity);

    if (count) {
        *count = i;
    }

    return entries;
}

/// Drop these sequences and rewrite the file. mutex_identity must be held.
static size_t identity_journal_drop_locked(const long long *seqs, size_t count) {
    identity_node_t **prev;
    identity_node_t *node;
    size_t dropped = 0;
    size_t i;

    for (prev = &identity_journal; (node = *prev) != NULL;) {
        bool wanted = false;

        for (i = 0; i < count && !wanted; i++) {
            wanted = node->entry.seq == seqs[i];
        }

        if (!wanted) {
            prev = &node->next;
            continue;
        }

        *prev = node->next;
        if (!*prev) {
            identity_journal_tail = prev;
        }
        identity_journal_size--;
        dropped++;
        identity_entry_clear(&node->entry);
        os_free(node);
    }

    if (dropped > 0) {
        identity_file_compact_locked();
    }

    return dropped;
}

size_t identity_journal_drop(const long long *seqs, size_t count) {
    size_t dropped;

    if (!seqs || count == 0) {
        return 0;
    }

    w_mutex_lock(&mutex_identity);
    dropped = identity_journal_drop_locked(seqs, count);
    w_mutex_unlock(&mutex_identity);

    return dropped;
}

void identity_journal_load(void) {
    FILE *fp;
    char line[OS_MAXSTR];
    struct stat info;
    unsigned int loaded = 0;
    unsigned int malformed = 0;

    w_mutex_lock(&mutex_identity);

    if (stat(identity_file(), &info) == 0 && info.st_size > IDENTITY_JOURNAL_MAX_BYTES) {
        w_mutex_unlock(&mutex_identity);
        merror("'%s' is %ld bytes, past the %d the journal may ever hold: it is not loaded. Move it "
               "aside to start clean, and expect the agents it names to need a fresh enrollment.",
               identity_file(), (long)info.st_size, IDENTITY_JOURNAL_MAX_BYTES);
        return;
    }

    fp = wfopen(identity_file(), "r");

    if (!fp) {
        w_mutex_unlock(&mutex_identity);
        if (errno != ENOENT) {
            mwarn("Could not read '%s': %s. Identity transitions interrupted by the previous run, "
                  "if any, will not be recovered.", identity_file(), strerror(errno));
        }
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        cJSON *object = cJSON_Parse(line);
        cJSON *j_seq = object ? cJSON_GetObjectItem(object, "seq") : NULL;
        cJSON *j_id = object ? cJSON_GetObjectItem(object, "id") : NULL;
        cJSON *j_key = object ? cJSON_GetObjectItem(object, "key") : NULL;
        cJSON *j_secret = object ? cJSON_GetObjectItem(object, "secret") : NULL;
        cJSON *j_name = object ? cJSON_GetObjectItem(object, "name") : NULL;
        cJSON *j_ip = object ? cJSON_GetObjectItem(object, "ip") : NULL;
        cJSON *j_rotate = object ? cJSON_GetObjectItem(object, "rotate") : NULL;
        cJSON *j_ts = object ? cJSON_GetObjectItem(object, "ts") : NULL;
        identity_node_t *node;

        /* A torn last line is the expected shape of a crash mid-append: skipped, counted and
         * reported once, never a reason to refuse the lines that did land. */
        if (!cJSON_IsNumber(j_seq) || !cJSON_IsString(j_id) || !cJSON_IsString(j_key) ||
            !cJSON_IsString(j_secret) || !OS_IsValidID(j_id->valuestring)) {
            cJSON_Delete(object);
            malformed++;
            continue;
        }

        os_calloc(1, sizeof(identity_node_t), node);
        node->entry.seq = (long long)j_seq->valuedouble;
        node->entry.rotate = cJSON_IsTrue(j_rotate);
        node->entry.requested_at = cJSON_IsNumber(j_ts) ? (time_t)j_ts->valuedouble : time(NULL);
        os_strdup(j_id->valuestring, node->entry.id);
        os_strdup(cJSON_IsString(j_name) ? j_name->valuestring : "", node->entry.name);
        os_strdup(cJSON_IsString(j_ip) ? j_ip->valuestring : "", node->entry.ip);
        os_strdup(j_key->valuestring, node->entry.key);
        os_strdup(j_secret->valuestring, node->entry.secret);

        if (node->entry.seq > identity_last_seq) {
            identity_last_seq = node->entry.seq;
        }

        (*identity_journal_tail) = node;
        identity_journal_tail = &node->next;
        identity_journal_size++;
        loaded++;

        cJSON_Delete(object);
    }

    fclose(fp);

    w_mutex_unlock(&mutex_identity);

    if (malformed > 0) {
        mwarn("Ignored %u malformed entr(y|ies) in '%s'; the rest were loaded.", malformed,
              identity_file());
    }

    if (loaded > 0) {
        minfo("Recovered %u identity transition(s) that the previous run did not finish writing to "
              "the database.", loaded);
    }
}

/// Whether a later entry in the journal names the same agent. mutex_identity held.
///
/// The entries are appended in order, so "later in the list" is "higher seq" -- the only durable
/// ordering there is, and the one that decides which generation of an agent's credentials is the
/// live one.
static bool identity_superseded_locked(const identity_node_t *node) {
    const identity_node_t *later;

    for (later = node->next; later; later = later->next) {
        if (!strcmp(later->entry.id, node->entry.id)) {
            return true;
        }
    }

    return false;
}

size_t identity_journal_reconcile(void) {
    identity_node_t **prev;
    identity_node_t *node;
    size_t kept = 0;
    unsigned int gone = 0;
    unsigned int superseded = 0;
    unsigned int reserved = 0;
    bool changed = false;

    w_mutex_lock(&mutex_identity);

    for (prev = &identity_journal; (node = *prev) != NULL;) {
        bool drop;

        /* What the journal owes is decided by the JOURNAL's own order, not by client.keys.
         *
         * The earlier rule -- keep the entry only when its key is the one client.keys names -- was
         * wrong in exactly the case this file exists for: authd answers a rotation, and the crash
         * lands before the writer rewrites client.keys. The file then still holds the previous key,
         * the entry holds the credentials the agent is already using, and calling that "superseded"
         * deleted the only durable copy of them. The agent could then neither connect (its key is
         * not in client.keys) nor re-enroll (its secret is not in the database): stuck until
         * someone registered it again by hand.
         *
         *   - the id is gone from client.keys -> nothing is owed. The agent was deleted, or its
         *     very first key write never landed; either way, restoring a row for an agent no
         *     manager knows would resurrect what the operator removed, and an agent whose
         *     enrollment was lost simply enrolls again.
         *   - a LATER entry names the same agent -> this one is the previous generation.
         *   - otherwise -> it is the live generation and the database owes it, whatever
         *     client.keys says. Writing it means the agent can re-enroll with the secret it
         *     already holds, and the next rotation puts its key back in client.keys: it heals
         *     itself instead of needing a human. */
        if (OS_IsAllowedID(&keys, node->entry.id) < 0) {
            drop = true;
            gone++;
        } else if (identity_superseded_locked(node)) {
            drop = true;
            superseded++;
        } else {
            drop = false;
        }

        if (!drop) {
            kept++;

            /* The reservation of a rotation does not survive the process, and until this entry is
             * committed the database still names the PREVIOUS secret -- which is exactly what
             * would authorise another rotation. Taking it back before any thread starts keeps the
             * "one effective rotation per agent" guarantee across a restart; the writer releases
             * it when the recovery commits, like any other rotation. */
            if (node->entry.rotate && w_reenroll_reserve(node->entry.id, NULL)) {
                reserved++;
            }

            prev = &node->next;
            continue;
        }

        *prev = node->next;
        if (!*prev) {
            identity_journal_tail = prev;
        }
        identity_journal_size--;
        changed = true;
        identity_entry_clear(&node->entry);
        os_free(node);
    }

    if (changed) {
        identity_file_compact_locked();
    }

    w_mutex_unlock(&mutex_identity);

    if (gone > 0 || superseded > 0) {
        minfo("Discarded %u recorded identity transition(s) whose agent is no longer in client.keys "
              "and %u superseded by a later one.", gone, superseded);
    }

    if (kept > 0) {
        minfo("%zu identity transition(s) are still owed to the database; the writer applies them "
              "as soon as it is reachable. %u agent(s) cannot rotate until theirs is written.",
              kept, reserved);
    }

    return kept;
}
