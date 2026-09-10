/*
 * Wazuh authd - enrollment token store
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The enrollment token store: the file etc/enrollment_tokens.json and the in-memory replica of it.
 *
 * Three properties shape every function below.
 *
 * The file is the only durable state, and the cluster synchronises it: the master mints, revokes and
 * consumes, a worker only ever reads. That is why nothing here derives anything from a previous
 * in-memory value -- a worker's copy is replaced wholesale by whatever the master wrote -- and why
 * etoken_store_reload_if_changed() refuses to interpret a MISSING file as "no tokens": during a
 * cluster sync the file legitimately disappears for a moment, and wiping the replica then would let
 * an agent enroll with a token the master still considers revoked, or be refused one the master
 * still honours.
 *
 * Every write is an atomic rewrite (TempFile + rename, the shape of OS_WriteKeys()), because a
 * partially written store is not a degraded store: it fails to parse, and a worker that reloads it
 * would refuse every enrollment. The temporary file is created 0600 by TempFile() and chmod()ed to
 * 0640 before the rename, so the secrets are never world readable, not even for an instant.
 *
 * A token secret is credential material with the same weight as a key in client.keys. It reaches
 * the outside world exactly once, in the token text etoken_store_create() returns; it is never
 * logged, never listed, and every heap copy this file makes is OPENSSL_cleanse()d before it is
 * freed -- including the printed JSON buffer, which holds all of them at once.
 */

#include <shared.h>
#include <sys/stat.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "enrollment_token_store.h"
#include "enrollment_token.h"

/* Characters of a base64url encoded 32 byte pin */
#define ETOKEN_PIN_CHARS 43

/* Characters of a base64url encoded 16 byte secret */
#define ETOKEN_SECRET_CHARS 22

/* Format version of the file. Bumped only for a change a version 1 reader could not survive */
#define ETOKEN_STORE_VERSION 1

/* Attempts to draw an id that no token holds yet. A collision needs two identical 128 bit draws,
 * so the loop exists to make the impossible explicit rather than because it is expected to spin */
#define ETOKEN_ID_ATTEMPTS 8

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

/* The in-memory replica. Guarded by etoken_mutex: authd serves the token verbs on the local server
 * thread and consumes tokens on the enrollment threads, so both the array and the file are shared.
 * The path is owned by etoken_store_init() and deliberately outlives etoken_store_free(), which
 * exists to drop the tokens (and wipe their secrets), not to un-initialise the module. */
static pthread_mutex_t etoken_mutex = PTHREAD_MUTEX_INITIALIZER;
static etoken_entry_t *etoken_tokens = NULL;
static int etoken_tokens_size = 0;
static char *etoken_path = NULL;
static time_t etoken_mtime = 0;

/* Uses reserved by etoken_store_consume() whose enrollment has not finished yet.
 *
 * Deliberately NOT a field of the entry: an enrollment holds its reservation across the whole
 * OS_AddNewAgent() -- seconds, with the mutex released so other enrollments proceed -- and any
 * reload in between replaces the array wholesale with what the file says. Kept aside, a reservation
 * survives that, and a purge run in the middle of an enrollment cannot take away the token whose
 * last use is about to be returned by etoken_store_release(). Guarded by etoken_mutex, and empty
 * in the common case: authd is not usually enrolling anybody while an operator purges.
 */
typedef struct {
    char id[ETOKEN_ID_CHARS + 1];
    unsigned int count;
} etoken_inflight_t;

static etoken_inflight_t *etoken_inflight = NULL;
static int etoken_inflight_size = 0;

/**
 * @brief Wipe and release one entry. The struct itself is left zeroed.
 */
static void etoken_entry_free(etoken_entry_t *entry) {
    OPENSSL_cleanse(entry->secret, sizeof(entry->secret));
    os_free(entry->adr);
    os_free(entry->ca_pem);
    os_free(entry->description);
    memset(entry, 0, sizeof(*entry));
}

/**
 * @brief Drop every entry. Caller holds the mutex.
 */
static void etoken_clear_locked(void) {
    int i;

    for (i = 0; i < etoken_tokens_size; i++) {
        etoken_entry_free(&etoken_tokens[i]);
    }

    os_free(etoken_tokens);
    etoken_tokens_size = 0;
}

/**
 * @brief Reservations held for that id, 0 when there is none. Caller holds the mutex.
 */
static unsigned int etoken_inflight_held_locked(const char *id) {
    int i;

    for (i = 0; i < etoken_inflight_size; i++) {
        if (!strcmp(etoken_inflight[i].id, id)) {
            return etoken_inflight[i].count;
        }
    }

    return 0;
}

/**
 * @brief Take a reservation for that id. Caller holds the mutex.
 */
static void etoken_inflight_hold_locked(const char *id) {
    int i;

    for (i = 0; i < etoken_inflight_size; i++) {
        if (!strcmp(etoken_inflight[i].id, id)) {
            etoken_inflight[i].count++;
            return;
        }
    }

    os_realloc(etoken_inflight, sizeof(etoken_inflight_t) * (etoken_inflight_size + 1), etoken_inflight);
    memset(&etoken_inflight[etoken_inflight_size], 0, sizeof(etoken_inflight_t));
    strncpy(etoken_inflight[etoken_inflight_size].id, id, ETOKEN_ID_CHARS);
    etoken_inflight[etoken_inflight_size].count = 1;
    etoken_inflight_size++;
}

/**
 * @brief Give back one reservation for that id, dropping the record when the last one goes.
 *        Caller holds the mutex.
 */
static void etoken_inflight_drop_locked(const char *id) {
    int i;

    for (i = 0; i < etoken_inflight_size; i++) {
        if (strcmp(etoken_inflight[i].id, id)) {
            continue;
        }

        if (etoken_inflight[i].count > 1) {
            etoken_inflight[i].count--;
            return;
        }

        if (i != etoken_inflight_size - 1) {
            etoken_inflight[i] = etoken_inflight[etoken_inflight_size - 1];
        }

        etoken_inflight_size--;

        if (etoken_inflight_size == 0) {
            os_free(etoken_inflight);
        } else {
            os_realloc(etoken_inflight, sizeof(etoken_inflight_t) * etoken_inflight_size, etoken_inflight);
        }

        return;
    }
}

/**
 * @brief Whether an entry can no longer authorise an enrollment. Caller holds the mutex.
 *
 * The same three conditions etoken_store_consume() refuses on, in the same order: revoked, expired,
 * out of uses. A token with `uses == 0` and time left is alive however long it has sat unused --
 * that is a token an operator minted and has not handed out yet, not a leftover.
 *
 * A token whose last use is reserved by an enrollment still running is not dead either: the
 * enrollment may still fail and return that use, and a purge that took the entry away in the
 * meantime would make the return a no-op. `all` ignores this: emptying the store is an explicit,
 * documented order, not a cleanup.
 */
static int etoken_is_dead_locked(const etoken_entry_t *entry, time_t now) {
    if (etoken_inflight_size > 0 && etoken_inflight_held_locked(entry->id) > 0) {
        return 0;
    }

    return entry->revoked || now >= entry->expires ||
           (entry->max_uses != 0 && entry->uses >= entry->max_uses);
}

/**
 * @brief Remove the entries the scope names, keeping the order of the survivors. Caller holds the
 *        mutex and persists afterwards.
 *
 * @param ids Optional; every removed id is appended to it.
 * @return Number of entries removed.
 */
static int etoken_purge_locked(etoken_purge_t scope, time_t now, cJSON *ids) {
    int kept = 0;
    int removed = 0;
    int i;

    for (i = 0; i < etoken_tokens_size; i++) {
        if (scope == ETOKEN_PURGE_ALL || etoken_is_dead_locked(&etoken_tokens[i], now)) {
            if (ids != NULL) {
                cJSON_AddItemToArray(ids, cJSON_CreateString(etoken_tokens[i].id));
            }

            etoken_entry_free(&etoken_tokens[i]);
            removed++;
        } else {
            if (kept != i) {
                etoken_tokens[kept] = etoken_tokens[i];
            }

            kept++;
        }
    }

    etoken_tokens_size = kept;

    if (kept == 0) {
        os_free(etoken_tokens);
    }

    return removed;
}

/**
 * @brief Index of the entry with that id, or -1. Caller holds the mutex.
 */
static int etoken_find_locked(const char *id) {
    int i;

    if (id == NULL) {
        return -1;
    }

    for (i = 0; i < etoken_tokens_size; i++) {
        if (strcmp(etoken_tokens[i].id, id) == 0) {
            return i;
        }
    }

    return -1;
}

/**
 * @brief Lowercase hexadecimal of a byte string. @p out needs 2 * len + 1 bytes.
 */
static void etoken_hex(const uint8_t *in, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0F];
    }

    out[len * 2] = '\0';
}

/**
 * @brief Decode a canonical base64url field of an exact decoded length into @p out.
 *
 * @return 0 on success, -1 when the text is not canonical base64url or does not hold @p want bytes.
 */
static int etoken_decode_fixed(const char *text, size_t chars, uint8_t *out, size_t want) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int ret = -1;

    if (text == NULL || strlen(text) != chars) {
        return -1;
    }

    if (w_b64url_decode(text, &raw, &raw_len) == 0) {
        if (raw_len == want) {
            memcpy(out, raw, want);
            ret = 0;
        }

        OPENSSL_cleanse(raw, raw_len);
        os_free(raw);
    }

    return ret;
}

/**
 * @brief Whether an item is absent or JSON null: how the file writes "this token has no secret".
 */
static int etoken_json_absent(const cJSON *item) {
    return item == NULL || cJSON_IsNull((cJSON *) item);
}

/**
 * @brief Read a non-negative integer item.
 *
 * @return 0 on success, -1 when the item is absent, not a number or out of range.
 */
static int etoken_json_uint(const cJSON *item, double max, double *out) {
    if (!cJSON_IsNumber((cJSON *) item) || item->valuedouble < 0 || item->valuedouble > max) {
        return -1;
    }

    *out = item->valuedouble;

    return 0;
}

/**
 * @brief Parse one token of the file.
 *
 * Strict on purpose: a store that cannot be read exactly is not read at all (see
 * etoken_store_load_locked()), so every field is checked here rather than defaulted. The returned reason
 * is safe to log -- it never names a value, because half of these fields are credential material.
 *
 * @param item The JSON object.
 * @param out Receives the entry on success (untouched on failure).
 * @return NULL on success, or a static reason string.
 */
static const char *etoken_parse_entry(const cJSON *item, etoken_entry_t *out) {
    etoken_entry_t entry;
    const cJSON *field = NULL;
    uint8_t id_bytes[W_ETOKEN_ID_BYTES];
    double number = 0;

    memset(&entry, 0, sizeof(entry));

    if (!cJSON_IsObject((cJSON *) item)) {
        return "not an object";
    }

    /* id: the 16 identifier bytes as canonical base64url. Canonical matters -- two spellings of one
     * id would be two entries here and one token to an agent */
    field = cJSON_GetObjectItem((cJSON *) item, "id");

    if (!cJSON_IsString((cJSON *) field) ||
        etoken_decode_fixed(field->valuestring, ETOKEN_ID_CHARS, id_bytes, sizeof(id_bytes)) != 0) {
        return "invalid id";
    }

    memcpy(entry.id, field->valuestring, ETOKEN_ID_CHARS + 1);

    /* secret: null for a token that carries no credential (public information by design) */
    field = cJSON_GetObjectItem((cJSON *) item, "secret");

    if (!etoken_json_absent(field)) {
        if (!cJSON_IsString((cJSON *) field) ||
            etoken_decode_fixed(field->valuestring, ETOKEN_SECRET_CHARS, entry.secret,
                                W_ETOKEN_SECRET_BYTES) != 0) {
            return "invalid secret";
        }

        entry.has_secret = 1;
    }

    field = cJSON_GetObjectItem((cJSON *) item, "adr");

    if (!cJSON_IsString((cJSON *) field) || field->valuestring[0] == '\0') {
        goto invalid_adr;
    }

    os_strdup(field->valuestring, entry.adr);

    /* Exactly one anchor, the same rule w_etoken_encode() enforces: no anchor is an unverifiable
     * manager, both is an ambiguity about which one the agent must trust */
    field = cJSON_GetObjectItem((cJSON *) item, "pin");

    if (!etoken_json_absent(field)) {
        if (!cJSON_IsString((cJSON *) field) ||
            etoken_decode_fixed(field->valuestring, ETOKEN_PIN_CHARS, entry.pin, W_ETOKEN_PIN_BYTES) != 0) {
            goto invalid_pin;
        }

        entry.has_pin = 1;
    }

    field = cJSON_GetObjectItem((cJSON *) item, "ca");

    if (!etoken_json_absent(field)) {
        if (!cJSON_IsString((cJSON *) field) || field->valuestring[0] == '\0') {
            goto invalid_ca;
        }

        os_strdup(field->valuestring, entry.ca_pem);
    }

    if (entry.has_pin == (entry.ca_pem != NULL)) {
        goto invalid_anchor;
    }

    if (etoken_json_uint(cJSON_GetObjectItem((cJSON *) item, "created"), (double) INT64_MAX, &number) != 0) {
        goto invalid_created;
    }

    entry.created = (time_t) number;

    if (etoken_json_uint(cJSON_GetObjectItem((cJSON *) item, "expires"), (double) INT64_MAX, &number) != 0) {
        goto invalid_expires;
    }

    entry.expires = (time_t) number;

    if (etoken_json_uint(cJSON_GetObjectItem((cJSON *) item, "max_uses"), (double) UINT_MAX, &number) != 0) {
        goto invalid_max_uses;
    }

    entry.max_uses = (unsigned int) number;

    if (etoken_json_uint(cJSON_GetObjectItem((cJSON *) item, "uses"), (double) UINT_MAX, &number) != 0) {
        goto invalid_uses;
    }

    entry.uses = (unsigned int) number;

    field = cJSON_GetObjectItem((cJSON *) item, "revoked");

    if (!cJSON_IsBool((cJSON *) field)) {
        goto invalid_revoked;
    }

    entry.revoked = cJSON_IsTrue((cJSON *) field) ? 1 : 0;

    field = cJSON_GetObjectItem((cJSON *) item, "description");

    if (!etoken_json_absent(field)) {
        if (!cJSON_IsString((cJSON *) field)) {
            goto invalid_description;
        }

        os_strdup(field->valuestring, entry.description);
    }

    *out = entry;

    return NULL;

invalid_adr:
    etoken_entry_free(&entry);
    return "invalid adr";
invalid_pin:
    etoken_entry_free(&entry);
    return "invalid pin";
invalid_ca:
    etoken_entry_free(&entry);
    return "invalid ca";
invalid_anchor:
    etoken_entry_free(&entry);
    return "not exactly one anchor";
invalid_created:
    etoken_entry_free(&entry);
    return "invalid created";
invalid_expires:
    etoken_entry_free(&entry);
    return "invalid expires";
invalid_max_uses:
    etoken_entry_free(&entry);
    return "invalid max_uses";
invalid_uses:
    etoken_entry_free(&entry);
    return "invalid uses";
invalid_revoked:
    etoken_entry_free(&entry);
    return "invalid revoked";
invalid_description:
    etoken_entry_free(&entry);
    return "invalid description";
}

/**
 * @brief Read the file and replace the in-memory tokens. Caller holds the mutex.
 *
 * All or nothing: the whole file is parsed into a fresh array and only then swapped in, so a
 * malformed store leaves the tokens that were already loaded in place. A worker holding a good
 * replica keeps serving enrollments while an operator fixes the file.
 *
 * @return 0 on success (an absent file included, which is simply an empty store), -1 on error.
 */
static int etoken_store_load_locked(void) {
    struct stat statbuf;
    cJSON *root = NULL;
    cJSON *version = NULL;
    cJSON *array = NULL;
    cJSON *item = NULL;
    etoken_entry_t *loaded = NULL;
    int loaded_size = 0;
    int index = 0;

    if (etoken_path == NULL) {
        merror("The enrollment token store was used before etoken_store_init().");
        return -1;
    }

    if (stat(etoken_path, &statbuf) < 0) {
        if (errno == ENOENT) {
            /* Not an error, and not even unusual: the file only exists once a token has been
             * minted, and a worker has none until the master's first sync */
            mdebug1("The enrollment token store '%s' does not exist yet: no tokens loaded.", etoken_path);
            etoken_clear_locked();
            etoken_mtime = 0;
            return 0;
        }

        mwarn("Could not read the enrollment token store '%s': %s. The tokens already loaded are kept.",
              etoken_path, strerror(errno));
        return -1;
    }

    if (root = json_fread(etoken_path, 0), root == NULL) {
        mwarn("The enrollment token store '%s' is not valid JSON. The tokens already loaded are kept.",
              etoken_path);
        return -1;
    }

    version = cJSON_GetObjectItem(root, "version");

    if (!cJSON_IsNumber(version) || version->valuedouble != (double) ETOKEN_STORE_VERSION) {
        /* Fail rather than guess: a future version may have moved a field this reader would then
         * silently read as absent -- an expiry, a use count or an anchor */
        mwarn("The enrollment token store '%s' has an unsupported version. The tokens already loaded are kept.",
              etoken_path);
        cJSON_Delete(root);
        return -1;
    }

    array = cJSON_GetObjectItem(root, "tokens");

    if (!cJSON_IsArray(array)) {
        mwarn("The enrollment token store '%s' has no 'tokens' array. The tokens already loaded are kept.",
              etoken_path);
        cJSON_Delete(root);
        return -1;
    }

    cJSON_ArrayForEach(item, array) {
        const char *reason = NULL;

        os_realloc(loaded, sizeof(etoken_entry_t) * (loaded_size + 1), loaded);
        memset(&loaded[loaded_size], 0, sizeof(etoken_entry_t));

        if (reason = etoken_parse_entry(item, &loaded[loaded_size]), reason != NULL) {
            int i;

            /* The position and the field, never the value: half of a token's fields are credential
             * material, and the rest are of no use to whoever has to fix the file */
            mwarn("The enrollment token store '%s' is malformed: token %d is invalid (%s). The "
                  "tokens already loaded are kept.", etoken_path, index, reason);

            for (i = 0; i < loaded_size; i++) {
                etoken_entry_free(&loaded[i]);
            }

            os_free(loaded);
            cJSON_Delete(root);
            return -1;
        }

        loaded_size++;
        index++;
    }

    cJSON_Delete(root);

    etoken_clear_locked();
    etoken_tokens = loaded;
    etoken_tokens_size = loaded_size;
    /* The time taken BEFORE the read, so a write that raced with it is seen again by the next
     * reload_if_changed() instead of being missed for good */
    etoken_mtime = statbuf.st_mtime;

    mdebug1("Loaded %d enrollment token(s) from '%s'.", etoken_tokens_size, etoken_path);

    return 0;
}

/**
 * @brief Rewrite the file atomically from the in-memory tokens. Caller holds the mutex.
 *
 * @return 0 on success, -1 on error (the file on disk is left as it was).
 */
static int etoken_store_save_locked(void) {
    cJSON *root = NULL;
    cJSON *array = NULL;
    char *text = NULL;
    File file = {NULL, NULL};
    mode_t old_umask;
    int i;

    if (etoken_path == NULL) {
        merror("The enrollment token store was used before etoken_store_init().");
        return -1;
    }

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", ETOKEN_STORE_VERSION);
    array = cJSON_AddArrayToObject(root, "tokens");

    for (i = 0; i < etoken_tokens_size; i++) {
        const etoken_entry_t *entry = &etoken_tokens[i];
        cJSON *item = cJSON_CreateObject();

        cJSON_AddStringToObject(item, "id", entry->id);

        if (entry->has_secret) {
            char *secret = w_b64url_encode(entry->secret, sizeof(entry->secret));

            if (secret == NULL) {
                cJSON_Delete(item);
                merror("Could not encode the secret of the enrollment token '%s'.", entry->id);
                goto error_json;
            }

            cJSON_AddStringToObject(item, "secret", secret);
            OPENSSL_cleanse(secret, strlen(secret));
            os_free(secret);
        } else {
            cJSON_AddNullToObject(item, "secret");
        }

        cJSON_AddStringToObject(item, "adr", entry->adr);

        if (entry->has_pin) {
            char *pin = w_b64url_encode(entry->pin, sizeof(entry->pin));

            if (pin == NULL) {
                cJSON_Delete(item);
                merror("Could not encode the pin of the enrollment token '%s'.", entry->id);
                goto error_json;
            }

            cJSON_AddStringToObject(item, "pin", pin);
            os_free(pin);
        } else {
            cJSON_AddNullToObject(item, "pin");
        }

        if (entry->ca_pem != NULL) {
            cJSON_AddStringToObject(item, "ca", entry->ca_pem);
        } else {
            cJSON_AddNullToObject(item, "ca");
        }

        cJSON_AddNumberToObject(item, "created", (double) entry->created);
        cJSON_AddNumberToObject(item, "expires", (double) entry->expires);
        cJSON_AddNumberToObject(item, "max_uses", (double) entry->max_uses);
        cJSON_AddNumberToObject(item, "uses", (double) entry->uses);
        /* A plain 0/1: cJSON_AddBoolToObject() takes a truth value, and the cJSON_False CONSTANT is 2 */
        cJSON_AddBoolToObject(item, "revoked", entry->revoked ? 1 : 0);

        if (entry->description != NULL) {
            cJSON_AddStringToObject(item, "description", entry->description);
        } else {
            cJSON_AddNullToObject(item, "description");
        }

        cJSON_AddItemToArray(array, item);
    }

    text = cJSON_PrintUnformatted(root);

    /* Every secret of every token is in that cJSON tree; wipe the copies before releasing them */
    for (i = 0; array != NULL && i < cJSON_GetArraySize(array); i++) {
        cJSON *secret = cJSON_GetObjectItem(cJSON_GetArrayItem(array, i), "secret");

        if (cJSON_IsString(secret) && secret->valuestring != NULL) {
            OPENSSL_cleanse(secret->valuestring, strlen(secret->valuestring));
        }
    }

    cJSON_Delete(root);
    root = NULL;

    if (text == NULL) {
        merror("Could not serialise the enrollment token store.");
        return -1;
    }

    /* Measured on the document that would be written, not estimated from the entry count: a store
     * of tokens that embed the CA is six times heavier than one of tokens that only pin it. Above
     * this, remoted's replica would refuse the file and keep serving the previous one without
     * saying so, so the write is refused instead and the caller undoes whatever it was adding */
    if (strlen(text) > W_ETOKEN_STORE_MAX_BYTES) {
        merror("The enrollment token store would take %zu bytes, over the %d byte limit. Purge the "
               "tokens that are no longer usable (--purge-enrollment-tokens).",
               strlen(text), W_ETOKEN_STORE_MAX_BYTES);
        OPENSSL_cleanse(text, strlen(text));
        os_free(text);
        return -2;
    }

    /* TempFile() creates the temporary file 0600 and, when the destination exists, copies its mode
     * onto it; the umask covers the remaining case (a first write) the same way
     * w_authd_load_password() does, and the explicit chmod() below settles both. Nothing is ever
     * reachable at a wider mode, not even between the create and the rename */
    old_umask = umask(0137);

    if (TempFile(&file, etoken_path, 0) < 0) {
        int saved_errno = errno;

        umask(old_umask);
        merror("Could not open a temporary file for '%s': %s", etoken_path, strerror(saved_errno));
        goto error_text;
    }

    umask(old_umask);

    if (fprintf(file.fp, "%s\n", text) < 0) {
        merror(FWRITE_ERROR, file.name, errno, strerror(errno));
        fclose(file.fp);
        goto error_file;
    }

    if (fclose(file.fp) != 0) {
        merror(FCLOSE_ERROR, file.name, errno, strerror(errno));
        goto error_file;
    }

    if (chmod(file.name, 0640) < 0) {
        merror("Could not set the mode of '%s': %s", file.name, strerror(errno));
        goto error_file;
    }

    if (OS_MoveFile(file.name, etoken_path) < 0) {
        merror("Could not write the enrollment token store '%s'.", etoken_path);
        goto error_file;
    }

    OPENSSL_cleanse(text, strlen(text));
    os_free(text);
    os_free(file.name);

    /* Our own write must not look like somebody else's: without this the next
     * reload_if_changed() would re-read the file we just produced */
    etoken_mtime = File_DateofChange(etoken_path);

    return 0;

error_json:
    cJSON_Delete(root);
    return -1;

error_file:
    unlink(file.name);
    os_free(file.name);

error_text:
    OPENSSL_cleanse(text, strlen(text));
    os_free(text);

    return -1;
}

void etoken_store_init(const char *path) {
    w_mutex_lock(&etoken_mutex);

    os_free(etoken_path);
    etoken_path = (path != NULL) ? strdup(path) : NULL;
    etoken_mtime = 0;

    w_mutex_unlock(&etoken_mutex);
}

int etoken_store_load(void) {
    int ret;

    w_mutex_lock(&etoken_mutex);
    ret = etoken_store_load_locked();
    w_mutex_unlock(&etoken_mutex);

    return ret;
}

int etoken_store_reload_if_changed(void) {
    time_t mtime;
    int ret = 0;

    w_mutex_lock(&etoken_mutex);

    if (etoken_path == NULL) {
        w_mutex_unlock(&etoken_mutex);
        merror("The enrollment token store was used before etoken_store_init().");
        return -1;
    }

    mtime = File_DateofChange(etoken_path);

    if (mtime < 0) {
        /* The file is not there right now. A worker's replica must survive that: the cluster
         * replaces this file by renaming a freshly downloaded copy over it, and a store emptied in
         * that window would refuse every token an agent presents until the next sync */
        etoken_mtime = (etoken_tokens_size > 0) ? etoken_mtime : 0;
    } else if (mtime != etoken_mtime) {
        ret = (etoken_store_load_locked() == 0) ? 1 : -1;
    }

    w_mutex_unlock(&etoken_mutex);

    return ret;
}

int etoken_store_create(const etoken_mint_t *mint, time_t now, cJSON **data) {
    etoken_entry_t entry;
    w_etoken_t token;
    uint8_t id_bytes[W_ETOKEN_ID_BYTES];
    char summary[OS_SIZE_1024];
    char *text = NULL;
    char *id = NULL;
    int attempt;
    int index;
    int saved;

    if (data == NULL) {
        return -1;
    }

    *data = NULL;

    /* The contract of etoken_mint_prepare(): anything reaching here has already been refused with a
     * detail the operator can act on, so a violation is a bug in the caller, not bad input */
    if (mint == NULL || mint->adr == NULL || mint->ttl <= 0 ||
        (mint->has_pin == (mint->ca_pem != NULL))) {
        merror("Cannot mint an enrollment token: the request carries no endpoint, no lifetime or "
               "not exactly one anchor.");
        return -1;
    }

    memset(&entry, 0, sizeof(entry));

    w_mutex_lock(&etoken_mutex);

    /* The cap counts live tokens: a store full of revoked, expired or exhausted ones is not full,
     * it is dirty. Clean it here -- the same purge the operator can run by hand -- and refuse only
     * when that many tokens are genuinely usable. The cleanup is persisted at once so memory and
     * file never disagree, whatever happens to the mint afterwards */
    if (etoken_tokens_size >= ETOKEN_MAX_TOKENS) {
        int freed = etoken_purge_locked(ETOKEN_PURGE_DEAD, now, NULL);

        if (freed > 0) {
            minfo("Purged %d enrollment token(s) that could no longer authorise an enrollment to "
                  "make room in the store.", freed);

            if (etoken_store_save_locked() < 0) {
                w_mutex_unlock(&etoken_mutex);
                return -1;
            }
        }

        if (etoken_tokens_size >= ETOKEN_MAX_TOKENS) {
            w_mutex_unlock(&etoken_mutex);
            return ETOKEN_CREATE_FULL;
        }
    }

    for (attempt = 0; attempt < ETOKEN_ID_ATTEMPTS; attempt++) {
        if (RAND_bytes(id_bytes, sizeof(id_bytes)) != 1) {
            w_mutex_unlock(&etoken_mutex);
            merror("Unable to mint an enrollment token: the CSPRNG (RAND_bytes) failed.");
            return -1;
        }

        if (id = w_b64url_encode(id_bytes, sizeof(id_bytes)), id == NULL) {
            w_mutex_unlock(&etoken_mutex);
            merror("Unable to mint an enrollment token: the identifier could not be encoded.");
            return -1;
        }

        if (etoken_find_locked(id) < 0) {
            break;
        }

        os_free(id);
    }

    if (id == NULL) {
        w_mutex_unlock(&etoken_mutex);
        merror("Unable to mint an enrollment token: no free identifier was drawn.");
        return -1;
    }

    memcpy(entry.id, id, ETOKEN_ID_CHARS + 1);
    os_free(id);

    if (!mint->no_credential) {
        /* Straight from the CSPRNG, never os_random(): this is what proves to the manager that
         * whoever enrolls was handed the token, and it is valid for as long as the token is */
        if (RAND_bytes(entry.secret, sizeof(entry.secret)) != 1) {
            w_mutex_unlock(&etoken_mutex);
            OPENSSL_cleanse(entry.secret, sizeof(entry.secret));
            merror("Unable to mint an enrollment token: the CSPRNG (RAND_bytes) failed.");
            return -1;
        }

        entry.has_secret = 1;
    }

    os_strdup(mint->adr, entry.adr);
    entry.has_pin = mint->has_pin;
    memcpy(entry.pin, mint->pin, sizeof(entry.pin));

    if (mint->ca_pem != NULL) {
        os_strdup(mint->ca_pem, entry.ca_pem);
    }

    entry.created = now;
    entry.expires = now + (time_t) mint->ttl;
    entry.max_uses = mint->max_uses;
    entry.uses = 0;
    entry.revoked = 0;

    if (mint->description != NULL) {
        os_strdup(mint->description, entry.description);
    }

    /* The token text: the only copy of the secret that ever leaves this process */
    memset(&token, 0, sizeof(token));
    token.ver = 1;
    token.adr = entry.adr;
    token.has_pin = entry.has_pin;
    memcpy(token.pin, entry.pin, sizeof(token.pin));
    token.ca_pem = entry.ca_pem;
    token.has_key = entry.has_secret;
    memcpy(token.id, id_bytes, sizeof(token.id));
    memcpy(token.secret, entry.secret, sizeof(token.secret));

    text = w_etoken_encode(&token);
    OPENSSL_cleanse(token.secret, sizeof(token.secret));

    if (text == NULL) {
        w_mutex_unlock(&etoken_mutex);
        merror("Could not encode an enrollment token for the endpoint '%s'.", entry.adr);
        etoken_entry_free(&entry);
        return -1;
    }

    index = etoken_tokens_size;
    os_realloc(etoken_tokens, sizeof(etoken_entry_t) * (etoken_tokens_size + 1), etoken_tokens);
    etoken_tokens[index] = entry;
    etoken_tokens_size++;

    if (saved = etoken_store_save_locked(), saved < 0) {
        /* Nothing is kept in memory either: a token authd cannot persist is a token a restart or a
         * worker would not honour, and handing one out would be worse than refusing the request.
         * This is also what enforces the byte ceiling: the entry is undone and the caller learns
         * which of the two limits stopped it */
        etoken_entry_free(&etoken_tokens[index]);
        etoken_tokens_size--;
        w_mutex_unlock(&etoken_mutex);
        OPENSSL_cleanse(text, strlen(text));
        os_free(text);
        return saved == -2 ? ETOKEN_CREATE_TOOBIG : -1;
    }

    /* Loud before it hurts: the operator still has room, but not much, and the fix (a purge) takes
     * one command */
    if (etoken_tokens_size * 5 >= ETOKEN_MAX_TOKENS * 4) {
        mwarn("The enrollment token store holds %d of the %d tokens it accepts. Purge the ones that "
              "are no longer usable (--purge-enrollment-tokens).", etoken_tokens_size, ETOKEN_MAX_TOKENS);
    }

    *data = cJSON_CreateObject();
    cJSON_AddStringToObject(*data, "token", text);
    cJSON_AddStringToObject(*data, "id", entry.id);
    cJSON_AddStringToObject(*data, "adr", entry.adr);
    cJSON_AddNumberToObject(*data, "expires", (double) entry.expires);

    if (entry.has_pin) {
        char hex[W_ETOKEN_PIN_BYTES * 2 + 1];

        /* The same pin the token carries, in the form an operator can compare against
         * `openssl x509 -pubkey | openssl dgst -sha256` output */
        etoken_hex(entry.pin, sizeof(entry.pin), hex);
        cJSON_AddStringToObject(*data, "pin_hex", hex);
    }

    OPENSSL_cleanse(text, strlen(text));
    os_free(text);

    /* Rendered before the mutex is released, because `adr` and `description` belong to the entry in
     * the array and a concurrent reload would replace it -- but LOGGED afterwards, so nothing that
     * writes to a file or a socket runs while the enrollment threads are waiting for the store */
    snprintf(summary, sizeof(summary),
             "Enrollment token '%s' minted for '%s' (expires %ld, max_uses %u, credential %s)%s%s",
             entry.id, entry.adr, (long) entry.expires, entry.max_uses,
             entry.has_secret ? "yes" : "no",
             entry.description != NULL ? ", description " : "",
             entry.description != NULL ? entry.description : "");

    w_mutex_unlock(&etoken_mutex);

    /* The identifier, the endpoint and the limits: never the secret, and never the token text */
    minfo("%s", summary);

    return 0;
}

cJSON *etoken_store_list(void) {
    cJSON *array = cJSON_CreateArray();
    int i;

    w_mutex_lock(&etoken_mutex);

    for (i = 0; i < etoken_tokens_size; i++) {
        const etoken_entry_t *entry = &etoken_tokens[i];
        cJSON *item = cJSON_CreateObject();

        cJSON_AddStringToObject(item, "id", entry->id);
        cJSON_AddStringToObject(item, "adr", entry->adr);
        cJSON_AddNumberToObject(item, "created", (double) entry->created);
        cJSON_AddNumberToObject(item, "expires", (double) entry->expires);
        cJSON_AddNumberToObject(item, "max_uses", (double) entry->max_uses);
        cJSON_AddNumberToObject(item, "uses", (double) entry->uses);
        cJSON_AddBoolToObject(item, "revoked", entry->revoked ? 1 : 0);
        /* Whether the token needs a credential to be used, never the credential itself: this
         * answer is what tells an operator which tokens are public information */
        cJSON_AddBoolToObject(item, "credential", entry->has_secret ? 1 : 0);

        if (entry->description != NULL) {
            cJSON_AddStringToObject(item, "description", entry->description);
        } else {
            cJSON_AddNullToObject(item, "description");
        }

        cJSON_AddItemToArray(array, item);
    }

    w_mutex_unlock(&etoken_mutex);

    return array;
}

int etoken_store_revoke(const char *id) {
    int index;
    int ret = 0;

    w_mutex_lock(&etoken_mutex);

    if (index = etoken_find_locked(id), index < 0) {
        w_mutex_unlock(&etoken_mutex);
        mdebug1("Cannot revoke the enrollment token '%s': unknown identifier.", id != NULL ? id : "");
        return -1;
    }

    if (etoken_tokens[index].revoked) {
        /* Idempotent and free: rewriting the file would make the cluster ship an identical store */
        w_mutex_unlock(&etoken_mutex);
        mdebug1("The enrollment token '%s' was already revoked.", id);
        return 0;
    }

    etoken_tokens[index].revoked = 1;

    /* The flag stays set in memory even when the file could not be written: this authd must not
     * keep honouring a token an operator has revoked, and the next successful write persists it */
    if (etoken_store_save_locked() < 0) {
        ret = -1;
    }

    w_mutex_unlock(&etoken_mutex);

    if (ret == 0) {
        minfo("Enrollment token '%s' revoked.", id);
    }

    return ret;
}

int etoken_store_purge(etoken_purge_t scope, time_t now, cJSON **ids) {
    cJSON *removed_ids = cJSON_CreateArray();
    int removed;

    w_mutex_lock(&etoken_mutex);

    removed = etoken_purge_locked(scope, now, removed_ids);

    /* An empty purge leaves the file alone on purpose: rewriting it would change its mtime and make
     * every node that watches it (remoted's replica, the cluster sync) reload a file that says
     * exactly what it said before */
    if (removed > 0 && etoken_store_save_locked() < 0) {
        w_mutex_unlock(&etoken_mutex);
        cJSON_Delete(removed_ids);

        /* The tokens are gone from memory but not from the file. Reading it back is what puts the
         * two in agreement again, and it is cheaper to be wrong in the safe direction: until the
         * reload, this authd simply refuses tokens it would have accepted */
        merror("Could not persist the enrollment token purge; reloading the store from disk.");
        etoken_store_load();

        return -1;
    }

    w_mutex_unlock(&etoken_mutex);

    if (removed > 0) {
        minfo("Purged %d enrollment token(s) (%s).", removed,
              scope == ETOKEN_PURGE_ALL ? "all" : "no longer usable");
    }

    if (ids != NULL) {
        *ids = removed_ids;
    } else {
        cJSON_Delete(removed_ids);
    }

    return removed;
}

etoken_use_t etoken_store_consume(const char *id, time_t now) {
    etoken_use_t ret = ETOKEN_USE_OK;
    int index;
    int saved = 0;

    w_mutex_lock(&etoken_mutex);

    index = etoken_find_locked(id);

    /* An unknown id and a revoked one answer alike, here and on the wire (9022): telling them apart
     * would turn the enrollment endpoint into an oracle for which tokens exist */
    if (index < 0 || etoken_tokens[index].revoked) {
        ret = ETOKEN_USE_NOT_FOUND;
    } else if (now >= etoken_tokens[index].expires) {
        ret = ETOKEN_USE_EXPIRED;
    } else if (etoken_tokens[index].max_uses != 0 &&
               etoken_tokens[index].uses >= etoken_tokens[index].max_uses) {
        ret = ETOKEN_USE_EXHAUSTED;
    } else {
        etoken_tokens[index].uses++;
        /* Held until the enrollment either commits or gives the use back: while it is held, a
         * concurrent purge leaves the entry alone */
        etoken_inflight_hold_locked(etoken_tokens[index].id);
        saved = (etoken_store_save_locked() == 0);
    }

    w_mutex_unlock(&etoken_mutex);

    switch (ret) {
    case ETOKEN_USE_OK:
        if (!saved) {
            /* Best effort on purpose: the use is counted in memory and the enrollment goes ahead.
             * Failing it over a disk hiccup would deny a legitimate agent, and the worst a lost
             * counter can do is grant one extra use of a token that is still bounded by its expiry */
            merror("Could not persist the use of the enrollment token '%s'; the enrollment continues.", id);
        }

        mdebug2("Enrollment token '%s' consumed.", id);
        break;
    case ETOKEN_USE_NOT_FOUND:
        mdebug1("The enrollment token '%s' is unknown or revoked.", id != NULL ? id : "");
        break;
    case ETOKEN_USE_EXPIRED:
        mdebug1("The enrollment token '%s' expired.", id);
        break;
    case ETOKEN_USE_EXHAUSTED:
        mdebug1("The enrollment token '%s' has no uses left.", id);
        break;
    }

    return ret;
}

void etoken_store_release(const char *id) {
    int index;
    int released = 0;

    if (id == NULL) {
        return;
    }

    w_mutex_lock(&etoken_mutex);

    /* Unconditionally: the reservation is dropped even when the use cannot be given back, so a
     * token is never left unpurgeable by an enrollment that is over */
    etoken_inflight_drop_locked(id);

    if (index = etoken_find_locked(id), index >= 0 && etoken_tokens[index].uses > 0) {
        etoken_tokens[index].uses--;
        etoken_store_save_locked();
        released = 1;
    }

    w_mutex_unlock(&etoken_mutex);

    if (released) {
        mdebug2("Use of the enrollment token '%s' released.", id);
    } else {
        mdebug2("Nothing to release for the enrollment token '%s'.", id);
    }
}

void etoken_store_commit(const char *id) {
    if (id == NULL) {
        return;
    }

    w_mutex_lock(&etoken_mutex);
    etoken_inflight_drop_locked(id);
    w_mutex_unlock(&etoken_mutex);

    mdebug2("Use of the enrollment token '%s' committed.", id);
}

int etoken_store_count(void) {
    int count;

    w_mutex_lock(&etoken_mutex);
    count = etoken_tokens_size;
    w_mutex_unlock(&etoken_mutex);

    return count;
}

void etoken_store_free(void) {
    w_mutex_lock(&etoken_mutex);

    etoken_clear_locked();
    /* Reservations do not survive dropping the tokens they reserve: this is the teardown, not a
     * reload */
    os_free(etoken_inflight);
    etoken_inflight_size = 0;
    /* The path survives: this function drops the tokens, it does not un-initialise the module, so
     * a caller (and every test fixture) can load the store again right afterwards */
    etoken_mtime = 0;

    w_mutex_unlock(&etoken_mutex);
}

void etoken_mint_free(etoken_mint_t *mint) {
    if (mint == NULL) {
        return;
    }

    os_free(mint->adr);
    os_free(mint->ca_pem);
    os_free(mint->description);
    memset(mint, 0, sizeof(*mint));
}
