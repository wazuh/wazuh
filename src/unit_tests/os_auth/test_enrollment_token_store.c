/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The enrollment token store: the file etc/enrollment_tokens.json, and every rule that decides
 * whether a token an agent presents may still be used.
 *
 * These cases work on REAL files in a temporary directory, because the file is the point: it is the
 * only durable state, it is what the cluster ships to the workers, and it holds credential material
 * -- so its mode, its atomicity and what it does NOT contain are as much part of the contract as
 * the return codes. Stubbing the I/O away would leave almost nothing worth asserting.
 *
 * Two things shape how the cases are written. The log functions are wrapped, so every line the code
 * under test emits has to be declared, and an undeclared one aborts cmocka from inside whatever
 * lock the code was holding -- which hangs the run instead of failing it. That is why every case
 * opens by declaring the severities its own paths emit (see expect_any_mdebug1() below). And the
 * store's modification-time
 * bookkeeping is second-granular, so a case that needs "the file changed" sets the time with
 * utime() rather than hoping a second elapsed.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <utime.h>

#include "shared.h"
#include "enrollment_token_store.h"
#include "enrollment_token.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/// Where the fixture puts the store, relative to the temporary directory it chdir()s into.
#define STORE_PATH "etc/enrollment_tokens.json"

/// A syntactically valid identifier that no case ever mints: 16 zero bytes.
#define UNKNOWN_ID "AAAAAAAAAAAAAAAAAAAAAA"

/* enrollment_token_mint.c's endpoint builder, reachable because that file #defines static away
 * under WAZUH_UNIT_TESTING -- the same seam auth.c uses for its file-scope state. Covered here
 * because the prefix and port rules it implements are the ones an operator cannot see going wrong:
 * a token with the wrong endpoint fails in the field, on the agent, long after distribution. */
char *etoken_adr_build(const char *address, long port, const char *prefix);

static char test_cwd[PATH_MAX];
static char test_dir[PATH_MAX];

/* --- Fixtures ---------------------------------------------------------------------------------- */

static int setup_group(void **state) {
    (void)state;

    assert_non_null(getcwd(test_cwd, sizeof(test_cwd)));

    snprintf(test_dir, sizeof(test_dir), "/tmp/wazuh_etoken_XXXXXX");
    assert_non_null(mkdtemp(test_dir));
    assert_int_equal(chdir(test_dir), 0);
    assert_int_equal(mkdir("etc", 0770), 0);

    return 0;
}

static int teardown_group(void **state) {
    (void)state;

    unlink(STORE_PATH);
    rmdir("etc");
    assert_int_equal(chdir(test_cwd), 0);
    rmdir(test_dir);

    return 0;
}

/* The store's log surface, declared per case as "any, always": WHAT a message says is not what
 * these cases are about, and the one promise the store makes about its logs -- that none of them
 * carries a secret -- is asserted where the secret is (test_list_never_includes_secret).
 *
 * It cannot be one blanket declaration in the fixture, for two reasons that pull the same way. A
 * log line the code emits but the case did not declare aborts cmocka from inside the store's mutex,
 * which hangs the run rather than failing it; and a declaration the code never REACHES fails the
 * case in its own right ("still has values that haven't been checked"). So each case declares
 * exactly the severities its paths produce:
 *
 *   mdebug1  every case: TempFile() logs one the first time it writes a path that does not exist
 *            yet, an absent store logs one, and every refusal of a token is one
 *   minfo    any case that mints or revokes
 *   mdebug2  only where a use is consumed or released
 *   mwarn    only where a load fails, or where an entry of the file is dropped
 *   merror   the storage failures (break_storage(), which points the store at a path that cannot be
 *            written) and the mint refusals that come from the request itself. Still NOT declared
 *            anywhere else, so a case that starts emitting one says so loudly instead of hiding it
 */
#define expect_any_mdebug1() expect_any_always(__wrap__mdebug1, formatted_msg)
#define expect_any_mdebug2() expect_any_always(__wrap__mdebug2, formatted_msg)
#define expect_any_minfo()   expect_any_always(__wrap__minfo, formatted_msg)
#define expect_any_mwarn()   expect_any_always(__wrap__mwarn, formatted_msg)
#define expect_any_merror()  expect_any_always(__wrap__merror, formatted_msg)

static int setup_store(void **state) {
    (void)state;

    etoken_store_free();
    unlink(STORE_PATH);
    etoken_store_init(STORE_PATH);

    return 0;
}

static int teardown_store(void **state) {
    (void)state;

    etoken_store_free();
    unlink(STORE_PATH);

    return 0;
}

/* --- Helpers ----------------------------------------------------------------------------------- */

/// A pin that is easy to recognise once it has travelled through the file and the token text.
#define TEST_PIN_BYTE 0xAB

/**
 * @brief A validated mint request, as enrollment_token_mint.c would hand it over.
 */
static void build_mint(etoken_mint_t *mint, const char *adr, long ttl, unsigned int max_uses,
                       const char *description, int no_credential) {
    memset(mint, 0, sizeof(*mint));

    os_strdup(adr, mint->adr);
    mint->has_pin = 1;
    memset(mint->pin, TEST_PIN_BYTE, sizeof(mint->pin));
    mint->ttl = ttl;
    mint->max_uses = max_uses;
    mint->no_credential = no_credential;

    if (description != NULL) {
        os_strdup(description, mint->description);
    }
}

/**
 * @brief Mint a token and return what the caller would be answered with.
 */
static cJSON *mint_token(const char *adr, long ttl, unsigned int max_uses, const char *description,
                         int no_credential) {
    etoken_mint_t mint;
    cJSON *data = NULL;

    build_mint(&mint, adr, ttl, max_uses, description, no_credential);
    assert_int_equal(etoken_store_create(&mint, time(NULL), &data), 0);
    etoken_mint_free(&mint);

    assert_non_null(data);

    return data;
}

/// The identifier of a token, copied out of the answer so it survives its cJSON.
static void copy_string(char *out, size_t size, const cJSON *object, const char *member) {
    const cJSON *item = cJSON_GetObjectItem((cJSON *)object, member);

    assert_true(cJSON_IsString((cJSON *)item));
    snprintf(out, size, "%s", item->valuestring);
}

/// The `tokens` array of the file as it is on disk right now.
static cJSON *read_store_file(cJSON **root) {
    cJSON *array = NULL;

    *root = json_fread(STORE_PATH, 0);
    assert_non_null(*root);

    array = cJSON_GetObjectItem(*root, "tokens");
    assert_true(cJSON_IsArray(array));

    return array;
}

/// The `uses` counter the file records for @p id.
static int file_uses_of(const char *id) {
    cJSON *root = NULL;
    cJSON *array = read_store_file(&root);
    cJSON *item = NULL;
    int uses = -1;

    cJSON_ArrayForEach(item, array) {
        const cJSON *token_id = cJSON_GetObjectItem(item, "id");

        if (cJSON_IsString((cJSON *)token_id) && strcmp(token_id->valuestring, id) == 0) {
            uses = cJSON_GetObjectItem(item, "uses")->valueint;
        }
    }

    cJSON_Delete(root);

    return uses;
}

/// Whether the FILE (not memory) says that token is revoked; -1 when the id is not in it.
static int file_revoked_of(const char *id) {
    cJSON *root = NULL;
    cJSON *array = read_store_file(&root);
    cJSON *item = NULL;
    int revoked = -1;

    cJSON_ArrayForEach(item, array) {
        const cJSON *token_id = cJSON_GetObjectItem(item, "id");

        if (cJSON_IsString((cJSON *)token_id) && strcmp(token_id->valuestring, id) == 0) {
            revoked = cJSON_IsTrue(cJSON_GetObjectItem(item, "revoked")) ? 1 : 0;
        }
    }

    cJSON_Delete(root);

    return revoked;
}

/// Point the store at a path under a directory that does not exist: every save fails from now on,
/// which is how these cases reproduce a storage failure without depending on file permissions
/// (the tests run as root, so a read-only directory would not stop a write).
static void break_storage(void) {
    etoken_store_init("etc/no-such-directory/enrollment_tokens.json");
}

/// Put the store back on its real file.
static void restore_storage(void) {
    etoken_store_init(STORE_PATH);
}

/// Move the file's modification time forward, so the store sees a change it did not make itself.
static void touch_store_file(time_t when) {
    struct utimbuf times = {when, when};

    assert_int_equal(utime(STORE_PATH, &times), 0);
}

/* --- Loading ----------------------------------------------------------------------------------- */

static void test_load_absent_file_is_empty(void **state) {
    (void)state;

    expect_any_mdebug1();

    /* Not an error: the file only comes into existence with the first token, and a worker has none
     * until the master's first sync */
    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_count(), 0);
}

static void test_malformed_file_keeps_previous_and_warns(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();
    expect_any_mwarn();

    cJSON *data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    char id[ETOKEN_ID_CHARS + 1] = {0};
    FILE *fp = NULL;

    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    fp = fopen(STORE_PATH, "w");
    assert_non_null(fp);
    assert_true(fputs("{\"version\":1,\"tokens\":", fp) >= 0);
    fclose(fp);
    touch_store_file(time(NULL) + 2);

    /* The load fails, and that is where it ends: the tokens already in memory are what this authd
     * keeps answering enrollments with while somebody fixes the file */
    assert_int_equal(etoken_store_reload_if_changed(), -1);
    assert_int_equal(etoken_store_count(), 1);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
}

/* --- Minting ----------------------------------------------------------------------------------- */

static void test_create_persists_atomically_with_mode_0640(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_minfo();

    cJSON *data = mint_token("wazuh-1", 60, 2, "ci", 0);
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *item = NULL;
    struct stat statbuf;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    int leftovers = 0;

    /* What the operator is answered: the token itself (once), and enough to identify it later */
    assert_true(cJSON_IsString(cJSON_GetObjectItem(data, "token")));
    assert_true(cJSON_IsString(cJSON_GetObjectItem(data, "id")));
    assert_string_equal(cJSON_GetObjectItem(data, "adr")->valuestring, "wazuh-1");
    assert_true(cJSON_IsNumber(cJSON_GetObjectItem(data, "expires")));
    assert_true(cJSON_IsString(cJSON_GetObjectItem(data, "pin_hex")));
    assert_int_equal(strlen(cJSON_GetObjectItem(data, "pin_hex")->valuestring), W_ETOKEN_PIN_BYTES * 2);

    /* 0640: readable by the manager group, never by the rest of the host. The temporary file is
     * created 0600 and chmod()ed before the rename, so there is no window at a wider mode either */
    assert_int_equal(stat(STORE_PATH, &statbuf), 0);
    assert_int_equal(statbuf.st_mode & 0777, 0640);

    /* Nothing left behind: a failed or abandoned rewrite would leave its TempFile() next to the
     * store, holding every secret at whatever mode it was created with */
    dir = opendir("etc");
    assert_non_null(dir);

    while (entry = readdir(dir), entry != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, "enrollment_tokens.json") == 0) {
            continue;
        }

        leftovers++;
    }

    closedir(dir);
    assert_int_equal(leftovers, 0);

    array = read_store_file(&root);
    assert_int_equal(cJSON_GetObjectItem(root, "version")->valueint, 1);
    assert_int_equal(cJSON_GetArraySize(array), 1);

    item = cJSON_GetArrayItem(array, 0);
    assert_int_equal(strlen(cJSON_GetObjectItem(item, "secret")->valuestring), 22);
    assert_int_equal(strlen(cJSON_GetObjectItem(item, "pin")->valuestring), 43);
    assert_int_equal(cJSON_GetObjectItem(item, "uses")->valueint, 0);
    assert_false(cJSON_IsTrue(cJSON_GetObjectItem(item, "revoked")));
    assert_string_equal(cJSON_GetObjectItem(item, "description")->valuestring, "ci");

    cJSON_Delete(root);
    cJSON_Delete(data);
}

static void test_create_roundtrip_load(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_minfo();

    cJSON *data = mint_token("wazuh-1", 3600, 5, "roundtrip", 0);
    cJSON *list = NULL;
    cJSON *item = NULL;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    char text[1024] = {0};
    long expires;
    w_etoken_t token;
    uint8_t *id_bytes = NULL;
    size_t id_len = 0;
    uint8_t expected_pin[W_ETOKEN_PIN_BYTES];

    copy_string(id, sizeof(id), data, "id");
    copy_string(text, sizeof(text), data, "token");
    expires = (long)cJSON_GetObjectItem(data, "expires")->valuedouble;
    cJSON_Delete(data);

    /* Everything the store knows has to come back from the file alone: on a worker, that file is
     * all there ever is */
    etoken_store_free();
    assert_int_equal(etoken_store_count(), 0);
    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_count(), 1);

    list = etoken_store_list();
    assert_int_equal(cJSON_GetArraySize(list), 1);

    item = cJSON_GetArrayItem(list, 0);
    assert_string_equal(cJSON_GetObjectItem(item, "id")->valuestring, id);
    assert_string_equal(cJSON_GetObjectItem(item, "adr")->valuestring, "wazuh-1");
    assert_int_equal((long)cJSON_GetObjectItem(item, "expires")->valuedouble, expires);
    assert_int_equal(cJSON_GetObjectItem(item, "max_uses")->valueint, 5);
    assert_string_equal(cJSON_GetObjectItem(item, "description")->valuestring, "roundtrip");
    cJSON_Delete(list);

    /* And the token text the operator was handed has to be the token this entry describes */
    assert_int_equal(w_etoken_decode(text, &token), ETOKEN_OK);
    assert_string_equal(token.adr, "wazuh-1");
    memset(expected_pin, TEST_PIN_BYTE, sizeof(expected_pin));
    assert_memory_equal(token.pin, expected_pin, sizeof(expected_pin));
    assert_int_equal(token.has_key, 1);

    assert_int_equal(w_b64url_decode(id, &id_bytes, &id_len), 0);
    assert_int_equal(id_len, W_ETOKEN_ID_BYTES);
    assert_memory_equal(token.id, id_bytes, W_ETOKEN_ID_BYTES);
    os_free(id_bytes);

    w_etoken_free(&token);
}

/* --- Listing ----------------------------------------------------------------------------------- */

static void test_list_never_includes_secret(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_minfo();

    cJSON *credential = mint_token("wazuh-1", 3600, 0, NULL, 0);
    cJSON *anonymous = mint_token("wazuh-2", 3600, 0, NULL, 1);
    char id_credential[ETOKEN_ID_CHARS + 1] = {0};
    char id_anonymous[ETOKEN_ID_CHARS + 1] = {0};
    char text[1024] = {0};
    cJSON *list = NULL;
    cJSON *item = NULL;
    char *list_text = NULL;
    char *secret_b64 = NULL;
    w_etoken_t token;

    copy_string(id_credential, sizeof(id_credential), credential, "id");
    copy_string(text, sizeof(text), credential, "token");
    copy_string(id_anonymous, sizeof(id_anonymous), anonymous, "id");
    cJSON_Delete(credential);
    cJSON_Delete(anonymous);

    list = etoken_store_list();
    assert_int_equal(cJSON_GetArraySize(list), 2);

    cJSON_ArrayForEach(item, list) {
        const char *id = cJSON_GetObjectItem(item, "id")->valuestring;

        /* The two members that would turn a listing into a credential dump */
        assert_null(cJSON_GetObjectItem(item, "secret"));
        assert_null(cJSON_GetObjectItem(item, "token"));

        if (strcmp(id, id_credential) == 0) {
            assert_true(cJSON_IsTrue(cJSON_GetObjectItem(item, "credential")));
        } else {
            assert_string_equal(id, id_anonymous);
            assert_false(cJSON_IsTrue(cJSON_GetObjectItem(item, "credential")));
        }
    }

    /* Belt and braces: the secret is looked for in the rendered text, not just in the members this
     * case knows to check */
    assert_int_equal(w_etoken_decode(text, &token), ETOKEN_OK);
    secret_b64 = w_b64url_encode(token.secret, sizeof(token.secret));
    assert_non_null(secret_b64);
    w_etoken_free(&token);

    list_text = cJSON_PrintUnformatted(list);
    assert_non_null(list_text);
    assert_null(strstr(list_text, secret_b64));

    os_free(list_text);
    os_free(secret_b64);
    cJSON_Delete(list);
}

/* --- Consuming --------------------------------------------------------------------------------- */

static void test_consume_ok_unlimited(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    cJSON *data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    char id[ETOKEN_ID_CHARS + 1] = {0};

    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    /* max_uses 0 is "unlimited": the expiry is the only bound */
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);

    /* Persisted, not just counted: a restart or a failover must not restore the uses */
    assert_int_equal(file_uses_of(id), 3);
}

static void test_consume_exhausted_after_max_uses(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    cJSON *data = mint_token("wazuh-1", 3600, 2, NULL, 0);
    char id[ETOKEN_ID_CHARS + 1] = {0};

    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_EXHAUSTED);

    /* The refusal costs no use: the counter stops where the limit is */
    assert_int_equal(file_uses_of(id), 2);
}

static void test_consume_revoked_and_expired(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_minfo();

    cJSON *data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    char revoked[ETOKEN_ID_CHARS + 1] = {0};
    char expired[ETOKEN_ID_CHARS + 1] = {0};
    time_t now = time(NULL);

    copy_string(revoked, sizeof(revoked), data, "id");
    cJSON_Delete(data);

    assert_int_equal(etoken_store_revoke(revoked), 0);
    /* A revoked token answers exactly like one that never existed: the enrollment endpoint must not
     * become an oracle for which identifiers are real */
    assert_int_equal(etoken_store_consume(revoked, now), ETOKEN_USE_NOT_FOUND);

    data = mint_token("wazuh-2", 1, 0, NULL, 0);
    copy_string(expired, sizeof(expired), data, "id");
    cJSON_Delete(data);

    assert_int_equal(etoken_store_consume(expired, now + 2), ETOKEN_USE_EXPIRED);

    assert_int_equal(etoken_store_consume(UNKNOWN_ID, now), ETOKEN_USE_NOT_FOUND);
}

static void test_release_undoes_a_reserved_use(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    cJSON *data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    char id[ETOKEN_ID_CHARS + 1] = {0};

    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
    assert_int_equal(file_uses_of(id), 1);

    /* The enrollment failed after the use was reserved: giving it back is what keeps a
     * single-use token from being burned by a duplicate name or a full agent limit */
    etoken_store_release(id);
    assert_int_equal(file_uses_of(id), 0);

    /* Nothing to give back, and nothing to break: this runs on an error path */
    etoken_store_release(UNKNOWN_ID);
    assert_int_equal(file_uses_of(id), 0);
}

/* --- Revoking ---------------------------------------------------------------------------------- */

static void test_revoke_unknown_and_idempotent(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_minfo();

    cJSON *data = NULL;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    time_t marker = time(NULL) - 10;

    assert_int_equal(etoken_store_revoke(UNKNOWN_ID), -1);

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    assert_int_equal(etoken_store_revoke(id), 0);

    /* A second revoke is a success with nothing to do. Proven through the file: rewriting it would
     * make the cluster ship an identical store to every worker */
    touch_store_file(marker);
    assert_int_equal(etoken_store_revoke(id), 0);
    assert_int_equal(File_DateofChange(STORE_PATH), marker);
}

/* --- Reloading --------------------------------------------------------------------------------- */

static void test_reload_if_changed_picks_up_external_write(void **state) {
    (void)state;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    cJSON *data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *external = NULL;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    uint8_t id_bytes[W_ETOKEN_ID_BYTES];
    uint8_t pin_bytes[W_ETOKEN_PIN_BYTES];
    char *external_id = NULL;
    char *external_pin = NULL;
    size_t i;

    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    /* What a cluster sync looks like from here: the file is replaced by the master's version, which
     * revoked the first token and added one this node has never seen */
    array = read_store_file(&root);
    cJSON_ReplaceItemInObject(cJSON_GetArrayItem(array, 0), "revoked", cJSON_CreateTrue());

    for (i = 0; i < sizeof(id_bytes); i++) {
        id_bytes[i] = (uint8_t)i;
    }

    memset(pin_bytes, 0x01, sizeof(pin_bytes));
    external_id = w_b64url_encode(id_bytes, sizeof(id_bytes));
    external_pin = w_b64url_encode(pin_bytes, sizeof(pin_bytes));
    assert_non_null(external_id);
    assert_non_null(external_pin);

    external = cJSON_CreateObject();
    cJSON_AddStringToObject(external, "id", external_id);
    cJSON_AddNullToObject(external, "secret");
    cJSON_AddStringToObject(external, "adr", "wazuh-2");
    cJSON_AddStringToObject(external, "pin", external_pin);
    cJSON_AddNullToObject(external, "ca");
    cJSON_AddNumberToObject(external, "created", (double)time(NULL));
    cJSON_AddNumberToObject(external, "expires", (double)(time(NULL) + 3600));
    cJSON_AddNumberToObject(external, "max_uses", 0);
    cJSON_AddNumberToObject(external, "uses", 0);
    cJSON_AddBoolToObject(external, "revoked", 0);
    cJSON_AddNullToObject(external, "description");
    cJSON_AddItemToArray(array, external);

    assert_int_equal(json_fwrite(STORE_PATH, root), 0);
    cJSON_Delete(root);
    touch_store_file(time(NULL) + 2);

    assert_int_equal(etoken_store_reload_if_changed(), 1);
    assert_int_equal(etoken_store_count(), 2);

    /* The master's decisions, not this node's: the local copy of the first token said nothing about
     * being revoked */
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_NOT_FOUND);
    assert_int_equal(etoken_store_consume(external_id, time(NULL)), ETOKEN_USE_OK);

    os_free(external_id);
    os_free(external_pin);
}

/* --- Purge, cap and byte ceiling (issue #38994) ------------------------------------------------- */

/**
 * @brief Write a store file of @p count synthetic tokens and load it.
 *
 * Composing the file instead of minting is what makes the cap cases affordable: 5000 mints would be
 * 5000 rewrites of a growing file. @p expires_in is added to now (negative for an expired token),
 * @p uses / @p max_uses drive the exhausted case and @p ca_filler, when non-zero, gives every entry
 * a `ca` of that many characters so the document crosses the byte ceiling instead of the count one.
 */
static void write_store_of(int count, long expires_in, unsigned int uses, unsigned int max_uses,
                           int revoked, size_t ca_filler) {
    cJSON *root = cJSON_CreateObject();
    cJSON *array = NULL;
    char *filler = NULL;
    char *pin = NULL;
    uint8_t pin_bytes[W_ETOKEN_PIN_BYTES];
    int i;

    memset(pin_bytes, TEST_PIN_BYTE, sizeof(pin_bytes));
    pin = w_b64url_encode(pin_bytes, sizeof(pin_bytes));
    assert_non_null(pin);

    if (ca_filler > 0) {
        os_calloc(ca_filler + 1, sizeof(char), filler);
        memset(filler, 'C', ca_filler);
    }

    cJSON_AddNumberToObject(root, "version", 1);
    array = cJSON_AddArrayToObject(root, "tokens");

    for (i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        uint8_t id_bytes[W_ETOKEN_ID_BYTES];
        char *id = NULL;

        /* Ids only have to be distinct and well formed: the counter is enough and keeps the file
         * reproducible from one run to the next */
        memset(id_bytes, 0, sizeof(id_bytes));
        memcpy(id_bytes, &i, sizeof(i) < sizeof(id_bytes) ? sizeof(i) : sizeof(id_bytes));
        id = w_b64url_encode(id_bytes, sizeof(id_bytes));
        assert_non_null(id);

        cJSON_AddStringToObject(item, "id", id);
        cJSON_AddNullToObject(item, "secret");
        cJSON_AddStringToObject(item, "adr", "wazuh-full");

        if (filler != NULL) {
            cJSON_AddNullToObject(item, "pin");
            cJSON_AddStringToObject(item, "ca", filler);
        } else {
            cJSON_AddStringToObject(item, "pin", pin);
            cJSON_AddNullToObject(item, "ca");
        }

        cJSON_AddNumberToObject(item, "created", (double)(time(NULL) - 10));
        cJSON_AddNumberToObject(item, "expires", (double)(time(NULL) + expires_in));
        cJSON_AddNumberToObject(item, "max_uses", (double)max_uses);
        cJSON_AddNumberToObject(item, "uses", (double)uses);
        cJSON_AddBoolToObject(item, "revoked", revoked);
        cJSON_AddNullToObject(item, "description");
        cJSON_AddItemToArray(array, item);
        os_free(id);
    }

    assert_int_equal(json_fwrite(STORE_PATH, root), 0);
    cJSON_Delete(root);
    os_free(filler);
    os_free(pin);

    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_count(), count);
}

/// The inode of the store file: a rewrite goes through rename(), so a new inode proves it happened.
static ino_t store_inode(void) {
    struct stat info;

    assert_int_equal(stat(STORE_PATH, &info), 0);

    return info.st_ino;
}

static void test_purge_dead_removes_only_the_unusable(void **state) {
    (void)state;
    cJSON *ids = NULL;
    char alive[ETOKEN_ID_CHARS + 1] = {0};
    cJSON *data = NULL;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    /* One of each kind the purge is meant to reach, plus one it must not touch */
    data = mint_token("wazuh-alive", 3600, 0, NULL, 0);
    copy_string(alive, sizeof(alive), data, "id");
    cJSON_Delete(data);

    cJSON_Delete(mint_token("wazuh-expired", 1, 0, NULL, 0));
    data = mint_token("wazuh-revoked", 3600, 0, NULL, 0);
    {
        char revoked_id[ETOKEN_ID_CHARS + 1] = {0};

        copy_string(revoked_id, sizeof(revoked_id), data, "id");
        assert_int_equal(etoken_store_revoke(revoked_id), 0);
    }
    cJSON_Delete(data);

    data = mint_token("wazuh-exhausted", 3600, 1, NULL, 0);
    {
        char used_id[ETOKEN_ID_CHARS + 1] = {0};

        copy_string(used_id, sizeof(used_id), data, "id");
        assert_int_equal(etoken_store_consume(used_id, time(NULL)), ETOKEN_USE_OK);
        /* The enrollment that took the use finished, as the local server does when the agent was
         * created: an open reservation would (rightly) keep the entry out of this purge */
        etoken_store_commit(used_id);
    }
    cJSON_Delete(data);

    assert_int_equal(etoken_store_count(), 4);
    sleep(2); /* the one minted with ttl 1 is now past its expiry */

    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_DEAD, time(NULL), &ids), 3);
    assert_int_equal(cJSON_GetArraySize(ids), 3);
    assert_int_equal(etoken_store_count(), 1);
    cJSON_Delete(ids);

    /* The survivor is the live one, and it survives a reload: the file was rewritten, not just the
     * memory */
    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_count(), 1);
    assert_int_equal(etoken_store_consume(alive, time(NULL)), ETOKEN_USE_OK);
}

static void test_purge_without_victims_leaves_the_file_alone(void **state) {
    (void)state;
    ino_t before;
    cJSON *ids = NULL;

    expect_any_mdebug1();
    expect_any_minfo();

    cJSON_Delete(mint_token("wazuh-alive", 3600, 0, NULL, 0));
    before = store_inode();

    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_DEAD, time(NULL), &ids), 0);
    assert_int_equal(cJSON_GetArraySize(ids), 0);
    cJSON_Delete(ids);

    /* Not rewritten: every node that watches this file (remoted's replica, the cluster sync) would
     * otherwise reload a file that says exactly what it said before */
    assert_int_equal(etoken_store_count(), 1);
    assert_int_equal(store_inode(), before);
}

static void test_purge_all_empties_the_store(void **state) {
    (void)state;
    cJSON *root = NULL;
    cJSON *array = NULL;

    expect_any_mdebug1();
    expect_any_minfo();

    cJSON_Delete(mint_token("wazuh-1", 3600, 0, NULL, 0));
    cJSON_Delete(mint_token("wazuh-2", 3600, 0, NULL, 0));

    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_ALL, time(NULL), NULL), 2);
    assert_int_equal(etoken_store_count(), 0);

    /* A valid, empty store: the next mint appends to it and every reader parses it */
    array = read_store_file(&root);
    assert_int_equal(cJSON_GetArraySize(array), 0);
    assert_int_equal(cJSON_GetObjectItem(root, "version")->valueint, 1);
    cJSON_Delete(root);

    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_count(), 0);
}

/* --- Storage failures ---------------------------------------------------------------------------- */

static void test_revoke_reports_a_storage_failure_instead_of_success(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    cJSON *data = NULL;

    expect_any_mdebug1();
    expect_any_minfo();
    expect_any_merror();

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);
    assert_int_equal(file_revoked_of(id), 0);

    break_storage();

    /* The operator's intent stands in memory -- this authd stops honouring the token right away --
     * but the answer says the file does not know yet */
    assert_int_equal(etoken_store_revoke(id), ETOKEN_STORE_FAILED);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_NOT_FOUND);
    assert_int_equal(file_revoked_of(id), 0);

    /* The retry that used to lie: the flag was already set in memory, so it answered success
     * without writing anything (issue #39078, H04) */
    assert_int_equal(etoken_store_revoke(id), ETOKEN_STORE_FAILED);
    assert_int_equal(file_revoked_of(id), 0);

    restore_storage();
    assert_int_equal(etoken_store_revoke(id), 0);
    assert_int_equal(file_revoked_of(id), 1);
}

static void test_a_pending_revocation_is_retried_by_the_next_verb(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    cJSON *data = NULL;

    expect_any_mdebug1();
    expect_any_minfo();
    expect_any_merror();

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    break_storage();
    assert_int_equal(etoken_store_revoke(id), ETOKEN_STORE_FAILED);

    /* Every verb calls reload_if_changed() first, and that is where the pending write is retried:
     * the operator does not have to run the revoke again */
    restore_storage();
    /* 1: init() reset the known mtime, so this call reloads the file first and then flushes */
    assert_int_equal(etoken_store_reload_if_changed(), 1);
    assert_int_equal(file_revoked_of(id), 1);

    /* Nothing left pending: a further call is the free, idempotent one and does not rewrite */
    assert_int_equal(etoken_store_revoke(id), 0);
}

static void test_a_pending_revocation_survives_a_reload(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    cJSON *data = NULL;

    expect_any_mdebug1();
    expect_any_minfo();
    expect_any_merror();

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    break_storage();
    assert_int_equal(etoken_store_revoke(id), ETOKEN_STORE_FAILED);

    /* A reload replaces the whole array with what the file says -- and the file still says the
     * token is live. Without the pending list this is exactly where the revocation was lost, and
     * it is the path etoken_store_purge() takes to recover from its own failed save */
    restore_storage();
    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_NOT_FOUND);

    /* And the intent is still pending, so the next verb writes it */
    assert_int_equal(etoken_store_reload_if_changed(), 0);
    assert_int_equal(file_revoked_of(id), 1);
}

static void test_a_pending_revocation_of_a_vanished_token_is_dropped(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    cJSON *data = NULL;

    expect_any_mdebug1();
    expect_any_minfo();
    expect_any_merror();

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    break_storage();
    assert_int_equal(etoken_store_revoke(id), ETOKEN_STORE_FAILED);

    /* Someone else (the master, through the cluster) removed the token while the revocation was
     * pending: there is nothing left to revoke, and the list must not keep the id forever */
    unlink(STORE_PATH);
    restore_storage();
    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_count(), 0);
    assert_int_equal(etoken_store_reload_if_changed(), 0);
    assert_int_equal(etoken_store_count(), 0);
}

static void test_a_store_above_the_token_cap_is_not_loaded(void **state) {
    (void)state;
    cJSON *data = NULL;
    cJSON *root = NULL;
    cJSON *array = NULL;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    int i;

    expect_any_mdebug1();
    expect_any_minfo();
    expect_any_mwarn();

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    /* A file inherited from somewhere else with more tokens than this authd can ever write back.
     * Every id has to be a real one -- canonical base64url of 16 bytes -- or the entries would be
     * dropped one at a time and the file would load empty, which says nothing about the cap */
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    array = cJSON_AddArrayToObject(root, "tokens");

    for (i = 0; i <= ETOKEN_MAX_TOKENS; i++) {
        cJSON *item = cJSON_CreateObject();
        uint8_t id_bytes[W_ETOKEN_ID_BYTES];
        char *token_id = NULL;

        memset(id_bytes, 0, sizeof(id_bytes));
        memcpy(id_bytes, &i, sizeof(i));
        token_id = w_b64url_encode(id_bytes, sizeof(id_bytes));
        assert_non_null(token_id);

        cJSON_AddStringToObject(item, "id", token_id);
        cJSON_AddNullToObject(item, "secret");
        cJSON_AddStringToObject(item, "adr", "wazuh-1");
        cJSON_AddNullToObject(item, "pin");
        cJSON_AddStringToObject(item, "ca", "x");
        cJSON_AddNumberToObject(item, "created", 1);
        cJSON_AddNumberToObject(item, "expires", 99999999999.0);
        cJSON_AddNumberToObject(item, "max_uses", 0);
        cJSON_AddNumberToObject(item, "uses", 0);
        cJSON_AddBoolToObject(item, "revoked", 0);
        cJSON_AddNullToObject(item, "description");
        cJSON_AddItemToArray(array, item);
        os_free(token_id);
    }

    assert_int_equal(json_fwrite(STORE_PATH, root), 0);
    cJSON_Delete(root);

    /* Refused, and what was already loaded is kept: the alternative is an authd holding a store it
     * cannot persist (issue #39078, H08) */
    assert_int_equal(etoken_store_load(), -1);
    assert_int_equal(etoken_store_count(), 1);
}

static void test_a_store_above_the_byte_ceiling_is_not_loaded(void **state) {
    (void)state;
    cJSON *data = NULL;
    FILE *fp = NULL;
    size_t written = 0;
    char filler[4096];

    expect_any_mdebug1();
    expect_any_minfo();
    expect_any_mwarn();

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    cJSON_Delete(data);

    /* The size is checked before parsing: what the bytes say does not matter, only that this authd
     * could never write that much back */
    memset(filler, 'x', sizeof(filler));
    fp = fopen(STORE_PATH, "w");
    assert_non_null(fp);
    while (written <= (size_t)W_ETOKEN_STORE_MAX_BYTES) {
        assert_int_equal(fwrite(filler, 1, sizeof(filler), fp), sizeof(filler));
        written += sizeof(filler);
    }
    assert_int_equal(fclose(fp), 0);

    assert_int_equal(etoken_store_load(), -1);
    assert_int_equal(etoken_store_count(), 1);
}

/* --- Reservations in flight -------------------------------------------------------------------- */

/// Mint a single-use token and reserve its only use, as an enrollment about to run does.
static void reserve_only_use(char *id, size_t size) {
    cJSON *data = mint_token("wazuh-inflight", 3600, 1, NULL, 0);

    copy_string(id, size, data, "id");
    cJSON_Delete(data);

    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
}

static void test_purge_dead_spares_a_use_still_in_flight(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    reserve_only_use(id, sizeof(id));

    /* The token is out of uses on paper, but the enrollment that took the last one is still
     * running: purging it here would make the release below a no-op and lose the use for good */
    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_DEAD, time(NULL), NULL), 0);
    assert_int_equal(etoken_store_count(), 1);

    etoken_store_release(id);
    assert_int_equal(file_uses_of(id), 0);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
}

static void test_purge_dead_removes_it_once_the_enrollment_is_over(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    reserve_only_use(id, sizeof(id));
    etoken_store_commit(id);

    /* Committed: the use is spent for good and the entry is a leftover like any other */
    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_DEAD, time(NULL), NULL), 1);
    assert_int_equal(etoken_store_count(), 0);
}

static void test_purge_all_takes_a_use_in_flight_too(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    reserve_only_use(id, sizeof(id));

    /* Emptying the store is an explicit order, not a cleanup: it takes the token an enrollment is
     * holding as well, and the release that follows finds nothing and says so */
    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_ALL, time(NULL), NULL), 1);
    assert_int_equal(etoken_store_count(), 0);

    etoken_store_release(id);
    assert_int_equal(etoken_store_count(), 0);
}

static void test_a_reservation_survives_a_reload(void **state) {
    (void)state;
    char id[ETOKEN_ID_CHARS + 1] = {0};

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    reserve_only_use(id, sizeof(id));

    /* Any mint or revoke rewrites the file and the next verb reloads it, replacing the entries
     * wholesale. The reservation is not kept in them precisely so that it outlives this */
    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_DEAD, time(NULL), NULL), 0);
    assert_int_equal(etoken_store_count(), 1);

    etoken_store_commit(id);
    assert_int_equal(etoken_store_purge(ETOKEN_PURGE_DEAD, time(NULL), NULL), 1);
}

static void test_mint_is_refused_when_the_store_is_full_of_live_tokens(void **state) {
    (void)state;
    etoken_mint_t mint;
    cJSON *data = NULL;

    expect_any_mdebug1();

    write_store_of(ETOKEN_MAX_TOKENS, 3600, 0, 0, 0, 0);

    build_mint(&mint, "wazuh-one-too-many", 3600, 0, NULL, 0);
    assert_int_equal(etoken_store_create(&mint, time(NULL), &data), ETOKEN_CREATE_FULL);
    etoken_mint_free(&mint);

    assert_null(data);
    assert_int_equal(etoken_store_count(), ETOKEN_MAX_TOKENS);
}

static void test_mint_purges_the_dead_to_make_room(void **state) {
    (void)state;
    etoken_mint_t mint;
    cJSON *data = NULL;

    expect_any_mdebug1();
    expect_any_minfo();

    /* Full, but of tokens that expired an hour ago: the store is dirty, not full */
    write_store_of(ETOKEN_MAX_TOKENS, -3600, 0, 0, 0, 0);

    build_mint(&mint, "wazuh-after-the-purge", 3600, 0, NULL, 0);
    assert_int_equal(etoken_store_create(&mint, time(NULL), &data), 0);
    etoken_mint_free(&mint);

    assert_non_null(data);
    cJSON_Delete(data);
    assert_int_equal(etoken_store_count(), 1);
}

static void test_mint_is_refused_when_the_store_would_be_too_big(void **state) {
    (void)state;
    etoken_mint_t mint;
    cJSON *data = NULL;
    ino_t before;

    expect_any_mdebug1();
    expect_any_merror();

    /* Few tokens, each carrying a CA far larger than a real one: the count cap is nowhere near, and
     * the only thing standing between this store and a replica that stops updating is the ceiling.
     * The file itself stays UNDER the ceiling -- since #39078 a store above it is not even loaded --
     * so what crosses it is the mint below, which carries a CA of its own */
    write_store_of(180, 3600, 0, 0, 0, 40000);
    before = store_inode();

    /* The mint carries the CA instead of a pin -- exactly one anchor, as the codec requires -- and
     * it is that CA which takes the store over the ceiling */
    build_mint(&mint, "wazuh-over-the-ceiling", 3600, 0, NULL, 0);
    mint.has_pin = 0;
    os_calloc(200000 + 1, sizeof(char), mint.ca_pem);
    memset(mint.ca_pem, 'C', 200000);
    assert_int_equal(etoken_store_create(&mint, time(NULL), &data), ETOKEN_CREATE_TOOBIG);
    etoken_mint_free(&mint);

    assert_null(data);
    assert_int_equal(etoken_store_count(), 180);
    assert_int_equal(store_inode(), before);
}

/* --- Lifetimes and records the loader cannot read ----------------------------------------------- */

static void test_a_lifetime_that_would_overflow_the_expiry_is_refused(void **state) {
    (void)state;
    etoken_mint_t mint;
    cJSON *data = NULL;
    struct stat statbuf;

    expect_any_merror();

    /* LONG_MAX seconds from now is not a far-off expiry, it is a NEGATIVE one: `now + ttl` wraps,
     * and a negative `expires` is precisely what etoken_parse_entry() refuses. Minting it would
     * write a file this very store cannot read back -- so the request never gets that far, and it
     * is refused before an identifier or a secret is drawn */
    build_mint(&mint, "wazuh-1", LONG_MAX, 0, NULL, 0);
    assert_int_equal(etoken_store_create(&mint, time(NULL), &data), -1);
    etoken_mint_free(&mint);
    assert_null(data);

    /* One second above the ceiling: the same refusal, and the reason it exists */
    build_mint(&mint, "wazuh-1", ETOKEN_MAX_TTL + 1, 0, NULL, 0);
    assert_int_equal(etoken_store_create(&mint, time(NULL), &data), -1);
    etoken_mint_free(&mint);
    assert_null(data);

    /* Nothing in memory, and no file at all: a refused mint leaves the store as it found it */
    assert_int_equal(etoken_store_count(), 0);
    assert_int_equal(stat(STORE_PATH, &statbuf), -1);
}

static void test_the_longest_accepted_lifetime_is_minted_and_reloads(void **state) {
    (void)state;
    cJSON *data = NULL;
    cJSON *root = NULL;
    cJSON *array = NULL;
    char id[ETOKEN_ID_CHARS + 1] = {0};
    time_t now = time(NULL);
    double expires;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();

    /* The ceiling itself is a lifetime like any other: what the bound refuses is what cannot be
     * represented, not a long-lived token */
    data = mint_token("wazuh-1", ETOKEN_MAX_TTL, 0, NULL, 0);
    copy_string(id, sizeof(id), data, "id");
    cJSON_Delete(data);

    array = read_store_file(&root);
    expires = cJSON_GetObjectItem(cJSON_GetArrayItem(array, 0), "expires")->valuedouble;
    cJSON_Delete(root);

    assert_true(expires > 0);
    assert_true(expires >= (double)(now + ETOKEN_MAX_TTL));

    /* And the file is one the loader accepts, which is the whole point of the bound */
    assert_int_equal(etoken_store_load(), 0);
    assert_int_equal(etoken_store_count(), 1);
    assert_int_equal(etoken_store_consume(id, time(NULL)), ETOKEN_USE_OK);
}

static void test_an_entry_with_a_negative_expiry_is_dropped_and_the_others_load(void **state) {
    (void)state;
    cJSON *data = NULL;
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *poisoned = NULL;
    char first[ETOKEN_ID_CHARS + 1] = {0};
    char second[ETOKEN_ID_CHARS + 1] = {0};
    char *text = NULL;
    FILE *fp = NULL;

    expect_any_mdebug1();
    expect_any_mdebug2();
    expect_any_minfo();
    expect_any_mwarn();

    data = mint_token("wazuh-1", 3600, 0, NULL, 0);
    copy_string(first, sizeof(first), data, "id");
    cJSON_Delete(data);

    data = mint_token("wazuh-2", 3600, 0, NULL, 0);
    copy_string(second, sizeof(second), data, "id");
    cJSON_Delete(data);

    /* The record a wrapped lifetime used to leave behind, put BETWEEN the two good tokens: a copy
     * of a real entry with another id and the negative expiry the addition produced. Refusing the
     * whole file over it is what turned one bad record into "no token enrolls anybody", on the
     * master at its next restart and on every worker the file is synchronised to */
    array = read_store_file(&root);
    poisoned = cJSON_Duplicate(cJSON_GetArrayItem(array, 0), 1);
    assert_non_null(poisoned);
    assert_true(cJSON_ReplaceItemInObject(poisoned, "id", cJSON_CreateString(UNKNOWN_ID)));
    assert_true(cJSON_ReplaceItemInObject(poisoned, "expires", cJSON_CreateNumber(-9223372035074776832.0)));
    assert_true(cJSON_InsertItemInArray(array, 1, poisoned));

    text = cJSON_PrintUnformatted(root);
    assert_non_null(text);
    cJSON_Delete(root);

    fp = fopen(STORE_PATH, "w");
    assert_non_null(fp);
    assert_true(fputs(text, fp) >= 0);
    fclose(fp);
    free(text);
    touch_store_file(time(NULL) + 2);

    /* The file loads. The only thing lost is the record nobody could have used anyway */
    assert_int_equal(etoken_store_reload_if_changed(), 1);
    assert_int_equal(etoken_store_count(), 2);
    assert_int_equal(etoken_store_consume(first, time(NULL)), ETOKEN_USE_OK);
    assert_int_equal(etoken_store_consume(second, time(NULL)), ETOKEN_USE_OK);
    assert_int_equal(etoken_store_consume(UNKNOWN_ID, time(NULL)), ETOKEN_USE_NOT_FOUND);

    /* Those uses were persisted, so the file has been rewritten from memory: the entry the loader
     * could not read is gone from it too, and the store stays self-consistent */
    array = read_store_file(&root);
    assert_int_equal(cJSON_GetArraySize(array), 2);
    cJSON_Delete(root);
}

/* --- The endpoint the token carries ------------------------------------------------------------ */

static void test_adr_build_drops_the_defaults(void **state) {
    (void)state;

    struct {
        const char *address;
        long port;
        const char *prefix;
        const char *expected;
    } cases[] = {
        /* Nothing to say: the agent applies both defaults itself */
        {"wazuh-1", 1517, "/wazuh-manager/", "wazuh-1"},
        {"wazuh-1", 1517, "wazuh-manager", "wazuh-1"},
        {"wazuh-1", 1520, "/wazuh-manager/", "wazuh-1:1520"},
        /* "no prefix" has to be stated: it is not the same answer as "use the default one" */
        {"wazuh-1", 1517, "/", "wazuh-1/"},
        {"wazuh-1", 1517, "", "wazuh-1/"},
        {"wazuh-1", 1517, "gw", "wazuh-1/gw"},
        {"wazuh-1", 1517, "/a/b/", "wazuh-1/a/b"},
        {"10.0.0.1", 1520, "/gw/", "10.0.0.1:1520/gw"},
        /* Bracketed, or the ':' of the port would be one of the address's own */
        {"2001:db8::1", 1517, "/wazuh-manager/", "[2001:db8::1]"},
        {"2001:db8::1", 1520, "/wazuh-manager/", "[2001:db8::1]:1520"},
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *adr = etoken_adr_build(cases[i].address, cases[i].port, cases[i].prefix);

        assert_non_null(adr);
        assert_string_equal(adr, cases[i].expected);
        os_free(adr);
    }

    assert_null(etoken_adr_build(NULL, 1517, "/wazuh-manager/"));
    assert_null(etoken_adr_build("", 1517, "/wazuh-manager/"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_load_absent_file_is_empty, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_malformed_file_keeps_previous_and_warns, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_create_persists_atomically_with_mode_0640, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_create_roundtrip_load, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_list_never_includes_secret, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_consume_ok_unlimited, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_consume_exhausted_after_max_uses, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_consume_revoked_and_expired, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_release_undoes_a_reserved_use, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_revoke_unknown_and_idempotent, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_reload_if_changed_picks_up_external_write, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_purge_dead_removes_only_the_unusable, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_purge_without_victims_leaves_the_file_alone, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_purge_all_empties_the_store, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_revoke_reports_a_storage_failure_instead_of_success, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_pending_revocation_is_retried_by_the_next_verb, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_pending_revocation_survives_a_reload, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_pending_revocation_of_a_vanished_token_is_dropped, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_store_above_the_token_cap_is_not_loaded, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_store_above_the_byte_ceiling_is_not_loaded, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_purge_dead_spares_a_use_still_in_flight, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_purge_dead_removes_it_once_the_enrollment_is_over, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_purge_all_takes_a_use_in_flight_too, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_reservation_survives_a_reload, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_mint_is_refused_when_the_store_is_full_of_live_tokens, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_mint_purges_the_dead_to_make_room, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_mint_is_refused_when_the_store_would_be_too_big, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_a_lifetime_that_would_overflow_the_expiry_is_refused, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_the_longest_accepted_lifetime_is_minted_and_reloads, setup_store, teardown_store),
        cmocka_unit_test_setup_teardown(test_an_entry_with_a_negative_expiry_is_dropped_and_the_others_load, setup_store, teardown_store),
        cmocka_unit_test(test_adr_build_drops_the_defaults),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
