/* Copyright (C) 2015, Wazuh Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../client-agent/agentd.h"
#include "../../os_crypto/md5/md5_op.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

typedef struct
{
    char cwd[PATH_MAX];
    char root[64];
} filesystem_fixture;

FILE* __real_wfopen(const char* path, const char* mode);
int __real_OS_MD5_File(const char* path, os_md5 output, int mode);
int __real_UnmergeFiles(const char* path, const char* dir, int mode, char*** list);
int __real_cldir_ex_ignore(const char* dir, const char** list);
int __real_rename_ex(const char* source, const char* destination);
int __real_unlink(const char* path);

static int real_files;
static const char* bundle_data;
static char* message;
static int extraction_result;
static int extracted;
static int errors;
static int cleanups;
static int cache_clears;
static int validations;
static int reloads;
static int cleanup_result;
static int publish_result;
static int publications;
static int discarded;
static const char* accepted_hash;
static const char* checksum = "0123456789abcdef0123456789abcdef";

ssize_t __wrap_OS_RecvSecureTCP(int sock, char* buffer, size_t size)
{
    (void)sock;
    (void)size;
    strcpy(buffer, "message");
    return 7;
}

int __wrap_ReadSecMSG(keystore* store, char* buffer, char* cleartext, int id,
                      unsigned int size, size_t* final_size, const char* ip, char** output)
{
    (void)store;
    (void)buffer;
    (void)cleartext;
    (void)id;
    (void)size;
    (void)ip;
    *output = message;
    *final_size = strlen(message);
    return KS_VALID;
}

FILE* __wrap_wfopen(const char* path, const char* mode)
{
    if (real_files)
    {
        return __real_wfopen(path, mode);
    }

    assert_string_equal(path, SHAREDCFG_FILE ".tmp");
    assert_string_equal(mode, "w");
    return tmpfile();
}

int __wrap_OS_MD5_File(const char* path, os_md5 output, int mode)
{
    assert_string_equal(path, SHAREDCFG_FILE ".tmp");
    assert_int_equal(mode, OS_TEXT);

    if (real_files)
    {
        return __real_OS_MD5_File(path, output, mode);
    }

    strcpy(output, checksum);
    return 0;
}

int __wrap_UnmergeFiles(const char* path, const char* dir, int mode, char*** list)
{
    assert_string_equal(path, SHAREDCFG_FILE ".tmp");
    assert_string_equal(dir, SHAREDCFG_DIR);
    assert_int_equal(mode, OS_TEXT);
    assert_string_equal((*list)[0], SHAREDCFG_FILENAME);
    assert_string_equal((*list)[1], SHAREDCFG_FILENAME ".tmp");

    if (real_files)
    {
        return __real_UnmergeFiles(path, dir, mode, list);
    }

    if (extracted)
    {
        *list = w_strarray_append(*list, strdup("agent.conf"), 2);
    }

    return extraction_result;
}

int __wrap_cldir_ex_ignore(const char* dir, const char** list)
{
    assert_string_equal(dir, SHAREDCFG_DIR);
    assert_string_equal(list[0], SHAREDCFG_FILENAME);
    assert_string_equal(list[1], SHAREDCFG_FILENAME ".tmp");
    ++cleanups;
    return real_files ? __real_cldir_ex_ignore(dir, list) : cleanup_result;
}

int __wrap_rename_ex(const char* source, const char* destination)
{
    assert_string_equal(source, SHAREDCFG_FILE ".tmp");
    assert_string_equal(destination, SHAREDCFG_FILE);
    assert_true(cleanups > 0);
    assert_int_equal(cleanup_result, 0);
    int result = real_files ? __real_rename_ex(source, destination) : publish_result;

    if (!result)
    {
        ++publications;
        accepted_hash = checksum;
    }

    return result;
}

int __wrap_unlink(const char* path)
{
    if (real_files)
    {
        if (!strcmp(path, SHAREDCFG_FILE ".tmp"))
        {
            ++discarded;
        }

        return __real_unlink(path);
    }

    assert_string_equal(path, SHAREDCFG_FILE ".tmp");
    ++discarded;
    return 0;
}

void __wrap_clear_merged_hash_cache(void)
{
    ++cache_clears;
}

int __wrap_verifyRemoteConf(void)
{
    ++validations;
    return 0;
}

void* __wrap_reloadAgent(void)
{
    ++reloads;
    return NULL;
}

int __wrap_send_msg(const char* msg, ssize_t length)
{
    char expected[OS_MAXSTR];
    snprintf(expected, sizeof(expected), "%c:wazuh-agent:%s", LOCALFILE_MQ, AG_IN_UNMERGE);
    assert_string_equal(msg, expected);
    assert_int_equal(length, -1);
    ++errors;
    return 0;
}

void __wrap_w_agentd_state_update(w_agentd_state_update_t item, void* value)
{
    (void)item;
    (void)value;
}

static int setup(void** state)
{
    *state = NULL;
    real_files = 0;
    bundle_data = NULL;
    checksum = "0123456789abcdef0123456789abcdef";
    agt = calloc(1, sizeof(*agt));
    agt->server = calloc(1, sizeof(*agt->server));
    agt->server[0].protocol = IPPROTO_TCP;
    agt->server[0].rip = strdup("127.0.0.1");
    agt->flags.remote_conf = 1;
    agt->flags.auto_restart = 1;
    extraction_result = 1;
    extracted = 1;
    errors = cleanups = cache_clears = validations = reloads = 0;
    cleanup_result = publish_result = publications = discarded = 0;
    accepted_hash = "previous";
    return 0;
}

static int teardown(void** state)
{
    filesystem_fixture* fixture = *state;

    if (fixture)
    {
        assert_int_equal(chdir(fixture->cwd), 0);
        assert_int_equal(rmdir_ex(fixture->root), 0);
        free(fixture);
    }

    real_files = 0;
    free(agt->server[0].rip);
    free(agt->server);
    free(agt);
    agt = NULL;
    return 0;
}

static void receive_bundle(void)
{
    char update[256];
    snprintf(update, sizeof(update), CONTROL_HEADER "%s%s %s", FILE_UPDATE_HEADER, checksum, SHAREDCFG_FILENAME);
    message = update;
    expect_any(__wrap__mdebug2, formatted_msg);
    assert_int_equal(receive_msg(), 0);

    if (bundle_data)
    {
        message = (char*)bundle_data;
        expect_any(__wrap__mdebug2, formatted_msg);
        assert_int_equal(receive_msg(), 0);
    }

    message = CONTROL_HEADER FILE_CLOSE_HEADER;
    expect_any(__wrap__mdebug2, formatted_msg);

    if (extraction_result && !cleanup_result && !publish_result && agt->flags.remote_conf)
    {
        expect_any(__wrap__minfo, formatted_msg);
    }

    if (extraction_result && cleanup_result)
    {
        expect_any(__wrap__mwarn, formatted_msg);
    }

    assert_int_equal(receive_msg(), 0);
}

static void test_complete_update(void** state)
{
    (void)state;
    receive_bundle();
    assert_int_equal(errors, 0);
    assert_int_equal(cleanups, 1);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 1);
    assert_int_equal(reloads, 1);
    assert_int_equal(publications, 1);
    assert_int_equal(discarded, 0);
    assert_string_equal(accepted_hash, checksum);
}

static void assert_update_pending(void)
{
    assert_int_equal(errors, 1);
    assert_int_equal(cache_clears, 0);
    assert_int_equal(validations, 0);
    assert_int_equal(reloads, 0);
    assert_int_equal(publications, 0);
    assert_int_equal(discarded, 1);
    assert_string_equal(accepted_hash, "previous");
}

static void test_partial_update(void** state)
{
    (void)state;
    extraction_result = 0;
    receive_bundle();
    assert_update_pending();
    assert_int_equal(cleanups, 0);
}

static void test_failed_update(void** state)
{
    (void)state;
    extraction_result = 0;
    extracted = 0;
    receive_bundle();
    assert_update_pending();
    assert_int_equal(cleanups, 0);
}

static void test_retry_after_partial_update(void** state)
{
    test_partial_update(state);
    extraction_result = 1;
    receive_bundle();
    assert_int_equal(errors, 1);
    assert_int_equal(cleanups, 1);
    assert_int_equal(publications, 1);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 1);
    assert_int_equal(reloads, 1);
    assert_string_equal(accepted_hash, checksum);
}

static void test_cleanup_failure(void** state)
{
    (void)state;
    cleanup_result = -1;
    receive_bundle();
    assert_update_pending();
    assert_int_equal(cleanups, 1);
}

static void test_publication_failure(void** state)
{
    (void)state;
    publish_result = -1;
    receive_bundle();
    assert_update_pending();
    assert_int_equal(cleanups, 1);
}

static void write_fixture_file(const char* path, const char* contents)
{
    FILE* fp = fopen(path, "w");
    assert_non_null(fp);
    assert_true(fputs(contents, fp) >= 0);
    assert_int_equal(fclose(fp), 0);
}

static void assert_fixture_contents(const char* path, const char* contents)
{
    char buffer[256] = {0};
    FILE* fp = fopen(path, "r");
    assert_non_null(fp);
    assert_int_equal(fread(buffer, 1, sizeof(buffer) - 1, fp), strlen(contents));
    assert_string_equal(buffer, contents);
    assert_int_equal(fclose(fp), 0);
}

static void test_filesystem_retry(void** state)
{
    filesystem_fixture* fixture = calloc(1, sizeof(*fixture));
    assert_non_null(fixture);
    assert_non_null(getcwd(fixture->cwd, sizeof(fixture->cwd)));
    strcpy(fixture->root, "/tmp/test_receiver_XXXXXX");
    assert_non_null(mkdtemp(fixture->root));
    *state = fixture;
    real_files = 1;
    assert_int_equal(chdir(fixture->root), 0);
    assert_int_equal(mkdir_ex(SHAREDCFG_DIR), 0);
    write_fixture_file(SHAREDCFG_FILE, "previous bundle");
    write_fixture_file(SHAREDCFG_DIR "/obsolete", "old");
    assert_int_equal(mkdir_ex(SHAREDCFG_DIR "/policy"), 0);

    bundle_data = "!3 agent.conf\nnew!4 policy\nrule";
    os_md5 new_hash;
    assert_int_equal(OS_MD5_Str(bundle_data, strlen(bundle_data), new_hash), 0);
    checksum = new_hash;
    extraction_result = 0;
    expect_any(__wrap__mferror, formatted_msg);
    receive_bundle();
    assert_update_pending();
    assert_int_equal(cleanups, 0);
    assert_fixture_contents(SHAREDCFG_FILE, "previous bundle");
    assert_fixture_contents(SHAREDCFG_DIR "/agent.conf", "new");
    assert_fixture_contents(SHAREDCFG_DIR "/obsolete", "old");
    assert_int_equal(IsDir(SHAREDCFG_DIR "/policy"), 0);
    assert_int_equal(access(SHAREDCFG_FILE ".tmp", F_OK), -1);

    assert_int_equal(rmdir(SHAREDCFG_DIR "/policy"), 0);
    extraction_result = 1;
    receive_bundle();
    assert_int_equal(errors, 1);
    assert_int_equal(cleanups, 1);
    assert_int_equal(publications, 1);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 1);
    assert_int_equal(reloads, 1);
    assert_fixture_contents(SHAREDCFG_FILE, bundle_data);
    assert_fixture_contents(SHAREDCFG_DIR "/agent.conf", "new");
    assert_fixture_contents(SHAREDCFG_DIR "/policy", "rule");
    assert_int_equal(access(SHAREDCFG_DIR "/obsolete", F_OK), -1);
    assert_int_equal(access(SHAREDCFG_FILE ".tmp", F_OK), -1);
}

static void test_update_without_restart(void** state)
{
    (void)state;
    agt->flags.auto_restart = 0;
    receive_bundle();
    assert_int_equal(errors, 0);
    assert_int_equal(publications, 1);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 1);
    assert_int_equal(reloads, 0);
}

static void test_update_without_remote_conf(void** state)
{
    (void)state;
    agt->flags.remote_conf = 0;
    receive_bundle();
    assert_int_equal(errors, 0);
    assert_int_equal(publications, 1);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 0);
    assert_int_equal(reloads, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_complete_update, setup, teardown),
        cmocka_unit_test_setup_teardown(test_partial_update, setup, teardown),
        cmocka_unit_test_setup_teardown(test_failed_update, setup, teardown),
        cmocka_unit_test_setup_teardown(test_retry_after_partial_update, setup, teardown),
        cmocka_unit_test_setup_teardown(test_cleanup_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_publication_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_filesystem_retry, setup, teardown),
        cmocka_unit_test_setup_teardown(test_update_without_restart, setup, teardown),
        cmocka_unit_test_setup_teardown(test_update_without_remote_conf, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
