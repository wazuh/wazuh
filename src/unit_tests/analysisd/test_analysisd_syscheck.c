/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

#include "../headers/wazuhdb_op.h"
#include "../headers/syscheck_op.h"

/* Auxiliar structs */

typedef struct __fim_data_s {
    cJSON *event;
    Eventinfo *lf;
}fim_data_t;

typedef struct __fim_adjust_checksum_data_s {
    sk_sum_t *newsum;
    char **checksum;
}fim_adjust_checksum_data_t;

/* private functions to be tested */
void fim_send_db_query(int * sock, const char * query);
void fim_send_db_delete(_sdb * sdb, const char * agent_id, const char * path);
void fim_send_db_save(_sdb * sdb, const char * agent_id, cJSON * data);
void fim_process_scan_info(_sdb * sdb, const char * agent_id, fim_scan_event event, cJSON * data);
int fim_fetch_attributes_state(cJSON *attr, Eventinfo *lf, char new_state);
int fim_fetch_attributes(cJSON *new_attrs, cJSON *old_attrs, Eventinfo *lf);
size_t fim_generate_comment(char * str, long size, const char * format, const char * a1, const char * a2);
int fim_generate_alert(Eventinfo *lf, char *event_type, cJSON *attributes, cJSON *old_attributes, cJSON *audit);
int fim_process_alert(_sdb *sdb, Eventinfo *lf, cJSON *event);
int decode_fim_event(_sdb *sdb, Eventinfo *lf);
void fim_adjust_checksum(sk_sum_t *newsum, char **checksum);

/* setup/teardown */

static int setup_fim_event_cjson(void **state) {
    const char *plain_event = "{\"type\":\"event\","
        "\"data\":{"
            "\"path\":\"/a/path\","
            "\"mode\":\"whodata\","
            "\"type\":\"added\","
            "\"timestamp\":123456789,"
            "\"changed_attributes\":["
                "\"size\",\"permission\",\"uid\","
                "\"user_name\",\"gid\",\"group_name\","
                "\"mtime\",\"inode\",\"md5\",\"sha1\",\"sha256\"],"
            "\"tags\":\"tags\","
            "\"content_changes\":\"some_changes\","
            "\"old_attributes\":{"
                "\"type\":\"file\","
                "\"size\":1234,"
                "\"perm\":\"perm\","
                "\"user_name\":\"user_name\","
                "\"group_name\":\"group_name\","
                "\"uid\":\"uid\","
                "\"gid\":\"gid\","
                "\"inode\":2345,"
                "\"mtime\":3456,"
                "\"hash_md5\":\"hash_md5\","
                "\"hash_sha1\":\"hash_sha1\","
                "\"hash_sha256\":\"hash_sha256\","
                "\"win_attributes\":\"win_attributes\","
                "\"symlink_path\":\"symlink_path\","
                "\"checksum\":\"checksum\"},"
            "\"attributes\":{"
                "\"type\":\"file\","
                "\"size\":4567,"
                "\"perm\":\"perm\","
                "\"user_name\":\"user_name\","
                "\"group_name\":\"group_name\","
                "\"uid\":\"uid\","
                "\"gid\":\"gid\","
                "\"inode\":5678,"
                "\"mtime\":6789,"
                "\"hash_md5\":\"hash_md5\","
                "\"hash_sha1\":\"hash_sha1\","
                "\"hash_sha256\":\"hash_sha256\","
                "\"win_attributes\":\"win_attributes\","
                "\"symlink_path\":\"symlink_path\","
                "\"checksum\":\"checksum\"},"
            "\"audit\":{"
                "\"user_id\":\"user_id\","
                "\"user_name\":\"user_name\","
                "\"group_id\":\"group_id\","
                "\"group_name\":\"group_name\","
                "\"process_name\":\"process_name\","
                "\"audit_uid\":\"audit_uid\","
                "\"audit_name\":\"audit_name\","
                "\"effective_uid\":\"effective_uid\","
                "\"effective_name\":\"effective_name\","
                "\"ppid\":12345,"
                "\"process_id\":23456}}}";

    cJSON *event = cJSON_Parse(plain_event);

    if(event == NULL)
        return -1;

    *state = event;
    return 0;
}

static int teardown_fim_event_cjson(void **state) {
    cJSON *event = *state;

    cJSON_Delete(event);

    return 0;
}

static int setup_fim_data(void **state) {
    fim_data_t *data;
    const char *plain_event = "{\"type\":\"event\","
        "\"data\":{"
            "\"path\":\"/a/path\","
            "\"mode\":\"whodata\","
            "\"type\":\"added\","
            "\"timestamp\":123456789,"
            "\"changed_attributes\":["
                "\"size\",\"permission\",\"uid\","
                "\"user_name\",\"gid\",\"group_name\","
                "\"mtime\",\"inode\",\"md5\",\"sha1\",\"sha256\"],"
            "\"tags\":\"tags\","
            "\"hard_links\":["
                "\"/a/hard1.file\","
                "\"/b/hard2.file\"],"
            "\"content_changes\":\"some_changes\","
            "\"old_attributes\":{"
                "\"type\":\"file\","
                "\"size\":1234,"
                "\"perm\":\"old_perm\","
                "\"user_name\":\"old_user_name\","
                "\"group_name\":\"old_group_name\","
                "\"uid\":\"old_uid\","
                "\"gid\":\"old_gid\","
                "\"inode\":2345,"
                "\"mtime\":3456,"
                "\"hash_md5\":\"old_hash_md5\","
                "\"hash_sha1\":\"old_hash_sha1\","
                "\"hash_sha256\":\"old_hash_sha256\","
                "\"win_attributes\":\"old_win_attributes\","
                "\"symlink_path\":\"old_symlink_path\","
                "\"checksum\":\"old_checksum\"},"
            "\"attributes\":{"
                "\"type\":\"file\","
                "\"size\":4567,"
                "\"perm\":\"perm\","
                "\"user_name\":\"user_name\","
                "\"group_name\":\"group_name\","
                "\"uid\":\"uid\","
                "\"gid\":\"gid\","
                "\"inode\":5678,"
                "\"mtime\":6789,"
                "\"hash_md5\":\"hash_md5\","
                "\"hash_sha1\":\"hash_sha1\","
                "\"hash_sha256\":\"hash_sha256\","
                "\"win_attributes\":\"win_attributes\","
                "\"symlink_path\":\"symlink_path\","
                "\"checksum\":\"checksum\"},"
            "\"audit\":{"
                "\"user_id\":\"user_id\","
                "\"user_name\":\"user_name\","
                "\"group_id\":\"group_id\","
                "\"group_name\":\"group_name\","
                "\"process_name\":\"process_name\","
                "\"audit_uid\":\"audit_uid\","
                "\"audit_name\":\"audit_name\","
                "\"effective_uid\":\"effective_uid\","
                "\"effective_name\":\"effective_name\","
                "\"ppid\":12345,"
                "\"process_id\":23456,"
                "\"cwd\":\"cwd\","
                "\"parent_name\":\"parent_name\","
                "\"parent_cwd\":\"parent_cwd\"}}}";

    if(data = calloc(1, sizeof(fim_data_t)), data == NULL)
        return -1;

    data->event = cJSON_Parse(plain_event);

    if(data->event == NULL)
        return -1;

    if(data->lf = calloc(1, sizeof(Eventinfo)), data->lf == NULL)
        return -1;
    if(data->lf->fields = calloc(FIM_NFIELDS, sizeof(DynamicField)), data->lf->fields == NULL)
        return -1;
    data->lf->nfields = FIM_NFIELDS;

    if(data->lf->decoder_info = calloc(1, sizeof(OSDecoderInfo)), data->lf->decoder_info == NULL)
        return -1;
    if(data->lf->decoder_info->fields = calloc(FIM_NFIELDS, sizeof(char*)), data->lf->decoder_info->fields == NULL)
        return -1;
    if(data->lf->full_log = calloc(OS_MAXSTR, sizeof(char)), data->lf->full_log == NULL)
        return -1;

    if(data->lf->decoder_info->fields[FIM_FILE] = strdup("file"), data->lf->decoder_info->fields[FIM_FILE] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_HARD_LINKS] = strdup("hard_links"), data->lf->decoder_info->fields[FIM_HARD_LINKS] == NULL)
        return -1;
    if (data->lf->decoder_info->fields[FIM_MODE] = strdup("mode"), data->lf->decoder_info->fields[FIM_MODE] == NULL)
        return -1;
    if (data->lf->fields[FIM_MODE].value = strdup("fim_mode"), data->lf->fields[FIM_MODE].value == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_SIZE] = strdup("size"), data->lf->decoder_info->fields[FIM_SIZE] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_PERM] = strdup("perm"), data->lf->decoder_info->fields[FIM_PERM] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_UID] = strdup("uid"), data->lf->decoder_info->fields[FIM_UID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_GID] = strdup("gid"), data->lf->decoder_info->fields[FIM_GID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_MD5] = strdup("md5"), data->lf->decoder_info->fields[FIM_MD5] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_SHA1] = strdup("sha1"), data->lf->decoder_info->fields[FIM_SHA1] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_UNAME] = strdup("uname"), data->lf->decoder_info->fields[FIM_UNAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_GNAME] = strdup("gname"), data->lf->decoder_info->fields[FIM_GNAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_MTIME] = strdup("mtime"), data->lf->decoder_info->fields[FIM_MTIME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_INODE] = strdup("inode"), data->lf->decoder_info->fields[FIM_INODE] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_SHA256] = strdup("sha256"), data->lf->decoder_info->fields[FIM_SHA256] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_DIFF] = strdup("diff"), data->lf->decoder_info->fields[FIM_DIFF] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_ATTRS] = strdup("attrs"), data->lf->decoder_info->fields[FIM_ATTRS] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_CHFIELDS] = strdup("chfields"), data->lf->decoder_info->fields[FIM_CHFIELDS] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_USER_ID] = strdup("user_id"), data->lf->decoder_info->fields[FIM_USER_ID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_USER_NAME] = strdup("user_name"), data->lf->decoder_info->fields[FIM_USER_NAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_GROUP_ID] = strdup("group_id"), data->lf->decoder_info->fields[FIM_GROUP_ID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_GROUP_NAME] = strdup("group_name"), data->lf->decoder_info->fields[FIM_GROUP_NAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_PROC_NAME] = strdup("proc_name"), data->lf->decoder_info->fields[FIM_PROC_NAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_AUDIT_ID] = strdup("audit_id"), data->lf->decoder_info->fields[FIM_AUDIT_ID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_AUDIT_NAME] = strdup("audit_name"), data->lf->decoder_info->fields[FIM_AUDIT_NAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_EFFECTIVE_UID] = strdup("effective_uid"), data->lf->decoder_info->fields[FIM_EFFECTIVE_UID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_EFFECTIVE_NAME] = strdup("effective_name"), data->lf->decoder_info->fields[FIM_EFFECTIVE_NAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_PPID] = strdup("ppid"), data->lf->decoder_info->fields[FIM_PPID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_PROC_ID] = strdup("proc_id"), data->lf->decoder_info->fields[FIM_PROC_ID] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_TAG] = strdup("tag"), data->lf->decoder_info->fields[FIM_TAG] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_SYM_PATH] = strdup("sym_path"), data->lf->decoder_info->fields[FIM_SYM_PATH] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_AUDIT_CWD] = strdup("cwd"), data->lf->decoder_info->fields[FIM_AUDIT_CWD] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_PROC_PNAME] = strdup("parent_name"), data->lf->decoder_info->fields[FIM_PROC_PNAME] == NULL)
        return -1;
    if(data->lf->decoder_info->fields[FIM_AUDIT_PCWD] = strdup("parent_cwd"), data->lf->decoder_info->fields[FIM_AUDIT_PCWD] == NULL)
        return -1;

    *state = data;

    return 0;
}

static int teardown_fim_data(void **state) {
    fim_data_t *data = *state;
    int i;

    for(i = 0; i < FIM_NFIELDS; i++) {
        free(data->lf->decoder_info->fields[i]);
    }
    free(data->lf->decoder_info->fields);
    free(data->lf->decoder_info);

    cJSON_Delete(data->event);

    Free_Eventinfo(data->lf);

    free(data);

    return 0;
}

static int setup_decode_fim_event(void **state) {
    Eventinfo *data;
    const char *plain_event = "{\"type\":\"event\","
        "\"data\":{"
            "\"path\":\"/a/path\","
            "\"mode\":\"whodata\","
            "\"type\":\"added\","
            "\"timestamp\":123456789,"
            "\"changed_attributes\":["
                "\"size\",\"permission\",\"uid\","
                "\"user_name\",\"gid\",\"group_name\","
                "\"mtime\",\"inode\",\"md5\",\"sha1\",\"sha256\"],"
            "\"tags\":\"tags\","
            "\"hard_links\":["
                "\"/a/hard1.file\","
                "\"/b/hard2.file\"],"
            "\"content_changes\":\"some_changes\","
            "\"old_attributes\":{"
                "\"type\":\"file\","
                "\"size\":1234,"
                "\"perm\":\"old_perm\","
                "\"user_name\":\"old_user_name\","
                "\"group_name\":\"old_group_name\","
                "\"uid\":\"old_uid\","
                "\"gid\":\"old_gid\","
                "\"inode\":2345,"
                "\"mtime\":3456,"
                "\"hash_md5\":\"old_hash_md5\","
                "\"hash_sha1\":\"old_hash_sha1\","
                "\"hash_sha256\":\"old_hash_sha256\","
                "\"win_attributes\":\"old_win_attributes\","
                "\"symlink_path\":\"old_symlink_path\","
                "\"checksum\":\"old_checksum\"},"
            "\"attributes\":{"
                "\"type\":\"file\","
                "\"size\":4567,"
                "\"perm\":\"perm\","
                "\"user_name\":\"user_name\","
                "\"group_name\":\"group_name\","
                "\"uid\":\"uid\","
                "\"gid\":\"gid\","
                "\"inode\":5678,"
                "\"mtime\":6789,"
                "\"hash_md5\":\"hash_md5\","
                "\"hash_sha1\":\"hash_sha1\","
                "\"hash_sha256\":\"hash_sha256\","
                "\"win_attributes\":\"win_attributes\","
                "\"symlink_path\":\"symlink_path\","
                "\"checksum\":\"checksum\"},"
            "\"audit\":{"
                "\"user_id\":\"user_id\","
                "\"user_name\":\"user_name\","
                "\"group_id\":\"group_id\","
                "\"group_name\":\"group_name\","
                "\"process_name\":\"process_name\","
                "\"audit_uid\":\"audit_uid\","
                "\"audit_name\":\"audit_name\","
                "\"effective_uid\":\"effective_uid\","
                "\"effective_name\":\"effective_name\","
                "\"ppid\":12345,"
                "\"process_id\":23456,"
                "\"cwd\":\"cwd\","
                "\"parent_name\":\"parent_name\","
                "\"parent_cwd\":\"parent_cwd\"}}}";

    if(data = calloc(1, sizeof(Eventinfo)), data == NULL)
        return -1;

    if(data->fields = calloc(FIM_NFIELDS, sizeof(DynamicField)), data->fields == NULL)
        return -1;
    if(data->decoder_info = calloc(1, sizeof(OSDecoderInfo)), data->decoder_info == NULL)
        return -1;
    if(data->decoder_info->fields = calloc(FIM_NFIELDS, sizeof(char*)), data->decoder_info->fields == NULL)
        return -1;
    if(data->full_log = calloc(OS_MAXSTR, sizeof(char)), data->full_log == NULL)
        return -1;

    if(data->decoder_info->fields[FIM_FILE] = strdup("file"), data->decoder_info->fields[FIM_FILE] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_HARD_LINKS] = strdup("hard_links"), data->decoder_info->fields[FIM_HARD_LINKS] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_SIZE] = strdup("size"), data->decoder_info->fields[FIM_SIZE] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_PERM] = strdup("perm"), data->decoder_info->fields[FIM_PERM] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_UID] = strdup("uid"), data->decoder_info->fields[FIM_UID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_GID] = strdup("gid"), data->decoder_info->fields[FIM_GID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_MD5] = strdup("md5"), data->decoder_info->fields[FIM_MD5] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_SHA1] = strdup("sha1"), data->decoder_info->fields[FIM_SHA1] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_UNAME] = strdup("uname"), data->decoder_info->fields[FIM_UNAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_GNAME] = strdup("gname"), data->decoder_info->fields[FIM_GNAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_MTIME] = strdup("mtime"), data->decoder_info->fields[FIM_MTIME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_INODE] = strdup("inode"), data->decoder_info->fields[FIM_INODE] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_SHA256] = strdup("sha256"), data->decoder_info->fields[FIM_SHA256] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_DIFF] = strdup("diff"), data->decoder_info->fields[FIM_DIFF] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_ATTRS] = strdup("attrs"), data->decoder_info->fields[FIM_ATTRS] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_CHFIELDS] = strdup("chfields"), data->decoder_info->fields[FIM_CHFIELDS] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_USER_ID] = strdup("user_id"), data->decoder_info->fields[FIM_USER_ID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_USER_NAME] = strdup("user_name"), data->decoder_info->fields[FIM_USER_NAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_GROUP_ID] = strdup("group_id"), data->decoder_info->fields[FIM_GROUP_ID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_GROUP_NAME] = strdup("group_name"), data->decoder_info->fields[FIM_GROUP_NAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_PROC_NAME] = strdup("proc_name"), data->decoder_info->fields[FIM_PROC_NAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_AUDIT_ID] = strdup("audit_id"), data->decoder_info->fields[FIM_AUDIT_ID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_AUDIT_NAME] = strdup("audit_name"), data->decoder_info->fields[FIM_AUDIT_NAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_EFFECTIVE_UID] = strdup("effective_uid"), data->decoder_info->fields[FIM_EFFECTIVE_UID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_EFFECTIVE_NAME] = strdup("effective_name"), data->decoder_info->fields[FIM_EFFECTIVE_NAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_PPID] = strdup("ppid"), data->decoder_info->fields[FIM_PPID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_PROC_ID] = strdup("proc_id"), data->decoder_info->fields[FIM_PROC_ID] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_TAG] = strdup("tag"), data->decoder_info->fields[FIM_TAG] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_SYM_PATH] = strdup("sym_path"), data->decoder_info->fields[FIM_SYM_PATH] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_AUDIT_CWD] = strdup("cwd"), data->decoder_info->fields[FIM_AUDIT_CWD] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_PROC_PNAME] = strdup("parent_name"), data->decoder_info->fields[FIM_PROC_PNAME] == NULL)
        return -1;
    if(data->decoder_info->fields[FIM_AUDIT_PCWD] = strdup("parent_cwd"), data->decoder_info->fields[FIM_AUDIT_PCWD] == NULL)
        return -1;

    if(data->log = strdup(plain_event), data->log == NULL)
        return -1;

    *state = data;

    return 0;
}

static int teardown_decode_fim_event(void **state) {
    Eventinfo *data = *state;
    int i;

    if(data->log){
        free(data->log);
        data->log = NULL;
    }

    for(i = 0; i < FIM_NFIELDS; i++) {
        free(data->decoder_info->fields[i]);
    }
    free(data->decoder_info->fields);
    free(data->decoder_info);

    Free_Eventinfo(data);

    return 0;
}

static int setup_fim_adjust_checksum(void **state) {
    fim_adjust_checksum_data_t *data;

    if(data = calloc(1, sizeof(fim_adjust_checksum_data_t)), data == NULL)
        return -1;
    if(data->newsum = calloc(1, sizeof(sk_sum_t)), data->newsum == NULL)
        return -1;
    if(data->checksum = calloc(1, sizeof(char*)), data->checksum == NULL)
        return -1;

    *state = data;

    return 0;
}

static int teardown_fim_adjust_checksum(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    sk_sum_clean(data->newsum);
    free(data->newsum);

    if(*data->checksum) {
        free(*data->checksum);
    }
    if(data->checksum) {
        free(data->checksum);
    }

    if(data) {
        free(data);
        data = NULL;
    }

    return 0;
}

/* tests */
/* fim_send_db_query */
static void test_fim_send_db_query_success(void **state) {
    const char *query = "This is a mock query, it wont go anywhere";
    const char *result = "This is a mock query result, it wont go anywhere";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_send_db_query(&sock, query);
}

static void test_fim_send_db_query_communication_error(void **state) {
    const char *query = "This is a mock query, it wont go anywhere";
    const char *result = "This is a mock query result, it wont go anywhere";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -2);

    expect_string(__wrap__merror, formatted_msg, "FIM decoder: Cannot communicate with database.");

    fim_send_db_query(&sock, query);
}

static void test_fim_send_db_query_no_response(void **state) {
    const char *query = "This is a mock query, it wont go anywhere";
    const char *result = "This is a mock query result, it wont go anywhere";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "FIM decoder: Cannot get response from database.");

    fim_send_db_query(&sock, query);
}

static void test_fim_send_db_query_format_error(void **state) {
    const char *query = "This is a mock query, it wont go anywhere";
    const char *result = "This is a mock query result, it wont go anywhere";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    expect_string(__wrap__merror, formatted_msg,
        "FIM decoder: Bad response from database: is a mock query result, it wont go anywhere");

    fim_send_db_query(&sock, query);
}

/* fim_send_db_delete */
static void test_fim_send_db_delete_success(void **state) {
    _sdb sdb = {.socket=10};
    const char *agent_id = "001";
    const char *path = "/a/path";
    const char *result = "This is a mock query result, it wont go anywhere";

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 001 syscheck delete /a/path");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_send_db_delete(&sdb, agent_id, path);
}

static void test_fim_send_db_delete_query_too_long(void **state) {
    _sdb sdb = {.socket=10};
    const char *agent_id = "001";
    char path[OS_SIZE_6144];

    memset(path, 'a', OS_SIZE_6144);
    path[OS_SIZE_6144 - 1] = '\0';

    // This test should fail due to path being larger than the query buffer
    // but it doesn't...
    expect_string(__wrap__merror, formatted_msg, "FIM decoder: Cannot build delete query: input is too long.");

    fim_send_db_delete(&sdb, agent_id, path);
}

static void test_fim_send_db_delete_null_agent_id(void **state) {
    _sdb sdb = {.socket=10};
    const char *path = "/a/path";
    const char *result = "This is a mock query result, it wont go anywhere";

    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent (null) syscheck delete /a/path");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_send_db_delete(&sdb, NULL, path);
}

static void test_fim_send_db_delete_null_path(void **state) {
    _sdb sdb = {.socket=10};
    const char *agent_id = "001";
    const char *result = "This is a mock query result, it wont go anywhere";

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 001 syscheck delete (null)");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_send_db_delete(&sdb, agent_id, NULL);
}

/* fim_send_db_save */
static void test_fim_send_db_save_success(void **state) {
    _sdb sdb = {.socket = 10};
    const char *agent_id = "007";
    const char *result = "This is a mock query result, it wont go anywhere";
    cJSON *event = *state;

    cJSON *data = cJSON_GetObjectItem(event, "data");

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_send_db_save(&sdb, agent_id, data);
}

static void test_fim_send_db_save_event_too_long(void **state) {
    _sdb sdb = {.socket = 10};
    const char *agent_id = "007";
    char buffer[OS_MAXSTR];
    cJSON *event = *state;

    memset(buffer, 'a', OS_MAXSTR);
    buffer[OS_MAXSTR - 1] = '\0';


    cJSON *data = cJSON_GetObjectItem(event, "data");

    cJSON_DeleteItemFromObject(data, "attributes");
    cJSON_AddStringToObject(data, "attributes", buffer);

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_string(__wrap__merror, formatted_msg, "FIM decoder: Cannot build save2 query: input is too long.");

    fim_send_db_save(&sdb, agent_id, data);
}

static void test_fim_send_db_save_null_agent_id(void **state) {
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    cJSON *event = *state;

    cJSON *data = cJSON_GetObjectItem(event, "data");

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent (null) syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_send_db_save(&sdb, NULL, data);
}

static void test_fim_send_db_save_null_data(void **state) {
    _sdb sdb = {.socket = 10};
    const char *agent_id = "007";
    const char *result = "This is a mock query result, it wont go anywhere";

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 (null)");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_send_db_save(&sdb, agent_id, NULL);
}

/* fim_process_scan_info */
static void test_fim_process_scan_info_scan_start(void **state) {
    _sdb sdb = {.socket = 10};
    const char *agent_id = "007";
    const char *result = "This is a mock query result, it wont go anywhere";
    cJSON *event = *state;

    cJSON *data = cJSON_GetObjectItem(event, "data");

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck scan_info_update start_scan 123456789");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_process_scan_info(&sdb, agent_id, FIM_SCAN_START, data);
}

static void test_fim_process_scan_info_scan_end(void **state) {
    _sdb sdb = {.socket = 10};
    const char *agent_id = "007";
    const char *result = "This is a mock query result, it wont go anywhere";
    cJSON *event = *state;

    cJSON *data = cJSON_GetObjectItem(event, "data");

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck scan_info_update end_scan 123456789");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_process_scan_info(&sdb, agent_id, FIM_SCAN_END, data);
}

static void test_fim_process_scan_info_timestamp_not_a_number(void **state) {
    _sdb sdb = {.socket = 10};
    const char *agent_id = "007";
    cJSON *event = *state;

    cJSON *data = cJSON_GetObjectItem(event, "data");

    cJSON_DeleteItemFromObject(data, "timestamp");
    cJSON_AddStringToObject(data, "timestamp", "not_a_number");

    expect_string(__wrap__mdebug1, formatted_msg, "No such member \"timestamp\" in FIM scan info event.");

    fim_process_scan_info(&sdb, agent_id, FIM_SCAN_START, data);
}

static void test_fim_process_scan_info_query_too_long(void **state) {
    _sdb sdb = {.socket = 10};
    char buffer[OS_SIZE_6144];
    cJSON *event = *state;

    cJSON *data = cJSON_GetObjectItem(event, "data");

    memset(buffer, 'a', OS_SIZE_6144);
    buffer[OS_SIZE_6144 - 1] = '\0';

    expect_string(__wrap__merror, formatted_msg, "FIM decoder: Cannot build save query: input is too long.");

    fim_process_scan_info(&sdb, buffer, FIM_SCAN_START, data);
}

static void test_fim_process_scan_info_null_agent_id(void **state) {
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    cJSON *event = *state;

    cJSON *data = cJSON_GetObjectItem(event, "data");

    // Assertion of this test is done through fim_send_db_query.
    // The following lines configure the test to check a correct input message.
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent (null) syscheck scan_info_update start_scan 123456789");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    fim_process_scan_info(&sdb, NULL, FIM_SCAN_START, data);
}

static void test_fim_process_scan_info_null_data(void **state) {
    _sdb sdb = {.socket = 10};
    const char *agent_id = "007";

    expect_string(__wrap__mdebug1, formatted_msg, "No such member \"timestamp\" in FIM scan info event.");

    fim_process_scan_info(&sdb, agent_id, FIM_SCAN_START, NULL);
}

/* fim_fetch_attributes_state */
static void test_fim_fetch_attributes_state_new_attr(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attr = cJSON_GetObjectItem(data, "attributes");

    ret = fim_fetch_attributes_state(attr, input->lf, 1);

    assert_int_equal(ret, 0);
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");
}

static void test_fim_fetch_attributes_state_old_attr(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attr = cJSON_GetObjectItem(data, "attributes");

    ret = fim_fetch_attributes_state(attr, input->lf, 0);

    assert_int_equal(ret, 0);
    assert_string_equal(input->lf->size_before, "4567");
    assert_int_equal(input->lf->inode_before, 5678);
    assert_int_equal(input->lf->mtime_before, 6789);
    assert_string_equal(input->lf->perm_before, "perm");
    assert_string_equal(input->lf->uname_before, "user_name");
    assert_string_equal(input->lf->gname_before, "group_name");
    assert_string_equal(input->lf->owner_before, "uid");
    assert_string_equal(input->lf->gowner_before, "gid");
    assert_string_equal(input->lf->md5_before, "hash_md5");
    assert_string_equal(input->lf->sha1_before, "hash_sha1");
    assert_string_equal(input->lf->sha256_before, "hash_sha256");
}

static void test_fim_fetch_attributes_state_item_with_no_key(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attr = cJSON_GetObjectItem(data, "attributes");

    cJSON *corrupted_element = cJSON_GetObjectItem(attr, "mtime");
    free(corrupted_element->string);
    corrupted_element->string = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "FIM attribute set contains an item with no key.");

    ret = fim_fetch_attributes_state(attr, input->lf, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_fetch_attributes_state_invalid_element_type(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attr = cJSON_GetObjectItem(data, "attributes");

    cJSON_AddArrayToObject(attr, "invalid_element");

    expect_string(__wrap__mdebug1, formatted_msg, "Unknown FIM data type.");

    ret = fim_fetch_attributes_state(attr, input->lf, 1);

    assert_int_equal(ret, 0);
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");
}

static void test_fim_fetch_attributes_state_null_attr(void **state) {
    fim_data_t *input = *state;
    int ret;

    ret = fim_fetch_attributes_state(NULL, input->lf, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_fetch_attributes_state_null_lf(void **state) {
    fim_data_t *input = *state;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attr = cJSON_GetObjectItem(data, "attributes");

    expect_assert_failure(fim_fetch_attributes_state(attr, NULL, 1));
}

/* fim_fetch_attributes */
static void test_fim_fetch_attributes_success(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *new_attrs = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attrs = cJSON_GetObjectItem(data, "old_attributes");

    ret = fim_fetch_attributes(new_attrs, old_attrs, input->lf);

    assert_int_equal(ret, 0);

    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");
}

static void test_fim_fetch_attributes_invalid_attribute(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *new_attrs = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attrs = cJSON_GetObjectItem(data, "old_attributes");

    cJSON *corrupted_element = cJSON_GetObjectItem(new_attrs, "mtime");
    free(corrupted_element->string);
    corrupted_element->string = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "FIM attribute set contains an item with no key.");

    ret = fim_fetch_attributes(new_attrs, old_attrs, input->lf);

    assert_int_equal(ret, -1);
}

static void test_fim_fetch_attributes_null_new_attrs(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *old_attrs = cJSON_GetObjectItem(data, "old_attributes");

    ret = fim_fetch_attributes(NULL, old_attrs, input->lf);

    assert_int_equal(ret, 0);

    /* assert new attributes */
    assert_null(input->lf->fields[FIM_SIZE].value);
    assert_null(input->lf->fields[FIM_INODE].value);
    assert_int_equal(input->lf->inode_after, 0);
    assert_null(input->lf->fields[FIM_MTIME].value);
    assert_int_equal(input->lf->mtime_after, 0);
    assert_null(input->lf->fields[FIM_PERM].value);
    assert_null(input->lf->fields[FIM_UNAME].value);
    assert_null(input->lf->fields[FIM_GNAME].value);
    assert_null(input->lf->fields[FIM_UID].value);
    assert_null(input->lf->fields[FIM_GID].value);
    assert_null(input->lf->fields[FIM_MD5].value);
    assert_null(input->lf->fields[FIM_SHA1].value);
    assert_null(input->lf->fields[FIM_SHA256].value);
    assert_null(input->lf->fields[FIM_SYM_PATH].value);

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");
}

static void test_fim_fetch_attributes_null_old_attrs(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *new_attrs = cJSON_GetObjectItem(data, "attributes");

    ret = fim_fetch_attributes(new_attrs, NULL, input->lf);

    assert_int_equal(ret, 0);

    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_null(input->lf->size_before);
    assert_int_equal(input->lf->inode_before, 0);
    assert_int_equal(input->lf->mtime_before, 0);
    assert_null(input->lf->perm_before);
    assert_null(input->lf->uname_before);
    assert_null(input->lf->gname_before);
    assert_null(input->lf->owner_before);
    assert_null(input->lf->gowner_before);
    assert_null(input->lf->md5_before);
    assert_null(input->lf->sha1_before);
    assert_null(input->lf->sha256_before);
}

static void test_fim_fetch_attributes_null_lf(void **state) {
    fim_data_t *input = *state;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *new_attrs = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attrs = cJSON_GetObjectItem(data, "old_attributes");

    expect_assert_failure(fim_fetch_attributes(new_attrs, old_attrs, NULL));
}

/* fim_generate_comment */
static void test_fim_generate_comment_both_parameters(void **state) {
    char str[OS_MAXSTR];
    const char *format = "a1 is: %s - a2 is: %s";
    const char *a1 = "'a1'";
    const char *a2 = "'a2'";
    size_t ret;

    ret = fim_generate_comment(str, OS_MAXSTR, format, a1, a2);

    assert_int_equal(ret, 25);
    assert_string_equal(str, "a1 is: 'a1' - a2 is: 'a2'");
}

static void test_fim_generate_comment_a1(void **state) {
    char str[OS_MAXSTR];
    const char *format = "a1 is: %s - a2 is: %s";
    const char *a1 = "'a1'";
    size_t ret;

    ret = fim_generate_comment(str, OS_MAXSTR, format, a1, NULL);

    assert_int_equal(ret, 21);
    assert_string_equal(str, "a1 is: 'a1' - a2 is: ");
}

static void test_fim_generate_comment_a2(void **state) {
    char str[OS_MAXSTR];
    const char *format = "a1 is: %s - a2 is: %s";
    const char *a2 = "'a2'";
    size_t ret;

    ret = fim_generate_comment(str, OS_MAXSTR, format, NULL, a2);

    assert_int_equal(ret, 21);
    assert_string_equal(str, "a1 is:  - a2 is: 'a2'");
}

static void test_fim_generate_comment_no_parameters(void **state) {
    char str[OS_MAXSTR];
    const char *format = "a1 is: %s - a2 is: %s";
    size_t ret;

    str[0] = '\0';
    ret = fim_generate_comment(str, OS_MAXSTR, format, NULL, NULL);

    assert_int_equal(ret, 0);
    assert_string_equal(str, "");
}

static void test_fim_generate_comment_matching_parameters(void **state) {
    char str[OS_MAXSTR];
    const char *format = "a1 is: %s - a2 is: %s";
    const char *a1 = "'a1'";
    const char *a2 = "'a1'";
    size_t ret;

    str[0] = '\0';
    ret = fim_generate_comment(str, OS_MAXSTR, format, a1, a2);

    assert_int_equal(ret, 0);
    assert_string_equal(str, "");
}

static void test_fim_generate_comment_size_not_big_enough(void **state) {
    char str[OS_MAXSTR];
    const char *format = "a1 is: %s - a2 is: %s";
    const char *a1 = "'a1'";
    const char *a2 = "'a2'";
    size_t ret;

    ret = fim_generate_comment(str, 10, format, a1, a2);

    assert_int_equal(ret, 25);
    assert_string_equal(str, "a1 is: 'a");
}

static void test_fim_generate_comment_invalid_format(void **state) {
    char str[OS_MAXSTR];
    const char *format = "This format is not valid, and won't use a1 or a2";
    const char *a1 = "'a1'";
    const char *a2 = "'a2'";
    size_t ret;

    ret = fim_generate_comment(str, OS_MAXSTR, format, a1, a2);

    assert_int_equal(ret, 48);
    assert_string_equal(str, "This format is not valid, and won't use a1 or a2");
}

/* fim_generate_alert */
static void test_fim_generate_alert_full_alert(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    cJSON *array_it;

    input->lf->event_type = FIM_MODIFIED;

    if(input->lf->fields[FIM_FILE].value = strdup("/a/file"), input->lf->fields[FIM_FILE].value == NULL)
        fail();

    if(input->lf->fields[FIM_HARD_LINKS].value = strdup("[\"/a/hard1.file\",\"/b/hard2.file\"]"), input->lf->fields[FIM_HARD_LINKS].value == NULL)
        fail();

    cJSON_ArrayForEach(array_it, changed_attributes) {
        wm_strcat(&input->lf->fields[FIM_CHFIELDS].value, cJSON_GetStringValue(array_it), ',');
    }

    ret = fim_generate_alert(input->lf, event_type, attributes, old_attributes, audit);

    assert_int_equal(ret, 0);

    // Assert fim_fetch_attributes
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    /* Assert actual output */
    assert_string_equal(input->lf->full_log,
        "File '/a/file' fim_event_type\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: fim_mode\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n"
        "Size changed from '1234' to '4567'\n"
        "Permissions changed from 'old_perm' to 'perm'\n"
        "Ownership was 'old_uid', now it is 'uid'\n"
        "User name was 'old_user_name', now it is 'user_name'\n"
        "Group ownership was 'old_gid', now it is 'gid'\n"
        "Group name was 'old_group_name', now it is 'group_name'\n"
        "Old modification time was: '3456', now it is '6789'\n"
        "Old inode was: '2345', now it is '5678'\n"
        "Old md5sum was: 'old_hash_md5'\n"
        "New md5sum is : 'hash_md5'\n"
        "Old sha1sum was: 'old_hash_sha1'\n"
        "New sha1sum is : 'hash_sha1'\n"
        "Old sha256sum was: 'old_hash_sha256'\n"
        "New sha256sum is : 'hash_sha256'\n");
}

static void test_fim_generate_alert_type_not_modified(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    cJSON *array_it;

    input->lf->event_type = FIM_ADDED;

    if(input->lf->fields[FIM_FILE].value = strdup("/a/file"), input->lf->fields[FIM_FILE].value == NULL)
        fail();

    cJSON_ArrayForEach(array_it, changed_attributes) {
        wm_strcat(&input->lf->fields[FIM_CHFIELDS].value, cJSON_GetStringValue(array_it), ',');
    }

    ret = fim_generate_alert(input->lf, event_type, attributes, old_attributes, audit);

    assert_int_equal(ret, 0);

    // Assert fim_fetch_attributes
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    /* Assert actual output */
    assert_string_equal(input->lf->full_log,
        "File '/a/file' fim_event_type\n"
        "Mode: fim_mode\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");
}

static void test_fim_generate_alert_invalid_element_in_attributes(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");

    cJSON *corrupted_element = cJSON_GetObjectItem(attributes, "mtime");
    free(corrupted_element->string);
    corrupted_element->string = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "FIM attribute set contains an item with no key.");

    ret = fim_generate_alert(input->lf, event_type, attributes, old_attributes, audit);

    assert_int_equal(ret, -1);
}

static void test_fim_generate_alert_invalid_element_in_audit(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");

    cJSON *corrupted_element = cJSON_GetObjectItem(audit, "ppid");
    free(corrupted_element->string);
    corrupted_element->string = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "FIM audit set contains an item with no key.");

    ret = fim_generate_alert(input->lf, event_type, attributes, old_attributes, audit);

    assert_int_equal(ret, -1);
}

static void test_fim_generate_alert_null_mode(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    cJSON *array_it;

    input->lf->event_type = FIM_ADDED;

    if(input->lf->fields[FIM_FILE].value = strdup("/a/file"), input->lf->fields[FIM_FILE].value == NULL)
        fail();

    cJSON_ArrayForEach(array_it, changed_attributes) {
        wm_strcat(&input->lf->fields[FIM_CHFIELDS].value, cJSON_GetStringValue(array_it), ',');
    }

    input->lf->fields[FIM_MODE].value = NULL;

    ret = fim_generate_alert(input->lf, event_type, attributes, old_attributes, audit);

    assert_int_equal(ret, 0);

    // Assert fim_fetch_attributes
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    /* Assert actual output */
    assert_string_equal(input->lf->full_log,
        "File '/a/file' fim_event_type\n"
        "Mode: (null)\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");
}

static void test_fim_generate_alert_null_event_type(void **state) {
    fim_data_t *input = *state;
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    cJSON *array_it;

    input->lf->event_type = FIM_ADDED;

    if(input->lf->fields[FIM_FILE].value = strdup("/a/file"), input->lf->fields[FIM_FILE].value == NULL)
        fail();

    cJSON_ArrayForEach(array_it, changed_attributes) {
        wm_strcat(&input->lf->fields[FIM_CHFIELDS].value, cJSON_GetStringValue(array_it), ',');
    }

    ret = fim_generate_alert(input->lf, NULL, attributes, old_attributes, audit);

    assert_int_equal(ret, 0);

    // Assert fim_fetch_attributes
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    /* Assert actual output */
    assert_string_equal(input->lf->full_log,
        "File '/a/file' (null)\n"
        "Mode: fim_mode\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");
}

static void test_fim_generate_alert_null_attributes(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    cJSON *array_it;

    input->lf->event_type = FIM_MODIFIED;

    if(input->lf->fields[FIM_FILE].value = strdup("/a/file"), input->lf->fields[FIM_FILE].value == NULL)
        fail();

    cJSON_ArrayForEach(array_it, changed_attributes) {
        wm_strcat(&input->lf->fields[FIM_CHFIELDS].value, cJSON_GetStringValue(array_it), ',');
    }

    ret = fim_generate_alert(input->lf, event_type, NULL, old_attributes, audit);

    assert_int_equal(ret, 0);

    // Assert fim_fetch_attributes
    /* assert new attributes */
    assert_null(input->lf->fields[FIM_SIZE].value);
    assert_null(input->lf->fields[FIM_INODE].value);
    assert_int_equal(input->lf->inode_after, 0);
    assert_null(input->lf->fields[FIM_MTIME].value);
    assert_int_equal(input->lf->mtime_after, 0);
    assert_null(input->lf->fields[FIM_PERM].value);
    assert_null(input->lf->fields[FIM_UNAME].value);
    assert_null(input->lf->fields[FIM_GNAME].value);
    assert_null(input->lf->fields[FIM_UID].value);
    assert_null(input->lf->fields[FIM_GID].value);
    assert_null(input->lf->fields[FIM_MD5].value);
    assert_null(input->lf->fields[FIM_SHA1].value);
    assert_null(input->lf->fields[FIM_SHA256].value);
    assert_null(input->lf->fields[FIM_SYM_PATH].value);

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    /* Assert actual output */
    assert_string_equal(input->lf->full_log,
        "File '/a/file' fim_event_type\n"
        "Mode: fim_mode\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n"
        "Size changed from '1234' to ''\n"
        "Permissions changed from 'old_perm' to ''\n"
        "Ownership was 'old_uid', now it is ''\n"
        "User name was 'old_user_name', now it is ''\n"
        "Group ownership was 'old_gid', now it is ''\n"
        "Group name was 'old_group_name', now it is ''\n"
        "Old modification time was: '3456', now it is '0'\n"
        "Old inode was: '2345', now it is '0'\n"
        "Old md5sum was: 'old_hash_md5'\n"
        "New md5sum is : ''\n"
        "Old sha1sum was: 'old_hash_sha1'\n"
        "New sha1sum is : ''\n"
        "Old sha256sum was: 'old_hash_sha256'\n"
        "New sha256sum is : ''\n");
}

static void test_fim_generate_alert_null_old_attributes(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    cJSON *array_it;

    input->lf->event_type = FIM_MODIFIED;

    if(input->lf->fields[FIM_FILE].value = strdup("/a/file"), input->lf->fields[FIM_FILE].value == NULL)
        fail();

    cJSON_ArrayForEach(array_it, changed_attributes) {
        wm_strcat(&input->lf->fields[FIM_CHFIELDS].value, cJSON_GetStringValue(array_it), ',');
    }

    ret = fim_generate_alert(input->lf, event_type, attributes, NULL, audit);

    assert_int_equal(ret, 0);

    // Assert fim_fetch_attributes
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_null(input->lf->size_before);
    assert_int_equal(input->lf->inode_before, 0);
    assert_int_equal(input->lf->mtime_before, 0);
    assert_null(input->lf->perm_before);
    assert_null(input->lf->uname_before);
    assert_null(input->lf->gname_before);
    assert_null(input->lf->owner_before);
    assert_null(input->lf->gowner_before);
    assert_null(input->lf->md5_before);
    assert_null(input->lf->sha1_before);
    assert_null(input->lf->sha256_before);

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    /* Assert actual output */
    assert_string_equal(input->lf->full_log,
        "File '/a/file' fim_event_type\n"
        "Mode: fim_mode\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n"
        "Size changed from '' to '4567'\n"
        "Permissions changed from '' to 'perm'\n"
        "Ownership was '', now it is 'uid'\n"
        "User name was '', now it is 'user_name'\n"
        "Group ownership was '', now it is 'gid'\n"
        "Group name was '', now it is 'group_name'\n"
        "Old modification time was: '0', now it is '6789'\n"
        "Old inode was: '0', now it is '5678'\n"
        "Old md5sum was: ''\n"
        "New md5sum is : 'hash_md5'\n"
        "Old sha1sum was: ''\n"
        "New sha1sum is : 'hash_sha1'\n"
        "Old sha256sum was: ''\n"
        "New sha256sum is : 'hash_sha256'\n");

}

static void test_fim_generate_alert_null_audit(void **state) {
    fim_data_t *input = *state;
    char *event_type = "fim_event_type";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    cJSON *array_it;

    input->lf->event_type = FIM_MODIFIED;

    if(input->lf->fields[FIM_FILE].value = strdup("/a/file"), input->lf->fields[FIM_FILE].value == NULL)
        fail();

    cJSON_ArrayForEach(array_it, changed_attributes) {
        wm_strcat(&input->lf->fields[FIM_CHFIELDS].value, cJSON_GetStringValue(array_it), ',');
    }

    ret = fim_generate_alert(input->lf, event_type, attributes, old_attributes, NULL);

    assert_int_equal(ret, 0);

    // Assert fim_fetch_attributes
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_null(input->lf->fields[FIM_PPID].value);
    assert_null(input->lf->fields[FIM_PROC_ID].value);
    assert_null(input->lf->fields[FIM_USER_ID].value);
    assert_null(input->lf->fields[FIM_USER_NAME].value);
    assert_null(input->lf->fields[FIM_GROUP_ID].value);
    assert_null(input->lf->fields[FIM_GROUP_NAME].value);
    assert_null(input->lf->fields[FIM_PROC_NAME].value);
    assert_null(input->lf->fields[FIM_AUDIT_ID].value);
    assert_null(input->lf->fields[FIM_AUDIT_NAME].value);
    assert_null(input->lf->fields[FIM_EFFECTIVE_UID].value);
    assert_null(input->lf->fields[FIM_EFFECTIVE_NAME].value);

    /* Assert actual output */
    assert_string_equal(input->lf->full_log,
        "File '/a/file' fim_event_type\n"
        "Mode: fim_mode\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n"
        "Size changed from '1234' to '4567'\n"
        "Permissions changed from 'old_perm' to 'perm'\n"
        "Ownership was 'old_uid', now it is 'uid'\n"
        "User name was 'old_user_name', now it is 'user_name'\n"
        "Group ownership was 'old_gid', now it is 'gid'\n"
        "Group name was 'old_group_name', now it is 'group_name'\n"
        "Old modification time was: '3456', now it is '6789'\n"
        "Old inode was: '2345', now it is '5678'\n"
        "Old md5sum was: 'old_hash_md5'\n"
        "New md5sum is : 'hash_md5'\n"
        "Old sha1sum was: 'old_hash_sha1'\n"
        "New sha1sum is : 'hash_sha1'\n"
        "Old sha256sum was: 'old_hash_sha256'\n"
        "New sha256sum is : 'hash_sha256'\n");
}

/* fim_process_alert */
static void test_fim_process_alert_added_success(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_modified_success(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");

    cJSON_DeleteItemFromObject(data, "type");
    cJSON_AddStringToObject(data, "type", "modified");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    /* Assert fim_generate_alert */
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' modified\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n"
        "Size changed from '1234' to '4567'\n"
        "Permissions changed from 'old_perm' to 'perm'\n"
        "Ownership was 'old_uid', now it is 'uid'\n"
        "User name was 'old_user_name', now it is 'user_name'\n"
        "Group ownership was 'old_gid', now it is 'gid'\n"
        "Group name was 'old_group_name', now it is 'group_name'\n"
        "Old modification time was: '3456', now it is '6789'\n"
        "Old inode was: '2345', now it is '5678'\n"
        "Old md5sum was: 'old_hash_md5'\n"
        "New md5sum is : 'hash_md5'\n"
        "Old sha1sum was: 'old_hash_sha1'\n"
        "New sha1sum is : 'hash_sha1'\n"
        "Old sha256sum was: 'old_hash_sha256'\n"
        "New sha256sum is : 'hash_sha256'\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_MODIFIED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_MOD);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_deleted_success(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");

    cJSON_DeleteItemFromObject(data, "type");
    cJSON_AddStringToObject(data, "type", "deleted");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_delete */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck delete /a/path");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' deleted\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_DELETED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_DEL);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_no_event_type(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");

    cJSON_DeleteItemFromObject(data, "type");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_delete */
    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in Syscheck JSON payload");

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, -1);
}

static void test_fim_process_alert_invalid_event_type(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");

    cJSON_DeleteItemFromObject(data, "type");
    cJSON_AddStringToObject(data, "type", "invalid");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_delete */
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid 'type' value 'invalid' in JSON payload.");

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, -1);
}

static void test_fim_process_alert_invalid_object(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");

    cJSON *corrupted_object = cJSON_GetObjectItem(data, "type");
    free(corrupted_object->string);
    corrupted_object->string = NULL;

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_delete */
    expect_string(__wrap__mdebug1, formatted_msg, "FIM event contains an item with no key.");

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, -1);
}

static void test_fim_process_alert_no_path(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "path");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '(null)' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_no_hard_links(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "hard_links");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' added\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_no_mode(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "mode");

    input->lf->fields[FIM_MODE].value = NULL;

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: (null)\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_no_tags(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "tags");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
    assert_null(input->lf->sk_tag);
    assert_null(input->lf->fields[FIM_TAG].value);
}

static void test_fim_process_alert_no_content_changes(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "content_changes");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
    assert_null(input->lf->fields[FIM_DIFF].value);
}

static void test_fim_process_alert_no_changed_attributes(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "changed_attributes");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
    assert_null(input->lf->fields[FIM_CHFIELDS].value);
}

static void test_fim_process_alert_no_attributes(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "attributes");
    cJSON_DeleteItemFromObject(data, "type");
    cJSON_AddStringToObject(data, "type", "modified");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_null(input->lf->fields[FIM_SIZE].value);
    assert_null(input->lf->fields[FIM_INODE].value);
    assert_int_equal(input->lf->inode_after, 0);
    assert_null(input->lf->fields[FIM_MTIME].value);
    assert_int_equal(input->lf->mtime_after, 0);
    assert_null(input->lf->fields[FIM_PERM].value);
    assert_null(input->lf->fields[FIM_UNAME].value);
    assert_null(input->lf->fields[FIM_GNAME].value);
    assert_null(input->lf->fields[FIM_UID].value);
    assert_null(input->lf->fields[FIM_GID].value);
    assert_null(input->lf->fields[FIM_MD5].value);
    assert_null(input->lf->fields[FIM_SHA1].value);
    assert_null(input->lf->fields[FIM_SHA256].value);
    assert_null(input->lf->fields[FIM_SYM_PATH].value);

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' modified\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n"
        "Size changed from '1234' to ''\n"
        "Permissions changed from 'old_perm' to ''\n"
        "Ownership was 'old_uid', now it is ''\n"
        "User name was 'old_user_name', now it is ''\n"
        "Group ownership was 'old_gid', now it is ''\n"
        "Group name was 'old_group_name', now it is ''\n"
        "Old modification time was: '3456', now it is '0'\n"
        "Old inode was: '2345', now it is '0'\n"
        "Old md5sum was: 'old_hash_md5'\n"
        "New md5sum is : ''\n"
        "Old sha1sum was: 'old_hash_sha1'\n"
        "New sha1sum is : ''\n"
        "Old sha256sum was: 'old_hash_sha256'\n"
        "New sha256sum is : ''\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_MODIFIED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_MOD);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_no_old_attributes(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "old_attributes");
    cJSON_DeleteItemFromObject(data, "type");
    cJSON_AddStringToObject(data, "type", "modified");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_null(input->lf->size_before);
    assert_int_equal(input->lf->inode_before, 0);
    assert_int_equal(input->lf->mtime_before, 0);
    assert_null(input->lf->perm_before);
    assert_null(input->lf->uname_before);
    assert_null(input->lf->gname_before);
    assert_null(input->lf->owner_before);
    assert_null(input->lf->gowner_before);
    assert_null(input->lf->md5_before);
    assert_null(input->lf->sha1_before);
    assert_null(input->lf->sha256_before);

    /* Assert values gotten from audit */
    assert_string_equal(input->lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(input->lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(input->lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(input->lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(input->lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(input->lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(input->lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(input->lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(input->lf->full_log,
        "File '/a/path' modified\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n"
        "Size changed from '' to '4567'\n"
        "Permissions changed from '' to 'perm'\n"
        "Ownership was '', now it is 'uid'\n"
        "User name was '', now it is 'user_name'\n"
        "Group ownership was '', now it is 'gid'\n"
        "Group name was '', now it is 'group_name'\n"
        "Old modification time was: '0', now it is '6789'\n"
        "Old inode was: '0', now it is '5678'\n"
        "Old md5sum was: ''\n"
        "New md5sum is : 'hash_md5'\n"
        "Old sha1sum was: ''\n"
        "New sha1sum is : 'hash_sha1'\n"
        "Old sha256sum was: ''\n"
        "New sha256sum is : 'hash_sha256'\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_MODIFIED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_MOD);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_no_audit(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *data = cJSON_GetObjectItem(input->event, "data");
    cJSON_DeleteItemFromObject(data, "audit");

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = fim_process_alert(&sdb, input->lf, data);

    assert_int_equal(ret, 0);

    // Assert fim_generate_alert
    /* assert new attributes */
    assert_string_equal(input->lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(input->lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(input->lf->inode_after, 5678);
    assert_string_equal(input->lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(input->lf->mtime_after, 6789);
    assert_string_equal(input->lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(input->lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(input->lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(input->lf->fields[FIM_UID].value, "uid");
    assert_string_equal(input->lf->fields[FIM_GID].value, "gid");
    assert_string_equal(input->lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(input->lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(input->lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(input->lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(input->lf->size_before, "1234");
    assert_int_equal(input->lf->inode_before, 2345);
    assert_int_equal(input->lf->mtime_before, 3456);
    assert_string_equal(input->lf->perm_before, "old_perm");
    assert_string_equal(input->lf->uname_before, "old_user_name");
    assert_string_equal(input->lf->gname_before, "old_group_name");
    assert_string_equal(input->lf->owner_before, "old_uid");
    assert_string_equal(input->lf->gowner_before, "old_gid");
    assert_string_equal(input->lf->md5_before, "old_hash_md5");
    assert_string_equal(input->lf->sha1_before, "old_hash_sha1");
    assert_string_equal(input->lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_null(input->lf->fields[FIM_PPID].value);
    assert_null(input->lf->fields[FIM_PROC_ID].value);
    assert_null(input->lf->fields[FIM_USER_ID].value);
    assert_null(input->lf->fields[FIM_USER_NAME].value);
    assert_null(input->lf->fields[FIM_GROUP_ID].value);
    assert_null(input->lf->fields[FIM_GROUP_NAME].value);
    assert_null(input->lf->fields[FIM_PROC_NAME].value);
    assert_null(input->lf->fields[FIM_AUDIT_ID].value);
    assert_null(input->lf->fields[FIM_AUDIT_NAME].value);
    assert_null(input->lf->fields[FIM_EFFECTIVE_UID].value);
    assert_null(input->lf->fields[FIM_EFFECTIVE_NAME].value);

    assert_string_equal(input->lf->full_log,
        "File '/a/path' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    /* Assert actual output */
    assert_int_equal(input->lf->event_type, FIM_ADDED);
    assert_string_equal(input->lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(input->lf->decoder_info->id, 0);
}

static void test_fim_process_alert_null_event(void **state) {
    fim_data_t *input = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    if(input->lf->agent_id = strdup("007"), input->lf->agent_id == NULL)
        fail();

    /* Inside fim_send_db_save */
    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in Syscheck JSON payload");

    ret = fim_process_alert(&sdb, input->lf, NULL);

    assert_int_equal(ret, -1);
}

/* decode_fim_event */
static void test_decode_fim_event_type_event(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    lf->decoder_info->fields[FIM_MODE] = strdup("mode");

    /* Inside fim_process_alert */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck save2 "
        "{\"path\":\"/a/path\","
        "\"timestamp\":123456789,"
        "\"attributes\":{"
            "\"type\":\"file\","
            "\"size\":4567,"
            "\"perm\":\"perm\","
            "\"user_name\":\"user_name\","
            "\"group_name\":\"group_name\","
            "\"uid\":\"uid\","
            "\"gid\":\"gid\","
            "\"inode\":5678,"
            "\"mtime\":6789,"
            "\"hash_md5\":\"hash_md5\","
            "\"hash_sha1\":\"hash_sha1\","
            "\"hash_sha256\":\"hash_sha256\","
            "\"win_attributes\":\"win_attributes\","
            "\"symlink_path\":\"symlink_path\","
            "\"checksum\":\"checksum\"}}");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 1);

    // Assert fim_process_alert
    /* assert new attributes */
    assert_string_equal(lf->fields[FIM_SIZE].value, "4567");
    assert_string_equal(lf->fields[FIM_INODE].value, "5678");
    assert_int_equal(lf->inode_after, 5678);
    assert_string_equal(lf->fields[FIM_MTIME].value, "6789");
    assert_int_equal(lf->mtime_after, 6789);
    assert_string_equal(lf->fields[FIM_PERM].value, "perm");
    assert_string_equal(lf->fields[FIM_UNAME].value, "user_name");
    assert_string_equal(lf->fields[FIM_GNAME].value, "group_name");
    assert_string_equal(lf->fields[FIM_UID].value, "uid");
    assert_string_equal(lf->fields[FIM_GID].value, "gid");
    assert_string_equal(lf->fields[FIM_MD5].value, "hash_md5");
    assert_string_equal(lf->fields[FIM_SHA1].value, "hash_sha1");
    assert_string_equal(lf->fields[FIM_SHA256].value, "hash_sha256");
    assert_string_equal(lf->fields[FIM_SYM_PATH].value, "symlink_path");

    /* assert old attributes */
    assert_string_equal(lf->size_before, "1234");
    assert_int_equal(lf->inode_before, 2345);
    assert_int_equal(lf->mtime_before, 3456);
    assert_string_equal(lf->perm_before, "old_perm");
    assert_string_equal(lf->uname_before, "old_user_name");
    assert_string_equal(lf->gname_before, "old_group_name");
    assert_string_equal(lf->owner_before, "old_uid");
    assert_string_equal(lf->gowner_before, "old_gid");
    assert_string_equal(lf->md5_before, "old_hash_md5");
    assert_string_equal(lf->sha1_before, "old_hash_sha1");
    assert_string_equal(lf->sha256_before, "old_hash_sha256");

    /* Assert values gotten from audit */
    assert_string_equal(lf->fields[FIM_PPID].value, "12345");
    assert_string_equal(lf->fields[FIM_PROC_ID].value, "23456");
    assert_string_equal(lf->fields[FIM_USER_ID].value, "user_id");
    assert_string_equal(lf->fields[FIM_USER_NAME].value, "user_name");
    assert_string_equal(lf->fields[FIM_GROUP_ID].value, "group_id");
    assert_string_equal(lf->fields[FIM_GROUP_NAME].value, "group_name");
    assert_string_equal(lf->fields[FIM_PROC_NAME].value, "process_name");
    assert_string_equal(lf->fields[FIM_AUDIT_ID].value, "audit_uid");
    assert_string_equal(lf->fields[FIM_AUDIT_NAME].value, "audit_name");
    assert_string_equal(lf->fields[FIM_EFFECTIVE_UID].value, "effective_uid");
    assert_string_equal(lf->fields[FIM_EFFECTIVE_NAME].value, "effective_name");

    assert_string_equal(lf->full_log,
        "File '/a/path' added\n"
        "Hard links: /a/hard1.file,/b/hard2.file\n"
        "Mode: whodata\n"
        "Changed attributes: size,permission,uid,user_name,gid,group_name,mtime,inode,md5,sha1,sha256\n");

    assert_int_equal(lf->event_type, FIM_ADDED);
    assert_string_equal(lf->decoder_info->name, SYSCHECK_NEW);
    assert_int_equal(lf->decoder_info->id, 0);

}

static void test_decode_fim_event_type_scan_start(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *event = cJSON_Parse(lf->log);
    cJSON_DeleteItemFromObject(event, "type");
    cJSON_AddStringToObject(event, "type", "scan_start");

    free(lf->log);
    lf->log = cJSON_PrintUnformatted(event);

    cJSON_Delete(event);

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    /* inside fim_process_scan_info */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck scan_info_update start_scan 123456789");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 0);
}

static void test_decode_fim_event_type_scan_end(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    const char *result = "This is a mock query result, it wont go anywhere";
    int ret;

    cJSON *event = cJSON_Parse(lf->log);
    cJSON_DeleteItemFromObject(event, "type");
    cJSON_AddStringToObject(event, "type", "scan_end");

    free(lf->log);
    lf->log = cJSON_PrintUnformatted(event);

    cJSON_Delete(event);

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    /* inside fim_process_scan_info */
    expect_any(__wrap_wdbc_query_ex, sock);
    expect_string(__wrap_wdbc_query_ex, query, "agent 007 syscheck scan_info_update end_scan 123456789");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 0);
}

static void test_decode_fim_event_type_invalid(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    cJSON *event = cJSON_Parse(lf->log);
    cJSON_DeleteItemFromObject(event, "type");
    cJSON_AddStringToObject(event, "type", "invalid");

    free(lf->log);
    lf->log = cJSON_PrintUnformatted(event);

    cJSON_Delete(event);

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 0);
}

static void test_decode_fim_event_null_item(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    cJSON *event = cJSON_Parse(lf->log);
    cJSON_DeleteItemFromObject(event, "data");
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "test", "test");
    cJSON_AddItemToObject(event, "data", data);

    free(lf->log);
    lf->log = cJSON_PrintUnformatted(event);

    cJSON_Delete(event);

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    expect_string(__wrap__mdebug1, formatted_msg, "No member 'type' in Syscheck JSON payload");
    expect_string(__wrap__merror, formatted_msg, "Can't generate fim alert for event: '"
        "{\"type\":\"event\","
        "\"data\":{"
            "\"test\":\"test\"}}'");
    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 0);
}

static void test_decode_fim_event_no_data(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    cJSON *event = cJSON_Parse(lf->log);
    cJSON_DeleteItemFromObject(event, "data");

    free(lf->log);
    lf->log = cJSON_PrintUnformatted(event);

    cJSON_Delete(event);

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    /* inside fim_process_scan_info */
    expect_string(__wrap__merror, formatted_msg, "Invalid FIM event");

    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 0);
}

static void test_decode_fim_event_no_type(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    cJSON *event = cJSON_Parse(lf->log);
    cJSON_DeleteItemFromObject(event, "type");

    free(lf->log);
    lf->log = cJSON_PrintUnformatted(event);

    cJSON_Delete(event);

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    /* inside fim_process_scan_info */
    expect_string(__wrap__merror, formatted_msg, "Invalid FIM event");

    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 0);
}

static void test_decode_fim_event_invalid_json(void **state) {
    Eventinfo *lf = *state;
    _sdb sdb = {.socket = 10};
    int ret;

    free(lf->log);
    lf->log = NULL;

    if(lf->agent_id = strdup("007"), lf->agent_id == NULL)
        fail();

    /* inside fim_process_scan_info */
    expect_string(__wrap__merror, formatted_msg, "Malformed FIM JSON event");

    ret = decode_fim_event(&sdb, lf);

    assert_int_equal(ret, 0);
}

static void test_decode_fim_event_null_sdb(void **state) {
    Eventinfo *lf = *state;

    expect_assert_failure(decode_fim_event(NULL, lf));
}

static void test_decode_fim_event_null_eventinfo(void **state) {
    _sdb sdb = {.socket = 10};

    expect_assert_failure(decode_fim_event(&sdb, NULL));
}

static void test_fim_adjust_checksum_no_attributes_no_win_perm(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    *data->checksum = strdup("unchanged string::");

    fim_adjust_checksum(data->newsum, data->checksum);

    assert_string_equal(*data->checksum, "unchanged string::");
}

static void test_fim_adjust_checksum_no_win_perm_no_colon(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    *data->checksum = strdup("unchanged string");
    data->newsum->attributes = strdup("unused attributes");

    fim_adjust_checksum(data->newsum, data->checksum);

    assert_string_equal(*data->checksum, "unchanged string");
}

static void test_fim_adjust_checksum_no_win_perm(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    *data->checksum = strdup("changed: string");
    data->newsum->attributes = strdup("to this");

    fim_adjust_checksum(data->newsum, data->checksum);

    assert_string_equal(*data->checksum, "changed:to this");
}

static void test_fim_adjust_checksum_no_attributes_no_first_part(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    *data->checksum = strdup("unchanged string");
    data->newsum->win_perm = strdup("first part");

    fim_adjust_checksum(data->newsum, data->checksum);

    assert_string_equal(*data->checksum, "unchanged string");
}

static void test_fim_adjust_checksum_no_attributes_no_second_part(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    *data->checksum = strdup("unchanged string: no second part");
    data->newsum->win_perm = strdup("first part");

    fim_adjust_checksum(data->newsum, data->checksum);

    assert_string_equal(*data->checksum, "unchanged string:");
}

static void test_fim_adjust_checksum_no_attributes(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    *data->checksum = strdup("changed string: first part: second part");
    data->newsum->win_perm = strdup("replaced: this");

    fim_adjust_checksum(data->newsum, data->checksum);

    assert_string_equal(*data->checksum, "changed string:replaced\\: this: second part");
}

static void test_fim_adjust_checksum_all_possible_data(void **state) {
    fim_adjust_checksum_data_t *data = *state;

    *data->checksum = strdup("changed string: first part: second part:attributes");
    data->newsum->win_perm = strdup("replaced: this");
    data->newsum->attributes = strdup("new attributes");

    fim_adjust_checksum(data->newsum, data->checksum);

    assert_string_equal(*data->checksum, "changed string:replaced\\: this: second part:new attributes");
}


int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_send_db_query */
        cmocka_unit_test(test_fim_send_db_query_success),
        cmocka_unit_test(test_fim_send_db_query_communication_error),
        cmocka_unit_test(test_fim_send_db_query_no_response),
        cmocka_unit_test(test_fim_send_db_query_format_error),

        /* fim_send_db_delete */
        cmocka_unit_test(test_fim_send_db_delete_success),
        cmocka_unit_test(test_fim_send_db_delete_query_too_long),
        cmocka_unit_test(test_fim_send_db_delete_null_agent_id),
        cmocka_unit_test(test_fim_send_db_delete_null_path),

        /* fim_send_db_save */
        cmocka_unit_test_setup_teardown(test_fim_send_db_save_success, setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_send_db_save_event_too_long, setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_send_db_save_null_agent_id, setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_send_db_save_null_data, setup_fim_event_cjson, teardown_fim_event_cjson),

        /* fim_process_scan_info */
        cmocka_unit_test_setup_teardown(test_fim_process_scan_info_scan_start,setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_process_scan_info_scan_end, setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_process_scan_info_timestamp_not_a_number,setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_process_scan_info_query_too_long,setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_process_scan_info_null_agent_id,setup_fim_event_cjson, teardown_fim_event_cjson),
        cmocka_unit_test_setup_teardown(test_fim_process_scan_info_null_data,setup_fim_event_cjson, teardown_fim_event_cjson),

        /* fim_fetch_attributes_state */
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_state_new_attr, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_state_old_attr, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_state_item_with_no_key, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_state_invalid_element_type, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_state_null_attr, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_state_null_lf, setup_fim_data, teardown_fim_data),

        /* fim_fetch_attributes */
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_success, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_invalid_attribute, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_null_new_attrs, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_null_old_attrs, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_fetch_attributes_null_lf, setup_fim_data, teardown_fim_data),

        /* fim_generate_comment */
        cmocka_unit_test(test_fim_generate_comment_both_parameters),
        cmocka_unit_test(test_fim_generate_comment_a1),
        cmocka_unit_test(test_fim_generate_comment_a2),
        cmocka_unit_test(test_fim_generate_comment_no_parameters),
        cmocka_unit_test(test_fim_generate_comment_matching_parameters),
        cmocka_unit_test(test_fim_generate_comment_size_not_big_enough),
        cmocka_unit_test(test_fim_generate_comment_invalid_format),

        /* fim_generate_alert */
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_full_alert, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_type_not_modified, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_invalid_element_in_attributes, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_invalid_element_in_audit, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_null_mode, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_null_event_type, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_null_attributes, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_null_old_attributes, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_generate_alert_null_audit, setup_fim_data, teardown_fim_data),

        /* fim_process_alert */
        cmocka_unit_test_setup_teardown(test_fim_process_alert_added_success, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_modified_success, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_deleted_success, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_event_type, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_invalid_event_type, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_invalid_object, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_path, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_hard_links, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_mode, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_tags, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_content_changes, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_changed_attributes, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_attributes, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_old_attributes, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_no_audit, setup_fim_data, teardown_fim_data),
        cmocka_unit_test_setup_teardown(test_fim_process_alert_null_event, setup_fim_data, teardown_fim_data),

        /* decode_fim_event */
        cmocka_unit_test_setup_teardown(test_decode_fim_event_type_event, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_type_scan_start, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_type_scan_end, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_type_invalid, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_null_item, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_no_data, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_no_type, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_invalid_json, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_null_sdb, setup_decode_fim_event, teardown_decode_fim_event),
        cmocka_unit_test_setup_teardown(test_decode_fim_event_null_eventinfo, setup_decode_fim_event, teardown_decode_fim_event),

        /* fim_adjust_checksum */
        cmocka_unit_test_setup_teardown(test_fim_adjust_checksum_no_attributes_no_win_perm, setup_fim_adjust_checksum, teardown_fim_adjust_checksum),
        cmocka_unit_test_setup_teardown(test_fim_adjust_checksum_no_win_perm_no_colon, setup_fim_adjust_checksum, teardown_fim_adjust_checksum),
        cmocka_unit_test_setup_teardown(test_fim_adjust_checksum_no_win_perm, setup_fim_adjust_checksum, teardown_fim_adjust_checksum),
        cmocka_unit_test_setup_teardown(test_fim_adjust_checksum_no_attributes_no_first_part, setup_fim_adjust_checksum, teardown_fim_adjust_checksum),
        cmocka_unit_test_setup_teardown(test_fim_adjust_checksum_no_attributes_no_second_part, setup_fim_adjust_checksum, teardown_fim_adjust_checksum),
        cmocka_unit_test_setup_teardown(test_fim_adjust_checksum_no_attributes, setup_fim_adjust_checksum, teardown_fim_adjust_checksum),
        cmocka_unit_test_setup_teardown(test_fim_adjust_checksum_all_possible_data, setup_fim_adjust_checksum, teardown_fim_adjust_checksum),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
