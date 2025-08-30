/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../wazuh_db/wdb_state.h"

extern wdb_state_t wdb_state;

/* setup/teardown */

static int test_setup(void ** state) {
    wdb_state.uptime = 123456789;
    wdb_state.queries_total = 856;
    wdb_state.queries_breakdown.global_queries = 227;
    wdb_state.queries_breakdown.global_breakdown.sql_queries = 8;
    wdb_state.queries_breakdown.global_breakdown.backup_queries = 6;
    wdb_state.queries_breakdown.global_breakdown.vacuum_queries = 3;
    wdb_state.queries_breakdown.global_breakdown.get_fragmentation_queries = 5;
    wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_queries = 16;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_queries = 30;
    wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_queries = 12;
    wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_queries = 20;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.find_agent_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_queries = 2;
    wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_queries = 2;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries = 2;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_queries = 5;
    wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_queries = 2;
    wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.group.delete_group_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.group.select_groups_queries = 84;
    wdb_state.queries_breakdown.global_breakdown.group.find_group_queries = 10;
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_queries = 10;
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.open_calls_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.open_calls_time.tv_usec = 123456;
    wdb_state.queries_breakdown.global_breakdown.sql_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.sql_time.tv_usec = 1523;
    wdb_state.queries_breakdown.global_breakdown.backup_time.tv_sec = 1;
    wdb_state.queries_breakdown.global_breakdown.backup_time.tv_usec = 145452;
    wdb_state.queries_breakdown.global_breakdown.vacuum_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.vacuum_time.tv_usec = 11111;
    wdb_state.queries_breakdown.global_breakdown.get_fragmentation_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.get_fragmentation_time.tv_usec = 22222;
    wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_time.tv_usec = 580960;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_time.tv_usec = 10020;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_time.tv_sec = 2;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_time.tv_usec = 125048;
    wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_time.tv_usec = 12358;
    wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_time.tv_usec = 148903;
    wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_time.tv_usec = 100020;
    wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_time.tv_usec = 1202;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_time.tv_usec = 14258;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_time.tv_usec = 152300;
    wdb_state.queries_breakdown.global_breakdown.agent.find_agent_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.find_agent_time.tv_usec = 78120;
    wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_time.tv_usec = 152358;
    wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_time.tv_usec = 25101;
    wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time.tv_sec = 1;
    wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time.tv_usec = 2000;
    wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_time.tv_usec= 412480;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time.tv_usec = 548906;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time.tv_usec = 81230;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time.tv_usec = 8460;
    wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_time.tv_usec = 61500;
    wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_time.tv_usec = 1200;
    wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_time.tv_usec = 10230;
    wdb_state.queries_breakdown.global_breakdown.group.delete_group_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.group.delete_group_time.tv_usec = 92200;
    wdb_state.queries_breakdown.global_breakdown.group.select_groups_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.group.select_groups_time.tv_usec = 10560;
    wdb_state.queries_breakdown.global_breakdown.group.find_group_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.group.find_group_time.tv_usec = 510;
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time.tv_usec = 25600;
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time.tv_usec = 12500;
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time.tv_usec = 120025;
    wdb_state.queries_breakdown.task_queries = 45;
    wdb_state.queries_breakdown.task_breakdown.sql_queries = 1;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_queries = 20;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_custom_queries = 2;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_get_status_queries = 10;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_update_status_queries = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_result_queries = 2;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_queries = 4;
    wdb_state.queries_breakdown.task_breakdown.tasks.set_timeout_queries = 3;
    wdb_state.queries_breakdown.task_breakdown.tasks.delete_old_queries = 2;
    wdb_state.queries_breakdown.task_breakdown.sql_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.sql_time.tv_usec = 56300;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_time.tv_usec = 10230;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_custom_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_custom_time.tv_usec = 52120;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_get_status_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_get_status_time.tv_usec = 156322;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_update_status_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_update_status_time.tv_usec = 123548;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_result_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_result_time.tv_usec = 12356;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time.tv_usec = 10256;
    wdb_state.queries_breakdown.task_breakdown.tasks.set_timeout_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.set_timeout_time.tv_usec = 23002;
    wdb_state.queries_breakdown.task_breakdown.tasks.delete_old_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.tasks.delete_old_time.tv_usec = 12000;

    return 0;
}

static int test_teardown(void ** state) {
    cJSON* json = *state;
    cJSON_Delete(json);
    return 0;
}

/* Tests */

void test_wazuhdb_create_state_json(void ** state) {

    cJSON* state_json = wdb_create_state_json();

    *state = (void *)state_json;

    assert_non_null(state_json);

    assert_int_equal(cJSON_GetObjectItem(state_json, "uptime")->valueint, 123456789);

    assert_non_null(cJSON_GetObjectItem(state_json, "metrics"));
    cJSON* metrics = cJSON_GetObjectItem(state_json, "metrics");

    assert_non_null(cJSON_GetObjectItem(metrics, "queries"));
    cJSON* queries = cJSON_GetObjectItem(metrics, "queries");

    assert_non_null(cJSON_GetObjectItem(queries, "received"));
    assert_int_equal(cJSON_GetObjectItem(queries, "received")->valueint, 856);

    cJSON* received_breakdown = cJSON_GetObjectItem(queries, "received_breakdown");

    assert_non_null(cJSON_GetObjectItem(received_breakdown, "global"));
    assert_int_equal(cJSON_GetObjectItem(received_breakdown, "global")->valueint, 227);

    cJSON* global_queries_breakdown = cJSON_GetObjectItem(received_breakdown, "global_breakdown");

    cJSON* global_queries_db = cJSON_GetObjectItem(global_queries_breakdown, "db");
    assert_non_null(cJSON_GetObjectItem(global_queries_db, "sql"));
    assert_int_equal(cJSON_GetObjectItem(global_queries_db, "sql")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(global_queries_db, "backup"));
    assert_int_equal(cJSON_GetObjectItem(global_queries_db, "backup")->valueint, 6);
    assert_non_null(cJSON_GetObjectItem(global_queries_db, "vacuum"));
    assert_int_equal(cJSON_GetObjectItem(global_queries_db, "vacuum")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(global_queries_db, "get_fragmentation"));
    assert_int_equal(cJSON_GetObjectItem(global_queries_db, "get_fragmentation")->valueint, 5);

    cJSON* global_queries_tables = cJSON_GetObjectItem(global_queries_breakdown, "tables");

    cJSON* global_agent_queries_breakdown = cJSON_GetObjectItem(global_queries_tables, "agent");
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "insert-agent"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "insert-agent")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-data"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-data")->valueint, 16);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-name"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-name")->valueint, 30);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-keepalive"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-keepalive")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-connection-status"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-connection-status")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "reset-agents-connection"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "reset-agents-connection")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "delete-agent"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "delete-agent")->valueint, 20);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-name"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-name")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-group"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-group")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "find-agent"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "find-agent")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agent-info"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agent-info")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-all-agents"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-all-agents")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agents-by-connection-status"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agents-by-connection-status")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "disconnect-agents"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "disconnect-agents")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-get"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-get")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-set"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-set")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-groups-get"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-groups-get")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "set-agent-groups"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "set-agent-groups")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-groups-integrity"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-groups-integrity")->valueint, 2);

    cJSON* global_group_queries_breakdown = cJSON_GetObjectItem(global_queries_tables, "group");
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "insert-agent-group"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "insert-agent-group")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "delete-group"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "delete-group")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "select-groups"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "select-groups")->valueint, 84);
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "find-group"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "find-group")->valueint, 10);

    cJSON* global_belongs_queries_breakdown = cJSON_GetObjectItem(global_queries_tables, "belongs");
    assert_non_null(cJSON_GetObjectItem(global_belongs_queries_breakdown, "select-group-belong"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_queries_breakdown, "select-group-belong")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_belongs_queries_breakdown, "get-group-agents"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_queries_breakdown, "get-group-agents")->valueint, 0);

    cJSON* global_labels_queries_breakdown = cJSON_GetObjectItem(global_queries_tables, "labels");
    assert_non_null(cJSON_GetObjectItem(global_labels_queries_breakdown, "get-labels"));
    assert_int_equal(cJSON_GetObjectItem(global_labels_queries_breakdown, "get-labels")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(received_breakdown, "task"));
    assert_int_equal(cJSON_GetObjectItem(received_breakdown, "task")->valueint, 45);

    cJSON* task_queries_breakdown = cJSON_GetObjectItem(received_breakdown, "task_breakdown");

    cJSON* task_queries_db = cJSON_GetObjectItem(task_queries_breakdown, "db");
    assert_non_null(cJSON_GetObjectItem(task_queries_db, "sql"));
    assert_int_equal(cJSON_GetObjectItem(task_queries_db, "sql")->valueint, 1);

    cJSON* task_queries_tables = cJSON_GetObjectItem(task_queries_breakdown, "tables");

    cJSON* task_tasks_queries_breakdown = cJSON_GetObjectItem(task_queries_tables, "tasks");
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade")->valueint, 20);
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_custom"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_custom")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_get_status"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_get_status")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_update_status"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_update_status")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_result"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_result")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_cancel_tasks"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "upgrade_cancel_tasks")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "set_timeout"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "set_timeout")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(task_tasks_queries_breakdown, "delete_old"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_queries_breakdown, "delete_old")->valueint, 2);

    assert_non_null(cJSON_GetObjectItem(metrics, "time"));
    cJSON* time = cJSON_GetObjectItem(metrics, "time");

    assert_non_null(cJSON_GetObjectItem(time, "execution"));
    assert_int_equal(cJSON_GetObjectItem(time, "execution")->valueint, 7547);

    cJSON* execution_breakdown = cJSON_GetObjectItem(time, "execution_breakdown");

    assert_non_null(cJSON_GetObjectItem(execution_breakdown, "global"));
    assert_int_equal(cJSON_GetObjectItem(execution_breakdown, "global")->valueint, 7091);

    cJSON* global_time_breakdown = cJSON_GetObjectItem(execution_breakdown, "global_breakdown");

    cJSON* global_time_db = cJSON_GetObjectItem(global_time_breakdown, "db");
    assert_non_null(cJSON_GetObjectItem(global_time_db, "open"));
    assert_int_equal(cJSON_GetObjectItem(global_time_db, "open")->valueint, 123);
    assert_non_null(cJSON_GetObjectItem(global_time_db, "sql"));
    assert_int_equal(cJSON_GetObjectItem(global_time_db, "sql")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_time_db, "backup"));
    assert_int_equal(cJSON_GetObjectItem(global_time_db, "backup")->valueint, 1145);
    assert_non_null(cJSON_GetObjectItem(global_time_db, "vacuum"));
    assert_int_equal(cJSON_GetObjectItem(global_time_db, "vacuum")->valueint, 11);
    assert_non_null(cJSON_GetObjectItem(global_time_db, "get_fragmentation"));
    assert_int_equal(cJSON_GetObjectItem(global_time_db, "get_fragmentation")->valueint, 22);

    cJSON* global_time_tables = cJSON_GetObjectItem(global_time_breakdown, "tables");

    cJSON* global_agent_time_breakdown = cJSON_GetObjectItem(global_time_tables, "agent");
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "insert-agent"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "insert-agent")->valueint, 580);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-data"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-data")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-name"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-name")->valueint, 2125);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-keepalive"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-keepalive")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-connection-status"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-connection-status")->valueint, 148);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "reset-agents-connection"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "reset-agents-connection")->valueint, 100);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "delete-agent"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "delete-agent")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-name"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-name")->valueint, 14);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-group"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-group")->valueint, 152);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "find-agent"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "find-agent")->valueint, 78);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agent-info"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agent-info")->valueint, 152);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-all-agents"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-all-agents")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agents-by-connection-status"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agents-by-connection-status")->valueint, 1002);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "disconnect-agents"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "disconnect-agents")->valueint, 412);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-get"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-get")->valueint, 548);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-set"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-set")->valueint, 81);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-groups-get"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-groups-get")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "set-agent-groups"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "set-agent-groups")->valueint, 61);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-groups-integrity"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-groups-integrity")->valueint, 1);

    cJSON* global_group_time_breakdown = cJSON_GetObjectItem(global_time_tables, "group");
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "insert-agent-group"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "insert-agent-group")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "delete-group"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "delete-group")->valueint, 92);
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "select-groups"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "select-groups")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "find-group"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "find-group")->valueint, 0);

    cJSON* global_belongs_time_breakdown = cJSON_GetObjectItem(global_time_tables, "belongs");
    assert_non_null(cJSON_GetObjectItem(global_belongs_time_breakdown, "select-group-belong"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_time_breakdown, "select-group-belong")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(global_belongs_time_breakdown, "get-group-agents"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_time_breakdown, "get-group-agents")->valueint, 12);

    cJSON* global_labels_time_breakdown = cJSON_GetObjectItem(global_time_tables, "labels");
    assert_non_null(cJSON_GetObjectItem(global_labels_time_breakdown, "get-labels"));
    assert_int_equal(cJSON_GetObjectItem(global_labels_time_breakdown, "get-labels")->valueint, 120);

    assert_non_null(cJSON_GetObjectItem(execution_breakdown, "task"));
    assert_int_equal(cJSON_GetObjectItem(execution_breakdown, "task")->valueint, 456);

    cJSON* task_time_breakdown = cJSON_GetObjectItem(execution_breakdown, "task_breakdown");

    cJSON* task_time_db = cJSON_GetObjectItem(task_time_breakdown, "db");
    assert_non_null(cJSON_GetObjectItem(task_time_db, "sql"));
    assert_int_equal(cJSON_GetObjectItem(task_time_db, "sql")->valueint, 56);

    cJSON* task_time_tables = cJSON_GetObjectItem(task_time_breakdown, "tables");

    cJSON* task_tasks_time_breakdown = cJSON_GetObjectItem(task_time_tables, "tasks");
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_custom"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_custom")->valueint, 52);
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_get_status"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_get_status")->valueint, 156);
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_update_status"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_update_status")->valueint, 123);
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_result"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_result")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_cancel_tasks"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "upgrade_cancel_tasks")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "set_timeout"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "set_timeout")->valueint, 23);
    assert_non_null(cJSON_GetObjectItem(task_tasks_time_breakdown, "delete_old"));
    assert_int_equal(cJSON_GetObjectItem(task_tasks_time_breakdown, "delete_old")->valueint, 12);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test wdb_create_state_json
        cmocka_unit_test_setup_teardown(test_wazuhdb_create_state_json, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
