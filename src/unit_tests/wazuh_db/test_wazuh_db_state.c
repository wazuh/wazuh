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

#include "wazuh_db/wdb_state.h"

extern wdb_state_t wdb_state;

/* setup/teardown */

static int test_setup(void ** state) {
    wdb_state.queries_total = 856;
    wdb_state.queries_breakdown.wazuhdb_queries = 212;
    wdb_state.queries_breakdown.wazuhdb_breakdown.remove_queries = 212;
    wdb_state.queries_breakdown.wazuhdb_breakdown.unknown_queries = 0;
    wdb_state.queries_breakdown.wazuhdb_breakdown.remove_time.tv_sec = 0;
    wdb_state.queries_breakdown.wazuhdb_breakdown.remove_time.tv_usec = 132156;
    wdb_state.queries_breakdown.agent_queries = 365;
    wdb_state.queries_breakdown.agent_breakdown.sql_queries = 70;
    wdb_state.queries_breakdown.agent_breakdown.remove_queries = 2;
    wdb_state.queries_breakdown.agent_breakdown.begin_queries = 36;
    wdb_state.queries_breakdown.agent_breakdown.commit_queries = 2;
    wdb_state.queries_breakdown.agent_breakdown.close_queries = 36;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_queries = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_queries = 6;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_queries = 10;
    wdb_state.queries_breakdown.agent_breakdown.rootcheck_queries = 8;
    wdb_state.queries_breakdown.agent_breakdown.sca_queries = 2;
    wdb_state.queries_breakdown.agent_breakdown.ciscat_queries = 75;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries = 2;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries = 2;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries = 9;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries = 1;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries = 4;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries = 3;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries = 5;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries = 10;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.process_queries = 9;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.package_queries = 2;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hotfix_queries = 10;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.port_queries = 16;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netproto_queries = 4;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netaddr_queries = 5;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netinfo_queries = 12;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hardware_queries = 8;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.osinfo_queries = 1;
    wdb_state.queries_breakdown.agent_breakdown.vulnerability_detector_queries = 8;
    wdb_state.queries_breakdown.agent_breakdown.dbsync_queries = 5;
    wdb_state.queries_breakdown.agent_breakdown.unknown_queries = 1;
    wdb_state.queries_breakdown.agent_breakdown.sql_time.tv_sec = 1;
    wdb_state.queries_breakdown.agent_breakdown.sql_time.tv_usec = 546332;
    wdb_state.queries_breakdown.agent_breakdown.remove_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.remove_time.tv_usec = 351518;
    wdb_state.queries_breakdown.agent_breakdown.begin_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.begin_time.tv_usec = 313548;
    wdb_state.queries_breakdown.agent_breakdown.commit_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.commit_time.tv_usec = 122313;
    wdb_state.queries_breakdown.agent_breakdown.close_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.close_time.tv_usec = 156312;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_time.tv_usec = 641231;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time.tv_usec = 35121;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time.tv_usec = 221548;
    wdb_state.queries_breakdown.agent_breakdown.rootcheck_time.tv_sec = 1;
    wdb_state.queries_breakdown.agent_breakdown.rootcheck_time.tv_usec = 146684;
    wdb_state.queries_breakdown.agent_breakdown.sca_time.tv_sec = 2;
    wdb_state.queries_breakdown.agent_breakdown.sca_time.tv_usec = 351940;
    wdb_state.queries_breakdown.agent_breakdown.ciscat_time.tv_sec = 1;
    wdb_state.queries_breakdown.agent_breakdown.ciscat_time.tv_usec = 896460;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time.tv_usec = 356110;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time.tv_usec = 321850;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time.tv_sec = 1;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time.tv_usec = 513218;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time.tv_usec= 894321;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time.tv_usec= 123218;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time.tv_usec = 984318;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time.tv_usec = 781354;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time.tv_usec = 843633;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time.tv_usec= 123548;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.process_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.process_time.tv_usec = 145158;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.package_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.package_time.tv_usec = 231548;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hotfix_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hotfix_time.tv_usec = 512180;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.port_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.port_time.tv_usec = 716460;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netproto_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netproto_time.tv_usec = 123950;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netaddr_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netaddr_time.tv_usec = 515120;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netinfo_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netinfo_time.tv_usec = 651230;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hardware_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hardware_time.tv_usec = 156120;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.osinfo_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscollector.osinfo_time.tv_usec = 153215;
    wdb_state.queries_breakdown.agent_breakdown.vulnerability_detector_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.vulnerability_detector_time.tv_usec = 15321;
    wdb_state.queries_breakdown.agent_breakdown.dbsync_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.dbsync_time.tv_usec = 2315;
    wdb_state.queries_breakdown.global_queries = 227;
    wdb_state.queries_breakdown.global_breakdown.sql_queries = 8;
    wdb_state.queries_breakdown.global_breakdown.backup_queries = 6;
    wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_queries = 16;
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_queries = 30;
    wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_queries = 12;
    wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_queries = 20;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.agent.select_keepalive_queries = 2;
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
    wdb_state.queries_breakdown.global_breakdown.belongs.delete_agent_belong_queries = 8;
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_queries = 10;
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.labels.set_labels_queries = 2;
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_queries = 1;
    wdb_state.queries_breakdown.global_breakdown.unknown_queries = 0;
    wdb_state.queries_breakdown.global_breakdown.sql_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.sql_time.tv_usec = 1523;
    wdb_state.queries_breakdown.global_breakdown.backup_time.tv_sec = 1;
    wdb_state.queries_breakdown.global_breakdown.backup_time.tv_usec = 145452;
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
    wdb_state.queries_breakdown.global_breakdown.agent.select_keepalive_time.tv_sec = 1;
    wdb_state.queries_breakdown.global_breakdown.agent.select_keepalive_time.tv_usec = 125486;
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
    wdb_state.queries_breakdown.global_breakdown.belongs.delete_agent_belong_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.belongs.delete_agent_belong_time.tv_usec = 10250;
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time.tv_usec = 25600;
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time.tv_usec = 12500;
    wdb_state.queries_breakdown.global_breakdown.labels.set_labels_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.labels.set_labels_time.tv_usec = 10000;
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time.tv_sec = 0;
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time.tv_usec = 120025;
    wdb_state.queries_breakdown.task_queries = 45;
    wdb_state.queries_breakdown.task_breakdown.sql_queries = 1;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_queries = 20;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_custom_queries = 2;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_queries = 10;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_queries = 0;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_result_queries = 2;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_queries = 4;
    wdb_state.queries_breakdown.task_breakdown.set_timeout_queries = 3;
    wdb_state.queries_breakdown.task_breakdown.delete_old_queries = 2;
    wdb_state.queries_breakdown.task_breakdown.unknown_queries = 1;
    wdb_state.queries_breakdown.task_breakdown.sql_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.sql_time.tv_usec = 56300;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_time.tv_usec = 10230;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time.tv_usec = 52120;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time.tv_usec = 156322;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time.tv_usec = 123548;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_result_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_result_time.tv_usec = 12356;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time.tv_usec = 10256;
    wdb_state.queries_breakdown.task_breakdown.set_timeout_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.set_timeout_time.tv_usec = 23002;
    wdb_state.queries_breakdown.task_breakdown.delete_old_time.tv_sec = 0;
    wdb_state.queries_breakdown.task_breakdown.delete_old_time.tv_usec = 12000;
    wdb_state.queries_breakdown.mitre_queries = 2;
    wdb_state.queries_breakdown.mitre_breakdown.sql_queries = 2;
    wdb_state.queries_breakdown.mitre_breakdown.unknown_queries = 0;
    wdb_state.queries_breakdown.mitre_breakdown.sql_time.tv_sec = 0;
    wdb_state.queries_breakdown.mitre_breakdown.sql_time.tv_usec = 15202;
    wdb_state.queries_breakdown.unknown_queries = 5;

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

    assert_non_null(cJSON_GetObjectItem(state_json, "statistics"));
    cJSON* statistics = cJSON_GetObjectItem(state_json, "statistics");

    assert_non_null(cJSON_GetObjectItem(statistics, "queries_total"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "queries_total")->valueint, 856);

    cJSON* queries_breakdown = cJSON_GetObjectItem(statistics, "queries_breakdown");

    assert_non_null(cJSON_GetObjectItem(queries_breakdown, "wazuhdb_queries"));
    assert_int_equal(cJSON_GetObjectItem(queries_breakdown, "wazuhdb_queries")->valueint, 212);

    cJSON* wazuhdb_queries_breakdown = cJSON_GetObjectItem(queries_breakdown, "wazuhdb_queries_breakdown");
    assert_non_null(cJSON_GetObjectItem(wazuhdb_queries_breakdown, "remove_queries"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_queries_breakdown, "remove_queries")->valueint, 212);
    assert_non_null(cJSON_GetObjectItem(wazuhdb_queries_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_queries_breakdown, "unknown_queries")->valueint, 0);

    assert_non_null(cJSON_GetObjectItem(queries_breakdown, "agent_queries"));
    assert_int_equal(cJSON_GetObjectItem(queries_breakdown, "agent_queries")->valueint, 365);

    cJSON* agent_queries_breakdown = cJSON_GetObjectItem(queries_breakdown, "agent_queries_breakdown");
    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "sql_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "sql_queries")->valueint, 70);
    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "remove_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "remove_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "begin_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "begin_queries")->valueint, 36);
    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "commit_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "commit_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "close_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "close_queries")->valueint, 36);

    cJSON* agent_syscheck_queries = cJSON_GetObjectItem(agent_queries_breakdown, "syscheck_queries");
    assert_non_null(cJSON_GetObjectItem(agent_syscheck_queries, "syscheck_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck_queries, "syscheck_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(agent_syscheck_queries, "fim_file_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck_queries, "fim_file_queries")->valueint, 6);
    assert_non_null(cJSON_GetObjectItem(agent_syscheck_queries, "fim_registry_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck_queries, "fim_registry_queries")->valueint, 10);

    cJSON* agent_rootcheck_queries = cJSON_GetObjectItem(agent_queries_breakdown, "rootcheck_queries");
    assert_non_null(cJSON_GetObjectItem(agent_rootcheck_queries, "rootcheck_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_rootcheck_queries, "rootcheck_queries")->valueint, 8);

    cJSON* agent_sca_queries = cJSON_GetObjectItem(agent_queries_breakdown, "sca_queries");
    assert_non_null(cJSON_GetObjectItem(agent_sca_queries, "sca_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_sca_queries, "sca_queries")->valueint, 2);

    cJSON* agent_ciscat_queries = cJSON_GetObjectItem(agent_queries_breakdown, "ciscat_queries");
    assert_non_null(cJSON_GetObjectItem(agent_ciscat_queries, "ciscat_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_ciscat_queries, "ciscat_queries")->valueint, 75);

    cJSON* agent_syscollector_queries = cJSON_GetObjectItem(agent_queries_breakdown, "syscollector_queries");
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_processes_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_processes_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_packages_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_packages_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_hotfixes_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_hotfixes_queries")->valueint, 9);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_ports_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_ports_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_network_protocol_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_network_protocol_queries")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_network_address_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_network_address_queries")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_network_iface_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_network_iface_queries")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_hwinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_hwinfo_queries")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_osinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "syscollector_osinfo_queries")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "process_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "process_queries")->valueint, 9);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "package_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "package_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "hotfix_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "hotfix_queries")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "port_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "port_queries")->valueint, 16);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "netproto_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "netproto_queries")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "netaddr_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "netaddr_queries")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "netinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "netinfo_queries")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "hardware_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "hardware_queries")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_queries, "osinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_queries, "osinfo_queries")->valueint, 1);

    cJSON* agent_vuln_detector_queries = cJSON_GetObjectItem(agent_queries_breakdown, "vulnerability_detector_queries");
    assert_non_null(cJSON_GetObjectItem(agent_vuln_detector_queries, "vuln_cves_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_vuln_detector_queries, "vuln_cves_queries")->valueint, 8);

    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "dbsync_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "dbsync_queries")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "unknown_queries")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(queries_breakdown, "global_queries"));
    assert_int_equal(cJSON_GetObjectItem(queries_breakdown, "global_queries")->valueint, 227);

    cJSON* global_queries_breakdown = cJSON_GetObjectItem(queries_breakdown, "global_queries_breakdown");
    assert_non_null(cJSON_GetObjectItem(global_queries_breakdown, "sql_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_queries_breakdown, "sql_queries")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(global_queries_breakdown, "backup_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_queries_breakdown, "backup_queries")->valueint, 6);

    cJSON* global_agent_queries_breakdown = cJSON_GetObjectItem(global_queries_breakdown, "agent_queries");
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "insert-agent_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "insert-agent_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-data_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-data_queries")->valueint, 16);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-name_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-agent-name_queries")->valueint, 30);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-keepalive_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-keepalive_queries")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-connection-status_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "update-connection-status_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "reset-agents-connection_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "reset-agents-connection_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "delete-agent_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "delete-agent_queries")->valueint, 20);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-name_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-name_queries")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-group_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-agent-group_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-keepalive_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "select-keepalive_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "find-agent_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "find-agent_queries")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agent-info_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agent-info_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-all-agents_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-all-agents_queries")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agents-by-connection-status_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-agents-by-connection-status_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "disconnect-agents_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "disconnect-agents_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-get_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-get_queries")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-set_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-info-set_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-groups-get_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "sync-agent-groups-get_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "set-agent-groups_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "set-agent-groups_queries")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-groups-integrity_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_queries_breakdown, "get-groups-integrity_queries")->valueint, 2);

    cJSON* global_group_queries_breakdown = cJSON_GetObjectItem(global_queries_breakdown, "group_queries");
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "insert-agent-group_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "insert-agent-group_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "delete-group_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "delete-group_queries")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "select-groups_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "select-groups_queries")->valueint, 84);
    assert_non_null(cJSON_GetObjectItem(global_group_queries_breakdown, "find-group_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_group_queries_breakdown, "find-group_queries")->valueint, 10);

    cJSON* global_belongs_queries_breakdown = cJSON_GetObjectItem(global_queries_breakdown, "belongs_queries");
    assert_non_null(cJSON_GetObjectItem(global_belongs_queries_breakdown, "delete-agent-belong_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_queries_breakdown, "delete-agent-belong_queries")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(global_belongs_queries_breakdown, "select-group-belong_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_queries_breakdown, "select-group-belong_queries")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_belongs_queries_breakdown, "get-group-agents_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_queries_breakdown, "get-group-agents_queries")->valueint, 0);

    cJSON* global_labels_queries_breakdown = cJSON_GetObjectItem(global_queries_breakdown, "labels_queries");
    assert_non_null(cJSON_GetObjectItem(global_labels_queries_breakdown, "set-labels_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_labels_queries_breakdown, "set-labels_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(global_labels_queries_breakdown, "get-labels_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_labels_queries_breakdown, "get-labels_queries")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(global_queries_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(global_queries_breakdown, "unknown_queries")->valueint, 0);

    assert_non_null(cJSON_GetObjectItem(queries_breakdown, "task_queries"));
    assert_int_equal(cJSON_GetObjectItem(queries_breakdown, "task_queries")->valueint, 45);

    cJSON* task_queries_breakdown = cJSON_GetObjectItem(queries_breakdown, "task_queries_breakdown");
    assert_non_null(cJSON_GetObjectItem(task_queries_breakdown, "sql_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_queries_breakdown, "sql_queries")->valueint, 1);

    cJSON* task_upgrade_queries_breakdown = cJSON_GetObjectItem(task_queries_breakdown, "upgrade_queries");
    assert_non_null(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_queries")->valueint, 20);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_custom_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_custom_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_get_status_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_get_status_queries")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_update_status_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_update_status_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_result_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_result_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_cancel_tasks_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_queries_breakdown, "upgrade_cancel_tasks_queries")->valueint, 4);

    assert_non_null(cJSON_GetObjectItem(task_queries_breakdown, "set_timeout_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_queries_breakdown, "set_timeout_queries")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(task_queries_breakdown, "delete_old_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_queries_breakdown, "delete_old_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(task_queries_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(task_queries_breakdown, "unknown_queries")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(queries_breakdown, "mitre_queries"));
    assert_int_equal(cJSON_GetObjectItem(queries_breakdown, "mitre_queries")->valueint, 2);

    cJSON* mitre_queries_breakdown = cJSON_GetObjectItem(queries_breakdown, "mitre_queries_breakdown");
    assert_non_null(cJSON_GetObjectItem(mitre_queries_breakdown, "sql_queries"));
    assert_int_equal(cJSON_GetObjectItem(mitre_queries_breakdown, "sql_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(mitre_queries_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(mitre_queries_breakdown, "unknown_queries")->valueint, 0);

    assert_non_null(cJSON_GetObjectItem(queries_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(queries_breakdown, "unknown_queries")->valueint, 5);

    assert_non_null(cJSON_GetObjectItem(statistics, "queries_time_total"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "queries_time_total")->valueint, 26630);

    cJSON* queries_time_breakdown = cJSON_GetObjectItem(statistics, "queries_time_breakdown");

    assert_non_null(cJSON_GetObjectItem(queries_time_breakdown, "wazuhdb_time"));
    assert_int_equal(cJSON_GetObjectItem(queries_time_breakdown, "wazuhdb_time")->valueint, 132);

    cJSON* wazuhdb_time_breakdown = cJSON_GetObjectItem(queries_time_breakdown, "wazuhdb_time_breakdown");
    assert_non_null(cJSON_GetObjectItem(wazuhdb_time_breakdown, "remove_time"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_time_breakdown, "remove_time")->valueint, 132);

    assert_non_null(cJSON_GetObjectItem(queries_time_breakdown, "agent_time"));
    assert_int_equal(cJSON_GetObjectItem(queries_time_breakdown, "agent_time")->valueint, 17947);

    cJSON* agent_time_breakdown = cJSON_GetObjectItem(queries_time_breakdown, "agent_time_breakdown");
    assert_non_null(cJSON_GetObjectItem(agent_time_breakdown, "sql_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_time_breakdown, "sql_time")->valueint, 1546);
    assert_non_null(cJSON_GetObjectItem(agent_time_breakdown, "remove_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_time_breakdown, "remove_time")->valueint, 351);
    assert_non_null(cJSON_GetObjectItem(agent_time_breakdown, "begin_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_time_breakdown, "begin_time")->valueint, 313);
    assert_non_null(cJSON_GetObjectItem(agent_time_breakdown, "commit_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_time_breakdown, "commit_time")->valueint, 122);
    assert_non_null(cJSON_GetObjectItem(agent_time_breakdown, "close_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_time_breakdown, "close_time")->valueint, 156);

    cJSON* agent_syscheck_time = cJSON_GetObjectItem(agent_time_breakdown, "syscheck_time");
    assert_non_null(cJSON_GetObjectItem(agent_syscheck_time, "syscheck_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck_time, "syscheck_time")->valueint, 641);
    assert_non_null(cJSON_GetObjectItem(agent_syscheck_time, "fim_file_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck_time, "fim_file_time")->valueint, 35);
    assert_non_null(cJSON_GetObjectItem(agent_syscheck_time, "fim_registry_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck_time, "fim_registry_time")->valueint, 221);

    cJSON* agent_rootcheck_time = cJSON_GetObjectItem(agent_time_breakdown, "rootcheck_time");
    assert_non_null(cJSON_GetObjectItem(agent_rootcheck_time, "rootcheck_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_rootcheck_time, "rootcheck_time")->valueint, 1146);

    cJSON* agent_sca_time = cJSON_GetObjectItem(agent_time_breakdown, "sca_time");
    assert_non_null(cJSON_GetObjectItem(agent_sca_time, "sca_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_sca_time, "sca_time")->valueint, 2351);

    cJSON* agent_ciscat_time = cJSON_GetObjectItem(agent_time_breakdown, "ciscat_time");
    assert_non_null(cJSON_GetObjectItem(agent_ciscat_time, "ciscat_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_ciscat_time, "ciscat_time")->valueint, 1896);

    cJSON* agent_syscollector_time = cJSON_GetObjectItem(agent_time_breakdown, "syscollector_time");
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_processes_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_processes_time")->valueint, 356);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_packages_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_packages_time")->valueint, 321);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_hotfixes_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_hotfixes_time")->valueint, 1513);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_ports_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_ports_time")->valueint, 894);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_network_protocol_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_network_protocol_time")->valueint, 123);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_network_address_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_network_address_time")->valueint, 984);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_network_iface_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_network_iface_time")->valueint, 781);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_hwinfo_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_hwinfo_time")->valueint, 843);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_osinfo_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "syscollector_osinfo_time")->valueint, 123);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "process_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "process_time")->valueint, 145);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "package_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "package_time")->valueint, 231);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "hotfix_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "hotfix_time")->valueint, 512);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "port_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "port_time")->valueint, 716);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "netproto_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "netproto_time")->valueint, 123);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "netaddr_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "netaddr_time")->valueint, 515);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "netinfo_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "netinfo_time")->valueint, 651);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "hardware_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "hardware_time")->valueint, 156);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector_time, "osinfo_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector_time, "osinfo_time")->valueint, 153);

    cJSON* agent_vuln_detector_time = cJSON_GetObjectItem(agent_time_breakdown, "vulnerability_detector_time");
    assert_non_null(cJSON_GetObjectItem(agent_vuln_detector_time, "vuln_cves_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_vuln_detector_time, "vuln_cves_time")->valueint, 15);

    assert_non_null(cJSON_GetObjectItem(agent_time_breakdown, "dbsync_time"));
    assert_int_equal(cJSON_GetObjectItem(agent_time_breakdown, "dbsync_time")->valueint, 2);

    assert_non_null(cJSON_GetObjectItem(queries_time_breakdown, "global_time"));
    assert_int_equal(cJSON_GetObjectItem(queries_time_breakdown, "global_time")->valueint, 8080);

    cJSON* global_time_breakdown = cJSON_GetObjectItem(queries_time_breakdown, "global_time_breakdown");
    assert_non_null(cJSON_GetObjectItem(global_time_breakdown, "sql_time"));
    assert_int_equal(cJSON_GetObjectItem(global_time_breakdown, "sql_time")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_time_breakdown, "backup_time"));
    assert_int_equal(cJSON_GetObjectItem(global_time_breakdown, "backup_time")->valueint, 1145);

    cJSON* global_agent_time_breakdown = cJSON_GetObjectItem(global_time_breakdown, "agent_time");
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "insert-agent_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "insert-agent_time")->valueint, 580);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-data_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-data_time")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-name_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-agent-name_time")->valueint, 2125);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-keepalive_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-keepalive_time")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "update-connection-status_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "update-connection-status_time")->valueint, 148);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "reset-agents-connection_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "reset-agents-connection_time")->valueint, 100);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "delete-agent_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "delete-agent_time")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-name_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-name_time")->valueint, 14);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-group_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "select-agent-group_time")->valueint, 152);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "select-keepalive_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "select-keepalive_time")->valueint, 1125);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "find-agent_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "find-agent_time")->valueint, 78);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agent-info_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agent-info_time")->valueint, 152);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-all-agents_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-all-agents_time")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agents-by-connection-status_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-agents-by-connection-status_time")->valueint, 1002);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "disconnect-agents_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "disconnect-agents_time")->valueint, 412);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-get_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-get_time")->valueint, 548);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-set_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-info-set_time")->valueint, 81);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-groups-get_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "sync-agent-groups-get_time")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "set-agent-groups_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "set-agent-groups_time")->valueint, 61);
    assert_non_null(cJSON_GetObjectItem(global_agent_time_breakdown, "get-groups-integrity_time"));
    assert_int_equal(cJSON_GetObjectItem(global_agent_time_breakdown, "get-groups-integrity_time")->valueint, 1);

    cJSON* global_group_time_breakdown = cJSON_GetObjectItem(global_time_breakdown, "group_time");
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "insert-agent-group_time"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "insert-agent-group_time")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "delete-group_time"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "delete-group_time")->valueint, 92);
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "select-groups_time"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "select-groups_time")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_group_time_breakdown, "find-group_time"));
    assert_int_equal(cJSON_GetObjectItem(global_group_time_breakdown, "find-group_time")->valueint, 0);

    cJSON* global_belongs_time_breakdown = cJSON_GetObjectItem(global_time_breakdown, "belongs_time");
    assert_non_null(cJSON_GetObjectItem(global_belongs_time_breakdown, "delete-agent-belong_time"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_time_breakdown, "delete-agent-belong_time")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_belongs_time_breakdown, "select-group-belong_time"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_time_breakdown, "select-group-belong_time")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(global_belongs_time_breakdown, "get-group-agents_time"));
    assert_int_equal(cJSON_GetObjectItem(global_belongs_time_breakdown, "get-group-agents_time")->valueint, 12);

    cJSON* global_labels_time_breakdown = cJSON_GetObjectItem(global_time_breakdown, "labels_time");
    assert_non_null(cJSON_GetObjectItem(global_labels_time_breakdown, "set-labels_time"));
    assert_int_equal(cJSON_GetObjectItem(global_labels_time_breakdown, "set-labels_time")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(global_labels_time_breakdown, "get-labels_time"));
    assert_int_equal(cJSON_GetObjectItem(global_labels_time_breakdown, "get-labels_time")->valueint, 120);

    assert_non_null(cJSON_GetObjectItem(queries_time_breakdown, "task_time"));
    assert_int_equal(cJSON_GetObjectItem(queries_time_breakdown, "task_time")->valueint, 456);

    cJSON* task_time_breakdown = cJSON_GetObjectItem(queries_time_breakdown, "task_time_breakdown");
    assert_non_null(cJSON_GetObjectItem(task_time_breakdown, "sql_time"));
    assert_int_equal(cJSON_GetObjectItem(task_time_breakdown, "sql_time")->valueint, 56);

    cJSON* task_upgrade_time_breakdown = cJSON_GetObjectItem(task_time_breakdown, "upgrade_time");
    assert_non_null(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_time"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_time")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_custom_time"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_custom_time")->valueint, 52);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_get_status_time"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_get_status_time")->valueint, 156);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_update_status_time"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_update_status_time")->valueint, 123);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_result_time"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_result_time")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_cancel_tasks_time"));
    assert_int_equal(cJSON_GetObjectItem(task_upgrade_time_breakdown, "upgrade_cancel_tasks_time")->valueint, 10);

    assert_non_null(cJSON_GetObjectItem(task_time_breakdown, "set_timeout_time"));
    assert_int_equal(cJSON_GetObjectItem(task_time_breakdown, "set_timeout_time")->valueint, 23);
    assert_non_null(cJSON_GetObjectItem(task_time_breakdown, "delete_old_time"));
    assert_int_equal(cJSON_GetObjectItem(task_time_breakdown, "delete_old_time")->valueint, 12);

    assert_non_null(cJSON_GetObjectItem(queries_time_breakdown, "mitre_time"));
    assert_int_equal(cJSON_GetObjectItem(queries_time_breakdown, "mitre_time")->valueint, 15);

    cJSON* mitre_time_breakdown = cJSON_GetObjectItem(queries_time_breakdown, "mitre_time_breakdown");
    assert_non_null(cJSON_GetObjectItem(mitre_time_breakdown, "sql_time"));
    assert_int_equal(cJSON_GetObjectItem(mitre_time_breakdown, "sql_time")->valueint, 15);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test wdb_create_state_json
        cmocka_unit_test_setup_teardown(test_wazuhdb_create_state_json, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
