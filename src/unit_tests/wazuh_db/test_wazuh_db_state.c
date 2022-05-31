/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cmocka.h>

#include "wazuh_db/wdb_state.h"

extern wdb_state_t wdb_state;

/* setup/teardown */

static int test_setup(void ** state) {
    wdb_state.queries_total = 856;
    wdb_state.queries_breakdown.wazuhdb_queries = 212;
    wdb_state.queries_breakdown.wazuhdb_breakdown.get_config_queries = 210;
    wdb_state.queries_breakdown.wazuhdb_breakdown.remove_queries = 2;
    wdb_state.queries_breakdown.wazuhdb_breakdown.unknown_queries = 0;
    wdb_state.queries_breakdown.wazuhdb_breakdown.get_config_time.tv_sec = 0;
    wdb_state.queries_breakdown.wazuhdb_breakdown.get_config_time.tv_usec = 232321;
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
    wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_time.tv_sec = 641231;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time.tv_sec = 35121;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time.tv_sec = 0;
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time.tv_sec = 221548;
    wdb_state.queries_breakdown.agent_breakdown.rootcheck_time.tv_sec = 1;
    wdb_state.queries_breakdown.agent_breakdown.rootcheck_time.tv_sec = 146684;
    wdb_state.queries_breakdown.agent_breakdown.sca_time.tv_sec = 2;
    wdb_state.queries_breakdown.agent_breakdown.sca_time.tv_sec = 351940;
    wdb_state.queries_breakdown.agent_breakdown.ciscat_time.tv_sec = 1;
    wdb_state.queries_breakdown.agent_breakdown.ciscat_time.tv_sec = 896460;
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
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time.tv_usec = 5489060;
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

    assert_non_null(cJSON_GetObjectItem(statistics, "queries_time_total"));
    // assert_int_equal(cJSON_GetObjectItem(statistics, "queries_time_total")->valueint, ---------------------------);

    cJSON* queries_breakdown = cJSON_GetObjectItem(statistics, "queries_breakdown");
    assert_non_null(cJSON_GetObjectItem(queries_breakdown, "wazuhdb_queries"));
    assert_int_equal(cJSON_GetObjectItem(queries_breakdown, "wazuhdb_queries")->valueint, 212);

    cJSON* wazuhdb_breakdown = cJSON_GetObjectItem(queries_breakdown, "wazuhdb_breakdown");
    assert_non_null(cJSON_GetObjectItem(wazuhdb_breakdown, "get_config_queries"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_breakdown, "get_config_queries")->valueint, 210);
    assert_non_null(cJSON_GetObjectItem(wazuhdb_breakdown, "remove_queries"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_breakdown, "remove_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(wazuhdb_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_breakdown, "unknown_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(wazuhdb_breakdown, "get_config_time"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_breakdown, "get_config_time")->valueint, 232);
    assert_non_null(cJSON_GetObjectItem(wazuhdb_breakdown, "remove_time"));
    assert_int_equal(cJSON_GetObjectItem(wazuhdb_breakdown, "remove_time")->valueint, 132);

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

    cJSON* agent_syscheck = cJSON_GetObjectItem(agent_queries_breakdown, "syscheck_queries");
    assert_non_null(cJSON_GetObjectItem(agent_syscheck, "syscheck_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck, "syscheck_queries")->valueint, 70);
    assert_non_null(cJSON_GetObjectItem(agent_syscheck, "fim_file_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck, "fim_file_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_syscheck, "fim_registry_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscheck, "fim_registry_queries")->valueint, 36);

    cJSON* agent_rootcheck = cJSON_GetObjectItem(agent_queries_breakdown, "rootcheck_queries");
    assert_non_null(cJSON_GetObjectItem(agent_rootcheck, "rootcheck_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_rootcheck, "rootcheck_queries")->valueint, 8);

    cJSON* agent_sca = cJSON_GetObjectItem(agent_queries_breakdown, "sca_queries");
    assert_non_null(cJSON_GetObjectItem(agent_sca, "sca_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_sca, "sca_queries")->valueint, 2);

    cJSON* agent_ciscat = cJSON_GetObjectItem(agent_queries_breakdown, "ciscat_queries");
    assert_non_null(cJSON_GetObjectItem(agent_ciscat, "ciscat_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_ciscat, "ciscat_queries")->valueint, 75);

    cJSON* agent_syscollector = cJSON_GetObjectItem(agent_queries_breakdown, "syscollector_queries");
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_processes_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_processes_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_packages_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_packages_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_hotfixes_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_hotfixes_queries")->valueint, 9);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_ports_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_ports_queries")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_network_protocol_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_network_protocol_queries")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_network_address_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_network_address_queries")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_network_iface_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_network_iface_queries")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_hwinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_hwinfo_queries")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "syscollector_osinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "syscollector_osinfo_queries")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "process_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "process_queries")->valueint, 9);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "package_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "package_queries")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "hotfix_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "hotfix_queries")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "port_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "port_queries")->valueint, 16);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "netproto_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "netproto_queries")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "netaddr_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "netaddr_queries")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "netinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "netinfo_queries")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "hardware_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "hardware_queries")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(agent_syscollector, "osinfo_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_syscollector, "osinfo_queries")->valueint, 1);

    cJSON* agent_vuln_detector = cJSON_GetObjectItem(agent_queries_breakdown, "vulnerability_detector_queries");
    assert_non_null(cJSON_GetObjectItem(agent_vuln_detector, "vuln_cves_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_vuln_detector, "vuln_cves_queries")->valueint, 8);

    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "dbsync_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "dbsync_queries")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(agent_queries_breakdown, "unknown_queries"));
    assert_int_equal(cJSON_GetObjectItem(agent_queries_breakdown, "unknown_queries")->valueint, 1);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test wdb_create_state_json
        cmocka_unit_test_setup_teardown(test_wazuhdb_create_state_json, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}