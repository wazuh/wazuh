/* wazuhdb state management functions
 * May 27, 2022
 *
 * Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wdb_state.h"
#include <pthread.h>

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

#define timeval_to_milis(time) ((time.tv_sec * (uint64_t)1000) + (time.tv_usec / 1000))

STATIC uint64_t get_wazuhdb_time(wdb_state_t state);

STATIC uint64_t get_agent_time(wdb_state_t state);

STATIC uint64_t get_global_time(wdb_state_t state);

STATIC uint64_t get_task_time(wdb_state_t state);

STATIC uint64_t get_time_total(wdb_state_t state);

pthread_mutex_t db_state_t_mutex = PTHREAD_MUTEX_INITIALIZER;
wdb_state_t wdb_state = {0};

void w_inc_queries_total() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_total++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_wazuhdb() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.wazuhdb_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_wazuhdb_get_config() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.wazuhdb_breakdown.get_config_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_wazuhdb_remove() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.wazuhdb_breakdown.remove_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_wazuhdb_unknown() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.wazuhdb_breakdown.unknown_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sql() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.sql_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_remove() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.remove_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_begin() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.begin_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_commit() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.commit_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_close() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.close_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_rootcheck() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.rootcheck_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sca() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.sca_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_ciscat() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.ciscat_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_vul_detector() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.vulnerability_detector_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_dbsync() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.dbsync_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_unknown() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.unknown_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscheck() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_file() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_processes() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_packages() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_hotfixes() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_ports() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_network_protocol() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_network_address() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_network_iface() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_hwinfo() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_osinfo() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_process() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.process_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_packages() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.package_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hotfixes() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hotfix_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_ports() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.port_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_protocol() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netproto_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_address() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netaddr_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_info() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.netinfo_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hardware() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.hardware_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_osinfo() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.osinfo_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_sql() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.sql_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_backup() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.backup_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_unknown() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.unknown_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_insert_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_data() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_name() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_keepalive() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_connection_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_reset_agents_connection() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_set() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_delete_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_name() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_find_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.find_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agent_info() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_all_agents() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agents_by_connection_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_disconnect_agents() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_get() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_groups_get() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_set_agent_groups() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_groups_integrity() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_insert_agent_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_delete_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.delete_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_select_groups() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.select_groups_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_find_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.find_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_select_group_belong() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_get_group_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_labels_get_labels() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_sql() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.sql_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_set_timeout() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.set_timeout_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_delete_old() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.delete_old_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_unknown() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.unknown_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_custom() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_custom_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_get_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_update_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_result() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_result_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_cancel_tasks() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_mitre() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.mitre_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_mitre_sql() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.mitre_breakdown.sql_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_mitre_unknown() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.mitre_breakdown.unknown_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_unknown() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.unknown_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscheck_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_file_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_times(struct timeval time, wdb_component_t type) {

    w_mutex_lock(&db_state_t_mutex);

    switch (type) {
    case WDB_SYSCOLLECTOR_PROCESSES:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time);
        break;
    case WDB_SYSCOLLECTOR_PACKAGES:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time);
        break;
    case WDB_SYSCOLLECTOR_HOTFIXES:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time);
        break;
    case WDB_SYSCOLLECTOR_PORTS:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time);
        break;
    case WDB_SYSCOLLECTOR_NETPROTO:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time);
        break;
    case WDB_SYSCOLLECTOR_NETADDRESS:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time);
        break;
    case WDB_SYSCOLLECTOR_NETINFO:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time);
        break;
    case WDB_SYSCOLLECTOR_HWINFO:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time);
        break;
    case WDB_SYSCOLLECTOR_OSINFO:
        timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time);
        break;
    default:
        break;
    }

    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_process_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.process_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.process_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hotfixes_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.hotfix_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.hotfix_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_packages_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.package_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.package_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_ports_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.port_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.port_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hardware_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.hardware_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.hardware_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_osinfo_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.osinfo_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.osinfo_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_address_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.netaddr_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.netaddr_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_protocol_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.netproto_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.netproto_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_info_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.netinfo_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.netinfo_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.sql_time, &time, &wdb_state.queries_breakdown.agent_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_remove_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.remove_time, &time, &wdb_state.queries_breakdown.agent_breakdown.remove_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_begin_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.begin_time, &time, &wdb_state.queries_breakdown.agent_breakdown.begin_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_commit_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.commit_time, &time, &wdb_state.queries_breakdown.agent_breakdown.commit_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_close_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.close_time, &time, &wdb_state.queries_breakdown.agent_breakdown.close_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_rootcheck_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.rootcheck_time, &time, &wdb_state.queries_breakdown.agent_breakdown.rootcheck_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_ciscat_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.ciscat_time, &time, &wdb_state.queries_breakdown.agent_breakdown.ciscat_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_dbsync_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.dbsync_time, &time, &wdb_state.queries_breakdown.agent_breakdown.dbsync_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sca_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.sca_time, &time, &wdb_state.queries_breakdown.agent_breakdown.sca_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_vul_detector_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.vulnerability_detector_time, &time, &wdb_state.queries_breakdown.agent_breakdown.vulnerability_detector_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_mitre_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.mitre_breakdown.sql_time, &time, &wdb_state.queries_breakdown.mitre_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_insert_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_data_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_name_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_keepalive_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_connection_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_reset_agents_connection_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_set_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_delete_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_name_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_find_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.find_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.find_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agent_info_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_all_agents_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agents_by_connection_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_disconnect_agents_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_get_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_groups_get_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_set_agent_groups_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_groups_integrity_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_insert_agent_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_delete_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.delete_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.delete_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_select_groups_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.select_groups_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.select_groups_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_find_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.find_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.find_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_select_group_belong_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time, &time, &wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_get_group_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_labels_get_labels_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time, &time, &wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_time, &time, &wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_custom_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time, &time, &wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_get_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time, &time, &wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_update_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time, &time, &wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_result_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_result_time, &time, &wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_result_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_cancel_tasks_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time, &time, &wdb_state.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.sql_time, &time, &wdb_state.queries_breakdown.task_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_set_timeout_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.set_timeout_time, &time, &wdb_state.queries_breakdown.task_breakdown.set_timeout_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_delete_old_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.delete_old_time, &time, &wdb_state.queries_breakdown.task_breakdown.delete_old_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.sql_time, &time, &wdb_state.queries_breakdown.global_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_backup_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.backup_time, &time, &wdb_state.queries_breakdown.global_breakdown.backup_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_wazuhdb_get_config_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.wazuhdb_breakdown.get_config_time, &time, &wdb_state.queries_breakdown.wazuhdb_breakdown.get_config_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_wazuhdb_remove_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.wazuhdb_breakdown.remove_time, &time, &wdb_state.queries_breakdown.wazuhdb_breakdown.remove_time);
    w_mutex_unlock(&db_state_t_mutex);
}

cJSON* wdb_create_state_json() {
    wdb_state_t wdb_state_cpy;
    cJSON *_statistics = NULL;
    cJSON *_queries_breakdown = NULL;
    cJSON *_wazuhdb_queries_breakdown = NULL;
    cJSON *_wazuhdb_time_breakdown = NULL;
    cJSON *_agent_queries_breakdown = NULL;
    cJSON *_syscheck_queries = NULL;
    cJSON *_rootcheck_queries = NULL;
    cJSON *_sca_queries = NULL;
    cJSON *_ciscat_queries = NULL;
    cJSON *_syscollector_queries = NULL;
    cJSON *_vulnerability_detector_queries = NULL;
    cJSON *_agent_time_breakdown = NULL;
    cJSON *_syscheck_time = NULL;
    cJSON *_rootcheck_time = NULL;
    cJSON *_sca_time = NULL;
    cJSON *_ciscat_time = NULL;
    cJSON *_syscollector_time = NULL;
    cJSON *_vulnerability_detector_time = NULL;
    cJSON *_global_queries_breakdown = NULL;
    cJSON *_global_agent_queries_breakdown = NULL;
    cJSON *_global_group_queries_breakdown = NULL;
    cJSON *_global_belongs_queries_breakdown = NULL;
    cJSON *_global_labels_queries_breakdown = NULL;
    cJSON *_global_time_breakdown = NULL;
    cJSON *_global_agent_time_breakdown = NULL;
    cJSON *_global_group_time_breakdown = NULL;
    cJSON *_global_belongs_time_breakdown = NULL;
    cJSON *_global_labels_time_breakdown = NULL;
    cJSON *_task_queries_breakdown = NULL;
    cJSON *_task_upgrade_queries_breakdown = NULL;
    cJSON *_task_time_breakdown = NULL;
    cJSON *_task_upgrade_time_breakdown = NULL;
    cJSON *_mitre_queries_breakdown = NULL;
    cJSON *_mitre_time_breakdown = NULL;

    w_mutex_lock(&db_state_t_mutex);
    memcpy(&wdb_state_cpy, &wdb_state, sizeof(wdb_state_t));
    w_mutex_unlock(&db_state_t_mutex);

    cJSON *wdb_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(wdb_state_json, "version", VERSION);
    cJSON_AddNumberToObject(wdb_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(wdb_state_json, "daemon_name", ARGV0);

    _statistics = cJSON_CreateObject();
    cJSON_AddItemToObject(wdb_state_json, "statistics", _statistics);

    cJSON_AddNumberToObject(_statistics, "queries_total", wdb_state_cpy.queries_total);

    cJSON_AddNumberToObject(_statistics, "queries_time_total", get_time_total(wdb_state_cpy));

    _queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "queries_breakdown", _queries_breakdown);

    cJSON_AddNumberToObject(_queries_breakdown, "wazuhdb_queries", wdb_state_cpy.queries_breakdown.wazuhdb_queries);

    _wazuhdb_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "wazuhdb_queries_breakdown", _wazuhdb_queries_breakdown);

    cJSON_AddNumberToObject(_wazuhdb_queries_breakdown, "getconfig_queries", wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.get_config_queries);
    cJSON_AddNumberToObject(_wazuhdb_queries_breakdown, "remove_queries", wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.remove_queries);
    cJSON_AddNumberToObject(_wazuhdb_queries_breakdown, "unknown_queries", wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.unknown_queries);

    cJSON_AddNumberToObject(_queries_breakdown, "wazuhdb_time", get_wazuhdb_time(wdb_state_cpy));

    _wazuhdb_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "wazuhdb_time_breakdown", _wazuhdb_time_breakdown);

    cJSON_AddNumberToObject(_wazuhdb_time_breakdown, "getconfig_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.get_config_time));
    cJSON_AddNumberToObject(_wazuhdb_time_breakdown, "remove_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.remove_time));

    cJSON_AddNumberToObject(_queries_breakdown, "agent_queries", wdb_state_cpy.queries_breakdown.agent_queries);

    _agent_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "agent_queries_breakdown", _agent_queries_breakdown);

    cJSON_AddNumberToObject(_agent_queries_breakdown, "sql_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.sql_queries);
    cJSON_AddNumberToObject(_agent_queries_breakdown, "remove_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.remove_queries);
    cJSON_AddNumberToObject(_agent_queries_breakdown, "begin_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.begin_queries);
    cJSON_AddNumberToObject(_agent_queries_breakdown, "commit_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.commit_queries);
    cJSON_AddNumberToObject(_agent_queries_breakdown, "close_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.close_queries);

    _syscheck_queries = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_queries_breakdown, "syscheck_queries", _syscheck_queries);

    cJSON_AddNumberToObject(_syscheck_queries, "syscheck_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.syscheck_queries);
    cJSON_AddNumberToObject(_syscheck_queries, "fim_file_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_file_queries);
    cJSON_AddNumberToObject(_syscheck_queries, "fim_registry_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_queries);

    _rootcheck_queries = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_queries_breakdown, "rootcheck_queries", _rootcheck_queries);

    cJSON_AddNumberToObject(_rootcheck_queries, "rootcheck_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.rootcheck_queries);

    _sca_queries = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_queries_breakdown, "sca_queries", _sca_queries);

    cJSON_AddNumberToObject(_sca_queries, "sca_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.sca_queries);

    _ciscat_queries = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_queries_breakdown, "ciscat_queries", _ciscat_queries);

    cJSON_AddNumberToObject(_ciscat_queries, "ciscat_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.ciscat_queries);

    _syscollector_queries = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_queries_breakdown, "syscollector_queries", _syscollector_queries);

    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_processes_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_packages_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_hotfixes_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_ports_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_network_protocol_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_network_address_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_network_iface_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_hwinfo_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "syscollector_osinfo_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "process_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.process_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "package_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.package_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "hotfix_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.hotfix_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "port_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.port_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "netproto_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.netproto_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "netaddr_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.netaddr_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "netinfo_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.netinfo_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "hardware_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.hardware_queries);
    cJSON_AddNumberToObject(_syscollector_queries, "osinfo_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.osinfo_queries);

    _vulnerability_detector_queries = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_queries_breakdown, "vulnerability_detector_queries", _vulnerability_detector_queries);

    cJSON_AddNumberToObject(_vulnerability_detector_queries, "vuln_cves_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.vulnerability_detector_queries);

    cJSON_AddNumberToObject(_agent_queries_breakdown, "dbsync_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.dbsync_queries);
    cJSON_AddNumberToObject(_agent_queries_breakdown, "unknown_queries", wdb_state_cpy.queries_breakdown.agent_breakdown.unknown_queries);

    cJSON_AddNumberToObject(_queries_breakdown, "agent_time", get_agent_time(wdb_state_cpy));

    _agent_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "agent_time_breakdown", _agent_time_breakdown);

    cJSON_AddNumberToObject(_agent_time_breakdown, "sql_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.sql_time));
    cJSON_AddNumberToObject(_agent_time_breakdown, "remove_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.remove_time));
    cJSON_AddNumberToObject(_agent_time_breakdown, "begin_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.begin_time));
    cJSON_AddNumberToObject(_agent_time_breakdown, "commit_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.commit_time));
    cJSON_AddNumberToObject(_agent_time_breakdown, "close_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.close_time));

    _syscheck_time = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_time_breakdown, "syscheck_time", _syscheck_time);

    cJSON_AddNumberToObject(_syscheck_time, "syscheck_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.syscheck_time));
    cJSON_AddNumberToObject(_syscheck_time, "fim_file_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_file_time));
    cJSON_AddNumberToObject(_syscheck_time, "fim_registry_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_time));

    _rootcheck_time = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_time_breakdown, "rootcheck_time", _rootcheck_time);

    cJSON_AddNumberToObject(_rootcheck_time, "rootcheck_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.rootcheck_time));

    _sca_time = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_time_breakdown, "sca_time", _sca_time);

    cJSON_AddNumberToObject(_sca_time, "sca_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.sca_time));

    _ciscat_time = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_time_breakdown, "ciscat_time", _ciscat_time);

    cJSON_AddNumberToObject(_ciscat_time, "ciscat_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.ciscat_time));

    _syscollector_time = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_time_breakdown, "syscollector_time", _syscollector_time);

    cJSON_AddNumberToObject(_syscollector_time, "syscollector_processes_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_packages_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_hotfixes_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_ports_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_network_protocol_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_network_address_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_network_iface_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_hwinfo_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time));
    cJSON_AddNumberToObject(_syscollector_time, "syscollector_osinfo_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time));
    cJSON_AddNumberToObject(_syscollector_time, "process_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.process_time));
    cJSON_AddNumberToObject(_syscollector_time, "package_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.package_time));
    cJSON_AddNumberToObject(_syscollector_time, "hotfix_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.hotfix_time));
    cJSON_AddNumberToObject(_syscollector_time, "port_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.port_time));
    cJSON_AddNumberToObject(_syscollector_time, "netproto_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.netproto_time));
    cJSON_AddNumberToObject(_syscollector_time, "netaddr_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.netaddr_time));
    cJSON_AddNumberToObject(_syscollector_time, "netinfo_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.netinfo_time));
    cJSON_AddNumberToObject(_syscollector_time, "hardware_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.hardware_time));
    cJSON_AddNumberToObject(_syscollector_time, "osinfo_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.osinfo_time));

    _vulnerability_detector_time = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_time_breakdown, "vulnerability_detector_time", _vulnerability_detector_time);

    cJSON_AddNumberToObject(_vulnerability_detector_time, "vuln_cves_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.vulnerability_detector_time));

    cJSON_AddNumberToObject(_agent_time_breakdown, "dbsync_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.dbsync_time));

    cJSON_AddNumberToObject(_queries_breakdown, "global_queries", wdb_state_cpy.queries_breakdown.global_queries);

    _global_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "global_queries_breakdown", _global_queries_breakdown);

    cJSON_AddNumberToObject(_global_queries_breakdown, "sql_queries", wdb_state_cpy.queries_breakdown.global_breakdown.sql_queries);
    cJSON_AddNumberToObject(_global_queries_breakdown, "backup_queries", wdb_state_cpy.queries_breakdown.global_breakdown.backup_queries);

    _global_agent_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_queries_breakdown, "agent_queries", _global_agent_queries_breakdown);

    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "insert-agent_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.insert_agent_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "update-agent-data_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_data_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "update-agent-name_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_name_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "update-keepalive_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_keepalive_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "update-connection-status_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_connection_status_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "reset-agents-connection_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.reset_agents_connection_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "delete-agent_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.delete_agent_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "select-agent-name_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_name_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "select-agent-group_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_group_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "find-agent_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.find_agent_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "get-agent-info_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agent_info_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "get-all-agents_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_all_agents_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "get-agents-by-connection-status_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "disconnect-agents_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.disconnect_agents_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "sync-agent-info-get_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "sync-agent-info-set_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "sync-agent-groups-get_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "set-agent-groups_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.set_agent_groups_queries);
    cJSON_AddNumberToObject(_global_agent_queries_breakdown, "get-groups-integrity_queries", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_groups_integrity_queries);

    _global_group_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_queries_breakdown, "group_queries", _global_group_queries_breakdown);

    cJSON_AddNumberToObject(_global_group_queries_breakdown, "insert-agent-group_queries", wdb_state_cpy.queries_breakdown.global_breakdown.group.insert_agent_group_queries);
    cJSON_AddNumberToObject(_global_group_queries_breakdown, "delete-group_queries", wdb_state_cpy.queries_breakdown.global_breakdown.group.delete_group_queries);
    cJSON_AddNumberToObject(_global_group_queries_breakdown, "select-groups_queries", wdb_state_cpy.queries_breakdown.global_breakdown.group.select_groups_queries);
    cJSON_AddNumberToObject(_global_group_queries_breakdown, "find-group_queries", wdb_state_cpy.queries_breakdown.global_breakdown.group.find_group_queries);

    _global_belongs_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_queries_breakdown, "belongs_queries", _global_belongs_queries_breakdown);

    cJSON_AddNumberToObject(_global_belongs_queries_breakdown, "select-group-belong_queries", wdb_state_cpy.queries_breakdown.global_breakdown.belongs.select_group_belong_queries);
    cJSON_AddNumberToObject(_global_belongs_queries_breakdown, "get-group-agents_queries", wdb_state_cpy.queries_breakdown.global_breakdown.belongs.get_group_agent_queries);

    _global_labels_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_queries_breakdown, "labels_queries", _global_labels_queries_breakdown);

    cJSON_AddNumberToObject(_global_labels_queries_breakdown, "get-labels_queries", wdb_state_cpy.queries_breakdown.global_breakdown.labels.get_labels_queries);

    cJSON_AddNumberToObject(_global_queries_breakdown, "unknown_queries", wdb_state_cpy.queries_breakdown.global_breakdown.unknown_queries);

    cJSON_AddNumberToObject(_queries_breakdown, "global_time", get_global_time(wdb_state_cpy));

    _global_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "global_time_breakdown", _global_time_breakdown);

    cJSON_AddNumberToObject(_global_time_breakdown, "sql_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.sql_time));
    cJSON_AddNumberToObject(_global_time_breakdown, "backup_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.backup_time));

    _global_agent_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_time_breakdown, "agent_time", _global_agent_time_breakdown);

    cJSON_AddNumberToObject(_global_agent_time_breakdown, "insert-agent_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.insert_agent_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "update-agent-data_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_data_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "update-agent-name_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_name_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "update-keepalive_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_keepalive_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "update-connection-status_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_connection_status_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "reset-agents-connection_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.reset_agents_connection_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "delete-agent_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.delete_agent_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "select-agent-name_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_name_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "select-agent-group_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_group_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "find-agent_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.find_agent_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "get-agent-info_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agent_info_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "get-all-agents_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_all_agents_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "get-agents-by-connection-status_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "disconnect-agents_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.disconnect_agents_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "sync-agent-info-get_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "sync-agent-info-set_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "sync-agent-groups-get_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "set-agent-groups_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.set_agent_groups_time));
    cJSON_AddNumberToObject(_global_agent_time_breakdown, "get-groups-integrity_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_groups_integrity_time));

    _global_group_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_time_breakdown, "group_time", _global_group_time_breakdown);

    cJSON_AddNumberToObject(_global_group_time_breakdown, "insert-agent-group_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.insert_agent_group_time));
    cJSON_AddNumberToObject(_global_group_time_breakdown, "delete-group_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.delete_group_time));
    cJSON_AddNumberToObject(_global_group_time_breakdown, "select-groups_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.select_groups_time));
    cJSON_AddNumberToObject(_global_group_time_breakdown, "find-group_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.find_group_time));

    _global_belongs_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_time_breakdown, "belongs_time", _global_belongs_time_breakdown);

    cJSON_AddNumberToObject(_global_belongs_time_breakdown, "select-group-belong_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.belongs.select_group_belong_time));
    cJSON_AddNumberToObject(_global_belongs_time_breakdown, "get-group-agents_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.belongs.get_group_agent_time));

    _global_labels_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_time_breakdown, "labels_time", _global_labels_time_breakdown);

    cJSON_AddNumberToObject(_global_labels_time_breakdown, "get-labels_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.labels.get_labels_time));

    cJSON_AddNumberToObject(_queries_breakdown, "task_queries", wdb_state_cpy.queries_breakdown.task_queries);

    _task_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "task_queries_breakdown", _task_queries_breakdown);

    cJSON_AddNumberToObject(_task_queries_breakdown, "sql_queries", wdb_state_cpy.queries_breakdown.task_breakdown.sql_queries);

    _task_upgrade_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_queries_breakdown, "upgrade_queries", _task_upgrade_queries_breakdown);

    cJSON_AddNumberToObject(_task_upgrade_queries_breakdown, "upgrade_queries", wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_queries);
    cJSON_AddNumberToObject(_task_upgrade_queries_breakdown, "upgrade_custom_queries", wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_custom_queries);
    cJSON_AddNumberToObject(_task_upgrade_queries_breakdown, "upgrade_get_status_queries", wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_queries);
    cJSON_AddNumberToObject(_task_upgrade_queries_breakdown, "upgrade_update_status_queries", wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_queries);
    cJSON_AddNumberToObject(_task_upgrade_queries_breakdown, "upgrade_result_queries", wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_result_queries);
    cJSON_AddNumberToObject(_task_upgrade_queries_breakdown, "upgrade_cancel_tasks_queries", wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_queries);

    cJSON_AddNumberToObject(_task_queries_breakdown, "set_timeout_queries", wdb_state_cpy.queries_breakdown.task_breakdown.set_timeout_queries);
    cJSON_AddNumberToObject(_task_queries_breakdown, "delete_old_queries", wdb_state_cpy.queries_breakdown.task_breakdown.delete_old_queries);
    cJSON_AddNumberToObject(_task_queries_breakdown, "unknown_queries", wdb_state_cpy.queries_breakdown.task_breakdown.unknown_queries);

    cJSON_AddNumberToObject(_queries_breakdown, "task_time", get_task_time(wdb_state_cpy));

    _task_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "task_time_breakdown", _task_time_breakdown);

    cJSON_AddNumberToObject(_task_time_breakdown, "sql_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.sql_time));

    _task_upgrade_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_time_breakdown, "upgrade_time", _task_upgrade_time_breakdown);

    cJSON_AddNumberToObject(_task_upgrade_time_breakdown, "upgrade_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_time));
    cJSON_AddNumberToObject(_task_upgrade_time_breakdown, "upgrade_custom_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time));
    cJSON_AddNumberToObject(_task_upgrade_time_breakdown, "upgrade_get_status_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time));
    cJSON_AddNumberToObject(_task_upgrade_time_breakdown, "upgrade_update_status_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time));
    cJSON_AddNumberToObject(_task_upgrade_time_breakdown, "upgrade_result_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_result_time));
    cJSON_AddNumberToObject(_task_upgrade_time_breakdown, "upgrade_cancel_tasks_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time));

    cJSON_AddNumberToObject(_task_time_breakdown, "set_timeout_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.set_timeout_time));
    cJSON_AddNumberToObject(_task_time_breakdown, "delete_old_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.delete_old_time));

    cJSON_AddNumberToObject(_queries_breakdown, "mitre_queries", wdb_state_cpy.queries_breakdown.mitre_queries);

    _mitre_queries_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "mitre_queries_breakdown", _mitre_queries_breakdown);

    cJSON_AddNumberToObject(_mitre_queries_breakdown, "sql_queries", wdb_state_cpy.queries_breakdown.mitre_breakdown.sql_queries);
    cJSON_AddNumberToObject(_mitre_queries_breakdown, "unknown_queries", wdb_state_cpy.queries_breakdown.mitre_breakdown.unknown_queries);

    cJSON_AddNumberToObject(_queries_breakdown, "mitre_time",timeval_to_milis(wdb_state_cpy.queries_breakdown.mitre_breakdown.sql_time));

    _mitre_time_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries_breakdown, "mitre_time_breakdown", _mitre_time_breakdown);

    cJSON_AddNumberToObject(_mitre_time_breakdown, "sql_time", timeval_to_milis(wdb_state_cpy.queries_breakdown.mitre_breakdown.sql_time));

    cJSON_AddNumberToObject(_queries_breakdown, "unknown_queries", wdb_state_cpy.queries_breakdown.unknown_queries);

    return wdb_state_json;
}

STATIC uint64_t get_wazuhdb_time(wdb_state_t state){
    struct timeval task_time;

    timeradd(&state.queries_breakdown.wazuhdb_breakdown.get_config_time, &state.queries_breakdown.wazuhdb_breakdown.remove_time, &task_time);

    return timeval_to_milis(task_time);
}

STATIC uint64_t get_agent_time(wdb_state_t state){
    struct timeval task_time;

    timeradd(&state.queries_breakdown.agent_breakdown.sql_time, &state.queries_breakdown.agent_breakdown.remove_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.begin_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.commit_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.close_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscheck.syscheck_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscheck.fim_file_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.rootcheck_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.sca_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.ciscat_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.process_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.package_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.hotfix_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.port_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.netproto_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.netaddr_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.netinfo_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.hardware_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.syscollector.osinfo_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.vulnerability_detector_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.agent_breakdown.dbsync_time, &task_time);

    return timeval_to_milis(task_time);
}

STATIC uint64_t get_global_time(wdb_state_t state){
    struct timeval task_time;

    timeradd(&state.queries_breakdown.global_breakdown.sql_time, &state.queries_breakdown.global_breakdown.backup_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.insert_agent_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.update_agent_data_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.update_agent_name_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.update_keepalive_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.update_connection_status_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.reset_agents_connection_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.delete_agent_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.select_agent_name_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.select_agent_group_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.find_agent_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.get_agent_info_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.get_all_agents_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.disconnect_agents_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.set_agent_groups_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.agent.get_groups_integrity_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.group.insert_agent_group_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.group.delete_group_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.group.select_groups_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.group.find_group_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.belongs.select_group_belong_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.belongs.get_group_agent_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.global_breakdown.labels.get_labels_time, &task_time);

    return timeval_to_milis(task_time);
}

STATIC uint64_t get_task_time(wdb_state_t state){
    struct timeval task_time;

    timeradd(&state.queries_breakdown.task_breakdown.sql_time, &state.queries_breakdown.task_breakdown.upgrade.upgrade_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.task_breakdown.upgrade.upgrade_result_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.task_breakdown.set_timeout_time, &task_time);
    timeradd(&task_time, &state.queries_breakdown.task_breakdown.delete_old_time, &task_time);

    return timeval_to_milis(task_time);
}

STATIC uint64_t get_time_total(wdb_state_t state){
    return get_task_time(state) + get_global_time(state) + get_agent_time(state) + get_wazuhdb_time(state) + timeval_to_milis(state.queries_breakdown.mitre_breakdown.sql_time);
}
