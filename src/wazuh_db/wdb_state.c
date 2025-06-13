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

#ifndef ARGV0
#define ARGV0 "wazuh-db"
#endif

#define timeval_to_milis(time) ((time.tv_sec * (uint64_t)1000) + (time.tv_usec / 1000))

STATIC uint64_t get_agent_time(wdb_state_t *state);

STATIC uint64_t get_global_time(wdb_state_t *state);

STATIC uint64_t get_task_time(wdb_state_t *state);

STATIC uint64_t get_time_total(wdb_state_t *state);

wdb_state_t wdb_state = {0};
pthread_mutex_t db_state_t_mutex = PTHREAD_MUTEX_INITIALIZER;

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

void w_inc_wazuhdb_remove() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.wazuhdb_breakdown.remove_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_wazuhdb_remove_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.wazuhdb_breakdown.remove_time, &time, &wdb_state.queries_breakdown.wazuhdb_breakdown.remove_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_open_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.open_calls_time, &time, &wdb_state.queries_breakdown.agent_breakdown.open_calls_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sql() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.sql_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.sql_time, &time, &wdb_state.queries_breakdown.agent_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_remove() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.remove_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_remove_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.remove_time, &time, &wdb_state.queries_breakdown.agent_breakdown.remove_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_begin() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.begin_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_begin_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.begin_time, &time, &wdb_state.queries_breakdown.agent_breakdown.begin_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_commit() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.commit_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_commit_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.commit_time, &time, &wdb_state.queries_breakdown.agent_breakdown.commit_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_close() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.close_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_close_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.close_time, &time, &wdb_state.queries_breakdown.agent_breakdown.close_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_vacuum() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.vacuum_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_vacuum_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.vacuum_time, &time, &wdb_state.queries_breakdown.agent_breakdown.vacuum_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_get_fragmentation() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.get_fragmentation_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_get_fragmentation_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.get_fragmentation_time, &time, &wdb_state.queries_breakdown.agent_breakdown.get_fragmentation_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_rootcheck() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.rootcheck.rootcheck_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_rootcheck_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.rootcheck.rootcheck_time, &time, &wdb_state.queries_breakdown.agent_breakdown.rootcheck.rootcheck_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sca() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.sca.sca_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sca_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.sca.sca_time, &time, &wdb_state.queries_breakdown.agent_breakdown.sca.sca_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_ciscat() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.ciscat.ciscat_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_ciscat_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.ciscat.ciscat_time, &time, &wdb_state.queries_breakdown.agent_breakdown.ciscat.ciscat_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_dbsync() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.sync.dbsync_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_dbsync_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.sync.dbsync_time, &time, &wdb_state.queries_breakdown.agent_breakdown.sync.dbsync_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscheck() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscheck_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.syscheck_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_file() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_file_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_file_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry_key() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_key_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry_key_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_key_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_key_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry_value() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_value_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_fim_registry_value_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_value_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscheck.fim_registry_value_time);
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

void w_inc_agent_syscollector_users() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_users_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_groups() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.syscollector_groups_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_times(struct timeval time, int type) {

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

void w_inc_agent_syscollector_deprecated_process() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.process_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_process_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.process_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.process_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_packages() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.package_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_packages_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.package_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.package_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hotfixes() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hotfixes_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_ports() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.port_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_ports_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.port_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.port_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_protocol() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_protocol_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_address() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_address_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_info() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_info_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hardware() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hardware_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_osinfo() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_syscollector_deprecated_osinfo_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_time, &time, &wdb_state.queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sleep() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.agent_breakdown.sleep_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_agent_sleep_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.agent_breakdown.sleep_time, &time, &wdb_state.queries_breakdown.agent_breakdown.sleep_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_open_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.open_calls_time, &time, &wdb_state.queries_breakdown.global_breakdown.open_calls_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_sql() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.sql_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.sql_time, &time, &wdb_state.queries_breakdown.global_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_backup() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.backup_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_backup_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.backup_time, &time, &wdb_state.queries_breakdown.global_breakdown.backup_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_insert_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_insert_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.insert_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_data() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_data_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_agent_data_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_name() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_agent_name_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_agent_name_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_keepalive() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_keepalive_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_keepalive_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_connection_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_connection_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_connection_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_status_code() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.update_status_code_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_update_status_code_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.update_status_code_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.update_status_code_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_reset_agents_connection() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_reset_agents_connection_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.reset_agents_connection_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_delete_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_delete_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.delete_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_name() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_name_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.select_agent_name_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_select_agent_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.select_agent_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_find_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.find_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_find_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.find_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.find_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agent_info() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agent_info_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_agent_info_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_all_agents() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_all_agents_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_all_agents_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_distinct_groups() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_distinct_groups_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_distinct_groups_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_distinct_groups_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_distinct_groups_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agents_by_connection_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_agents_by_connection_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_disconnect_agents() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_disconnect_agents_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.disconnect_agents_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_get() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_get_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_set() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_info_set_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_groups_get() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_sync_agent_groups_get_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_set_agent_groups() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_set_agent_groups_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.set_agent_groups_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_groups_integrity() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_get_groups_integrity_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.get_groups_integrity_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_recalculate_agent_group_hashes() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_agent_recalculate_agent_group_hashes_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_time, &time, &wdb_state.queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_insert_agent_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_insert_agent_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.insert_agent_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_delete_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.delete_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_delete_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.delete_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.delete_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_select_groups() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.select_groups_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_select_groups_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.select_groups_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.select_groups_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_find_group() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.group.find_group_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_group_find_group_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.group.find_group_time, &time, &wdb_state.queries_breakdown.global_breakdown.group.find_group_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_select_group_belong() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_select_group_belong_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time, &time, &wdb_state.queries_breakdown.global_breakdown.belongs.select_group_belong_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_get_group_agent() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_belongs_get_group_agent_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time, &time, &wdb_state.queries_breakdown.global_breakdown.belongs.get_group_agent_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_labels_get_labels() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.labels.get_labels_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_labels_get_labels_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time, &time, &wdb_state.queries_breakdown.global_breakdown.labels.get_labels_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_vacuum() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.vacuum_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_vacuum_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.vacuum_time, &time, &wdb_state.queries_breakdown.global_breakdown.vacuum_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_get_fragmentation() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.get_fragmentation_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_get_fragmentation_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.get_fragmentation_time, &time, &wdb_state.queries_breakdown.global_breakdown.get_fragmentation_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_sleep() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.global_breakdown.sleep_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_global_sleep_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.global_breakdown.sleep_time, &time, &wdb_state.queries_breakdown.global_breakdown.sleep_time);
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

void w_inc_task_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.sql_time, &time, &wdb_state.queries_breakdown.task_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_set_timeout() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.set_timeout_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_set_timeout_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.set_timeout_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.set_timeout_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_delete_old() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.delete_old_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_delete_old_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.delete_old_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.delete_old_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_custom() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_custom_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_custom_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_custom_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_custom_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_get_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_get_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_get_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_get_status_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_get_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_update_status() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_update_status_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_update_status_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_update_status_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_update_status_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_result() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_result_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_result_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_result_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_result_time);
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_cancel_tasks() {
    w_mutex_lock(&db_state_t_mutex);
    wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_queries++;
    w_mutex_unlock(&db_state_t_mutex);
}

void w_inc_task_upgrade_cancel_tasks_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time, &time, &wdb_state.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time);
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

void w_inc_mitre_sql_time(struct timeval time) {
    w_mutex_lock(&db_state_t_mutex);
    timeradd(&wdb_state.queries_breakdown.mitre_breakdown.sql_time, &time, &wdb_state.queries_breakdown.mitre_breakdown.sql_time);
    w_mutex_unlock(&db_state_t_mutex);
}

cJSON* wdb_create_state_json() {
    wdb_state_t wdb_state_cpy;

    w_mutex_lock(&db_state_t_mutex);
    memcpy(&wdb_state_cpy, &wdb_state, sizeof(wdb_state_t));
    w_mutex_unlock(&db_state_t_mutex);

    cJSON *wdb_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(wdb_state_json, "uptime", wdb_state_cpy.uptime);
    cJSON_AddNumberToObject(wdb_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(wdb_state_json, "name", ARGV0);

    cJSON *_metrics = cJSON_CreateObject();
    cJSON_AddItemToObject(wdb_state_json, "metrics", _metrics);

    // Fields within metrics are sorted alphabetically

    cJSON *_queries = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "queries", _queries);

    cJSON_AddNumberToObject(_queries, "received", wdb_state_cpy.queries_total);

    cJSON *_received_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_queries, "received_breakdown", _received_breakdown);

    cJSON_AddNumberToObject(_received_breakdown, "agent", wdb_state_cpy.queries_breakdown.agent_queries);

    cJSON *_agent_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "agent_breakdown", _agent_breakdown);

    cJSON *_agent_db = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_breakdown, "db", _agent_db);

    cJSON_AddNumberToObject(_agent_db, "begin", wdb_state_cpy.queries_breakdown.agent_breakdown.begin_queries);
    cJSON_AddNumberToObject(_agent_db, "close", wdb_state_cpy.queries_breakdown.agent_breakdown.close_queries);
    cJSON_AddNumberToObject(_agent_db, "commit", wdb_state_cpy.queries_breakdown.agent_breakdown.commit_queries);
    cJSON_AddNumberToObject(_agent_db, "remove", wdb_state_cpy.queries_breakdown.agent_breakdown.remove_queries);
    cJSON_AddNumberToObject(_agent_db, "sql", wdb_state_cpy.queries_breakdown.agent_breakdown.sql_queries);
    cJSON_AddNumberToObject(_agent_db, "vacuum", wdb_state_cpy.queries_breakdown.agent_breakdown.vacuum_queries);
    cJSON_AddNumberToObject(_agent_db, "get_fragmentation", wdb_state_cpy.queries_breakdown.agent_breakdown.get_fragmentation_queries);
    cJSON_AddNumberToObject(_agent_db, "sleep", wdb_state_cpy.queries_breakdown.agent_breakdown.sleep_queries);

    cJSON *_agent_tables = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_breakdown, "tables", _agent_tables);

    cJSON *_agent_tables_ciscat = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables, "ciscat", _agent_tables_ciscat);

    cJSON_AddNumberToObject(_agent_tables_ciscat, "ciscat", wdb_state_cpy.queries_breakdown.agent_breakdown.ciscat.ciscat_queries);

    cJSON *_agent_tables_rootcheck = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables, "rootcheck", _agent_tables_rootcheck);

    cJSON_AddNumberToObject(_agent_tables_rootcheck, "rootcheck", wdb_state_cpy.queries_breakdown.agent_breakdown.rootcheck.rootcheck_queries);

    cJSON *_agent_tables_sca = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables, "sca", _agent_tables_sca);

    cJSON_AddNumberToObject(_agent_tables_sca, "sca", wdb_state_cpy.queries_breakdown.agent_breakdown.sca.sca_queries);

    cJSON *_agent_tables_sync = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables, "sync", _agent_tables_sync);

    cJSON_AddNumberToObject(_agent_tables_sync, "dbsync", wdb_state_cpy.queries_breakdown.agent_breakdown.sync.dbsync_queries);

    cJSON *_agent_tables_syscheck = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables, "syscheck", _agent_tables_syscheck);

    cJSON_AddNumberToObject(_agent_tables_syscheck, "fim_file", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_file_queries);
    cJSON_AddNumberToObject(_agent_tables_syscheck, "fim_registry", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_queries);
    cJSON_AddNumberToObject(_agent_tables_syscheck, "fim_registry_key", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_key_queries);
    cJSON_AddNumberToObject(_agent_tables_syscheck, "fim_registry_value", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_value_queries);
    cJSON_AddNumberToObject(_agent_tables_syscheck, "syscheck", wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.syscheck_queries);

    cJSON *_agent_tables_syscollector = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables, "syscollector", _agent_tables_syscollector);

    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_hotfixes", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_hwinfo", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_network_address", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_network_iface", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_network_protocol", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_osinfo", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_packages", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_ports", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector, "syscollector_processes", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries);

    cJSON *_agent_tables_syscollector_deprecated = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_syscollector, "deprecated", _agent_tables_syscollector_deprecated);

    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "hardware", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "hotfix", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "netaddr", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "netinfo", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "netproto", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "osinfo", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "package", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.package_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "port", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.port_queries);
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated, "process", wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.process_queries);

    cJSON_AddNumberToObject(_received_breakdown, "global", wdb_state_cpy.queries_breakdown.global_queries);

    cJSON *_global_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "global_breakdown", _global_breakdown);

    cJSON *_global_db = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_breakdown, "db", _global_db);

    cJSON_AddNumberToObject(_global_db, "backup", wdb_state_cpy.queries_breakdown.global_breakdown.backup_queries);
    cJSON_AddNumberToObject(_global_db, "sql", wdb_state_cpy.queries_breakdown.global_breakdown.sql_queries);
    cJSON_AddNumberToObject(_global_db, "vacuum", wdb_state_cpy.queries_breakdown.global_breakdown.vacuum_queries);
    cJSON_AddNumberToObject(_global_db, "get_fragmentation", wdb_state_cpy.queries_breakdown.global_breakdown.get_fragmentation_queries);
    cJSON_AddNumberToObject(_global_db, "sleep", wdb_state_cpy.queries_breakdown.global_breakdown.sleep_queries);

    cJSON *_global_tables = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_breakdown, "tables", _global_tables);

    cJSON *_global_tables_agent = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables, "agent", _global_tables_agent);

    cJSON_AddNumberToObject(_global_tables_agent, "delete-agent", wdb_state_cpy.queries_breakdown.global_breakdown.agent.delete_agent_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "disconnect-agents", wdb_state_cpy.queries_breakdown.global_breakdown.agent.disconnect_agents_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "find-agent", wdb_state_cpy.queries_breakdown.global_breakdown.agent.find_agent_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "get-agent-info", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agent_info_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "get-agents-by-connection-status", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "get-all-agents", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_all_agents_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "get-distinct-groups", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_distinct_groups_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "get-groups-integrity", wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_groups_integrity_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "recalculate-agent-group-hashes", wdb_state_cpy.queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "insert-agent", wdb_state_cpy.queries_breakdown.global_breakdown.agent.insert_agent_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "reset-agents-connection", wdb_state_cpy.queries_breakdown.global_breakdown.agent.reset_agents_connection_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "select-agent-group", wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_group_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "select-agent-name", wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_name_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "set-agent-groups", wdb_state_cpy.queries_breakdown.global_breakdown.agent.set_agent_groups_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "sync-agent-groups-get", wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "sync-agent-info-get", wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "sync-agent-info-set", wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "update-agent-data", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_data_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "update-agent-name", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_name_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "update-connection-status", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_connection_status_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "update-status-code", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_status_code_queries);
    cJSON_AddNumberToObject(_global_tables_agent, "update-keepalive", wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_keepalive_queries);

    cJSON *_global_tables_belongs = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables, "belongs", _global_tables_belongs);

    cJSON_AddNumberToObject(_global_tables_belongs, "get-group-agents", wdb_state_cpy.queries_breakdown.global_breakdown.belongs.get_group_agent_queries);
    cJSON_AddNumberToObject(_global_tables_belongs, "select-group-belong", wdb_state_cpy.queries_breakdown.global_breakdown.belongs.select_group_belong_queries);

    cJSON *_global_tables_group = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables, "group", _global_tables_group);

    cJSON_AddNumberToObject(_global_tables_group, "delete-group", wdb_state_cpy.queries_breakdown.global_breakdown.group.delete_group_queries);
    cJSON_AddNumberToObject(_global_tables_group, "find-group", wdb_state_cpy.queries_breakdown.global_breakdown.group.find_group_queries);
    cJSON_AddNumberToObject(_global_tables_group, "insert-agent-group", wdb_state_cpy.queries_breakdown.global_breakdown.group.insert_agent_group_queries);
    cJSON_AddNumberToObject(_global_tables_group, "select-groups", wdb_state_cpy.queries_breakdown.global_breakdown.group.select_groups_queries);

    cJSON *_global_tables_labels = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables, "labels", _global_tables_labels);

    cJSON_AddNumberToObject(_global_tables_labels, "get-labels", wdb_state_cpy.queries_breakdown.global_breakdown.labels.get_labels_queries);

    cJSON_AddNumberToObject(_received_breakdown, "mitre", wdb_state_cpy.queries_breakdown.mitre_queries);

    cJSON *_mitre_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "mitre_breakdown", _mitre_breakdown);

    cJSON *_mitre_db = cJSON_CreateObject();
    cJSON_AddItemToObject(_mitre_breakdown, "db", _mitre_db);

    cJSON_AddNumberToObject(_mitre_db, "sql", wdb_state_cpy.queries_breakdown.mitre_breakdown.sql_queries);

    cJSON_AddNumberToObject(_received_breakdown, "task", wdb_state_cpy.queries_breakdown.task_queries);

    cJSON *_task_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "task_breakdown", _task_breakdown);

    cJSON *_task_db = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_breakdown, "db", _task_db);

    cJSON_AddNumberToObject(_task_db, "sql", wdb_state_cpy.queries_breakdown.task_breakdown.sql_queries);

    cJSON *_task_tables = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_breakdown, "tables", _task_tables);

    cJSON *_task_tables_tasks = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_tables, "tasks", _task_tables_tasks);

    cJSON_AddNumberToObject(_task_tables_tasks, "delete_old", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.delete_old_queries);
    cJSON_AddNumberToObject(_task_tables_tasks, "set_timeout", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.set_timeout_queries);
    cJSON_AddNumberToObject(_task_tables_tasks, "upgrade", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_queries);
    cJSON_AddNumberToObject(_task_tables_tasks, "upgrade_cancel_tasks", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_queries);
    cJSON_AddNumberToObject(_task_tables_tasks, "upgrade_custom", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_custom_queries);
    cJSON_AddNumberToObject(_task_tables_tasks, "upgrade_get_status", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_get_status_queries);
    cJSON_AddNumberToObject(_task_tables_tasks, "upgrade_result", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_result_queries);
    cJSON_AddNumberToObject(_task_tables_tasks, "upgrade_update_status", wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_update_status_queries);

    cJSON_AddNumberToObject(_received_breakdown, "wazuhdb", wdb_state_cpy.queries_breakdown.wazuhdb_queries);

    cJSON *_wazuhdb_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "wazuhdb_breakdown", _wazuhdb_breakdown);

    cJSON *_wazuhdb_db = cJSON_CreateObject();
    cJSON_AddItemToObject(_wazuhdb_breakdown, "db", _wazuhdb_db);

    cJSON_AddNumberToObject(_wazuhdb_db, "remove", wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.remove_queries);

    cJSON *_time = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "time", _time);

    cJSON_AddNumberToObject(_time, "execution", get_time_total(&wdb_state_cpy));

    cJSON *_execution_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_time, "execution_breakdown", _execution_breakdown);

    cJSON_AddNumberToObject(_execution_breakdown, "agent", get_agent_time(&wdb_state_cpy));

    cJSON *_agent_breakdown_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_execution_breakdown, "agent_breakdown", _agent_breakdown_t);

    cJSON *_agent_db_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_breakdown_t, "db", _agent_db_t);

    cJSON_AddNumberToObject(_agent_db_t, "open", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.open_calls_time));
    cJSON_AddNumberToObject(_agent_db_t, "begin", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.begin_time));
    cJSON_AddNumberToObject(_agent_db_t, "close", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.close_time));
    cJSON_AddNumberToObject(_agent_db_t, "commit", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.commit_time));
    cJSON_AddNumberToObject(_agent_db_t, "remove", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.remove_time));
    cJSON_AddNumberToObject(_agent_db_t, "sql", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.sql_time));
    cJSON_AddNumberToObject(_agent_db_t, "vacuum", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.vacuum_time));
    cJSON_AddNumberToObject(_agent_db_t, "get_fragmentation", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.get_fragmentation_time));
    cJSON_AddNumberToObject(_agent_db_t, "sleep", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.sleep_time));

    cJSON *_agent_tables_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_breakdown_t, "tables", _agent_tables_t);

    cJSON *_agent_tables_ciscat_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_t, "ciscat", _agent_tables_ciscat_t);

    cJSON_AddNumberToObject(_agent_tables_ciscat_t, "ciscat", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.ciscat.ciscat_time));

    cJSON *_agent_tables_rootcheck_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_t, "rootcheck", _agent_tables_rootcheck_t);

    cJSON_AddNumberToObject(_agent_tables_rootcheck_t, "rootcheck", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.rootcheck.rootcheck_time));

    cJSON *_agent_tables_sca_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_t, "sca", _agent_tables_sca_t);

    cJSON_AddNumberToObject(_agent_tables_sca_t, "sca", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.sca.sca_time));

    cJSON *_agent_tables_sync_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_t, "sync", _agent_tables_sync_t);

    cJSON_AddNumberToObject(_agent_tables_sync_t, "dbsync", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.sync.dbsync_time));

    cJSON *_agent_tables_syscheck_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_t, "syscheck", _agent_tables_syscheck_t);

    cJSON_AddNumberToObject(_agent_tables_syscheck_t, "fim_file", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_file_time));
    cJSON_AddNumberToObject(_agent_tables_syscheck_t, "fim_registry", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_time));
    cJSON_AddNumberToObject(_agent_tables_syscheck_t, "fim_registry_key", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_key_time));
    cJSON_AddNumberToObject(_agent_tables_syscheck_t, "fim_registry_value", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.fim_registry_value_time));
    cJSON_AddNumberToObject(_agent_tables_syscheck_t, "syscheck", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscheck.syscheck_time));

    cJSON *_agent_tables_syscollector_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_t, "syscollector", _agent_tables_syscollector_t);

    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_hotfixes", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_hwinfo", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_network_address", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_network_iface", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_network_protocol", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_osinfo", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_packages", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_ports", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_t, "syscollector_processes", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time));

    cJSON *_agent_tables_syscollector_deprecated_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_agent_tables_syscollector_t, "deprecated", _agent_tables_syscollector_deprecated_t);

    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "hardware", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "hotfix", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "netaddr", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "netinfo", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "netproto", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "osinfo", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "package", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.package_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "port", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.port_time));
    cJSON_AddNumberToObject(_agent_tables_syscollector_deprecated_t, "process", timeval_to_milis(wdb_state_cpy.queries_breakdown.agent_breakdown.syscollector.deprecated.process_time));

    cJSON_AddNumberToObject(_execution_breakdown, "global", get_global_time(&wdb_state_cpy));

    cJSON *_global_breakdown_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_execution_breakdown, "global_breakdown", _global_breakdown_t);

    cJSON *_global_db_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_breakdown_t, "db", _global_db_t);

    cJSON_AddNumberToObject(_global_db_t, "open", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.open_calls_time));
    cJSON_AddNumberToObject(_global_db_t, "backup", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.backup_time));
    cJSON_AddNumberToObject(_global_db_t, "sql", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.sql_time));
    cJSON_AddNumberToObject(_global_db_t, "vacuum", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.vacuum_time));
    cJSON_AddNumberToObject(_global_db_t, "get_fragmentation", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.get_fragmentation_time));
    cJSON_AddNumberToObject(_global_db_t, "sleep", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.sleep_time));

    cJSON *_global_tables_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_breakdown_t, "tables", _global_tables_t);

    cJSON *_global_tables_agent_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables_t, "agent", _global_tables_agent_t);

    cJSON_AddNumberToObject(_global_tables_agent_t, "delete-agent", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.delete_agent_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "disconnect-agents", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.disconnect_agents_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "find-agent", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.find_agent_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "get-agent-info", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agent_info_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "get-agents-by-connection-status", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "get-all-agents", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_all_agents_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "get-distinct-groups", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_distinct_groups_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "get-groups-integrity", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.get_groups_integrity_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "recalculate-agent-group-hashes", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "insert-agent", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.insert_agent_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "reset-agents-connection", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.reset_agents_connection_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "select-agent-group", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_group_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "select-agent-name", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.select_agent_name_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "set-agent-groups", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.set_agent_groups_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "sync-agent-groups-get", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "sync-agent-info-get", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "sync-agent-info-set", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "update-agent-data", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_data_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "update-agent-name", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_agent_name_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "update-connection-status", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_connection_status_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "update-status-code", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_status_code_time));
    cJSON_AddNumberToObject(_global_tables_agent_t, "update-keepalive", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.agent.update_keepalive_time));

    cJSON *_global_tables_belongs_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables_t, "belongs", _global_tables_belongs_t);

    cJSON_AddNumberToObject(_global_tables_belongs_t, "get-group-agents", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.belongs.get_group_agent_time));
    cJSON_AddNumberToObject(_global_tables_belongs_t, "select-group-belong", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.belongs.select_group_belong_time));

    cJSON *_global_tables_group_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables_t, "group", _global_tables_group_t);

    cJSON_AddNumberToObject(_global_tables_group_t, "delete-group", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.delete_group_time));
    cJSON_AddNumberToObject(_global_tables_group_t, "find-group", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.find_group_time));
    cJSON_AddNumberToObject(_global_tables_group_t, "insert-agent-group", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.insert_agent_group_time));
    cJSON_AddNumberToObject(_global_tables_group_t, "select-groups", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.group.select_groups_time));

    cJSON *_global_tables_labels_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_global_tables_t, "labels", _global_tables_labels_t);

    cJSON_AddNumberToObject(_global_tables_labels_t, "get-labels", timeval_to_milis(wdb_state_cpy.queries_breakdown.global_breakdown.labels.get_labels_time));

    cJSON_AddNumberToObject(_execution_breakdown, "mitre", timeval_to_milis(wdb_state_cpy.queries_breakdown.mitre_breakdown.sql_time));

    cJSON *_mitre_breakdown_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_execution_breakdown, "mitre_breakdown", _mitre_breakdown_t);

    cJSON *_mitre_db_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_mitre_breakdown_t, "db", _mitre_db_t);

    cJSON_AddNumberToObject(_mitre_db_t, "sql", timeval_to_milis(wdb_state_cpy.queries_breakdown.mitre_breakdown.sql_time));

    cJSON_AddNumberToObject(_execution_breakdown, "task", get_task_time(&wdb_state_cpy));

    cJSON *_task_breakdown_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_execution_breakdown, "task_breakdown", _task_breakdown_t);

    cJSON *_task_db_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_breakdown_t, "db", _task_db_t);

    cJSON_AddNumberToObject(_task_db_t, "sql", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.sql_time));

    cJSON *_task_tables_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_breakdown_t, "tables", _task_tables_t);

    cJSON *_task_tables_tasks_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_task_tables_t, "tasks", _task_tables_tasks_t);

    cJSON_AddNumberToObject(_task_tables_tasks_t, "delete_old", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.delete_old_time));
    cJSON_AddNumberToObject(_task_tables_tasks_t, "set_timeout", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.set_timeout_time));
    cJSON_AddNumberToObject(_task_tables_tasks_t, "upgrade", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_time));
    cJSON_AddNumberToObject(_task_tables_tasks_t, "upgrade_cancel_tasks", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time));
    cJSON_AddNumberToObject(_task_tables_tasks_t, "upgrade_custom", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_custom_time));
    cJSON_AddNumberToObject(_task_tables_tasks_t, "upgrade_get_status", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_get_status_time));
    cJSON_AddNumberToObject(_task_tables_tasks_t, "upgrade_result", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_result_time));
    cJSON_AddNumberToObject(_task_tables_tasks_t, "upgrade_update_status", timeval_to_milis(wdb_state_cpy.queries_breakdown.task_breakdown.tasks.upgrade_update_status_time));

    cJSON_AddNumberToObject(_execution_breakdown, "wazuhdb", timeval_to_milis(wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.remove_time));

    cJSON *_wazuhdb_breakdown_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_execution_breakdown, "wazuhdb_breakdown", _wazuhdb_breakdown_t);

    cJSON *_wazuhdb_db_t = cJSON_CreateObject();
    cJSON_AddItemToObject(_wazuhdb_breakdown_t, "db", _wazuhdb_db_t);

    cJSON_AddNumberToObject(_wazuhdb_db_t, "remove", timeval_to_milis(wdb_state_cpy.queries_breakdown.wazuhdb_breakdown.remove_time));

    return wdb_state_json;
}

STATIC uint64_t get_agent_time(wdb_state_t *state){
    struct timeval task_time;

    timeradd(&state->queries_breakdown.agent_breakdown.sql_time, &state->queries_breakdown.agent_breakdown.remove_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.open_calls_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.vacuum_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.get_fragmentation_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.sleep_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.begin_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.commit_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.close_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscheck.syscheck_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscheck.fim_file_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscheck.fim_registry_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscheck.fim_registry_key_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscheck.fim_registry_value_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.rootcheck.rootcheck_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.sca.sca_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.ciscat.ciscat_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.process_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.package_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.port_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.agent_breakdown.sync.dbsync_time, &task_time);

    return timeval_to_milis(task_time);
}

STATIC uint64_t get_global_time(wdb_state_t *state){
    struct timeval task_time;

    timeradd(&state->queries_breakdown.global_breakdown.sql_time, &state->queries_breakdown.global_breakdown.backup_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.open_calls_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.vacuum_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.get_fragmentation_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.sleep_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.insert_agent_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.update_agent_data_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.update_agent_name_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.update_keepalive_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.update_connection_status_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.update_status_code_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.reset_agents_connection_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.delete_agent_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.select_agent_name_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.select_agent_group_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.find_agent_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.get_agent_info_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.get_all_agents_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.get_distinct_groups_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.disconnect_agents_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.sync_agent_info_get_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.sync_agent_info_set_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.set_agent_groups_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.get_groups_integrity_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.group.insert_agent_group_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.group.delete_group_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.group.select_groups_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.group.find_group_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.belongs.select_group_belong_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.belongs.get_group_agent_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.global_breakdown.labels.get_labels_time, &task_time);

    return timeval_to_milis(task_time);
}

STATIC uint64_t get_task_time(wdb_state_t *state){
    struct timeval task_time;

    timeradd(&state->queries_breakdown.task_breakdown.sql_time, &state->queries_breakdown.task_breakdown.tasks.upgrade_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.task_breakdown.tasks.upgrade_custom_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.task_breakdown.tasks.upgrade_get_status_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.task_breakdown.tasks.upgrade_update_status_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.task_breakdown.tasks.upgrade_result_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.task_breakdown.tasks.set_timeout_time, &task_time);
    timeradd(&task_time, &state->queries_breakdown.task_breakdown.tasks.delete_old_time, &task_time);

    return timeval_to_milis(task_time);
}

STATIC uint64_t get_time_total(wdb_state_t *state){
    return get_task_time(state) + get_global_time(state) + get_agent_time(state) + timeval_to_milis(state->queries_breakdown.wazuhdb_breakdown.remove_time) + timeval_to_milis(state->queries_breakdown.mitre_breakdown.sql_time);
}
