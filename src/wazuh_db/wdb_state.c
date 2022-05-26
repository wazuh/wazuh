#include "wdb_state.h"
#include <pthread.h>

pthread_mutex_t db_stats_t_mutex = PTHREAD_MUTEX_INITIALIZER;
db_stats_t wazuhdb_stats = {0};

void w_inc_queries_total() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_total++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.wazuhdb_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_get_config() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.get_config_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_remove() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.remove_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_unknown() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_sql() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.sql_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_remove() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.remove_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_begin() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.begin_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_commit() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.commit_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_close() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.close_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_rootcheck() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.rootcheck_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_sca() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.sca_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_ciscat() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.ciscat_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_vul_detector() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.vulnerability_detector_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_dbsync() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.dbsync_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_unknown() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscheck() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.syscheck_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_fim_file() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_file_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_fim_registry() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_registry_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_processes() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_packages() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_hotfixes() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_ports() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_network_protocol() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_network_address() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_network_iface() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_hwinfo() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_osinfo() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_process() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.process_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_packages() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.package_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hotfixes() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hotfix_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_ports() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.port_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_protocol() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netproto_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_address() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netaddr_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_info() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hardware() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hardware_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_osinfo() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.osinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_sql() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.sql_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_backup() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.backup_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_unknown() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_insert_agent() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.insert_agent_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_agent_data() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_agent_data_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_agent_name() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_agent_name_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_keepalive() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_keepalive_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_connection_status() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_connection_status_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_reset_agents_connection() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.reset_agents_connection_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_sync_agent_info_set() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_delete_agent() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.delete_agent_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_select_agent_name() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.select_agent_name_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_select_agent_group() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.select_agent_group_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_find_agent() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.find_agent_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_agent_info() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_agent_info_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_all_agents() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_all_agents_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_agents_by_connection_status() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_disconnect_agents() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.disconnect_agents_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_sync_agent_info_get() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_sync_agent_groups_get() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_set_agent_groups() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.set_agent_groups_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_groups_integrity() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_groups_integrity_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_insert_agent_group() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.group.insert_agent_group_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_delete_group() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.group.delete_group_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_select_groups() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.group.select_groups_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_find_group() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.group.find_group_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_belongs_select_group_belong() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.belongs.select_group_belong_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_belongs_get_group_agent() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.belongs.get_group_agent_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_labels_get_labels() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.global_breakdown.labels.get_labels_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_sql() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.sql_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_set_timeout() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.set_timeout_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_delete_old() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.delete_old_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_unknown() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_custom() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_custom_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_get_status() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_update_status() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_result() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_result_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_cancel_tasks() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_mitre() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.mitre_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_mitre_sql() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.mitre_breakdown.sql_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_mitre_unknown() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.mitre_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_unknown() {
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscheck_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.syscheck_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.syscheck_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_fim_file_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_file_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_file_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_fim_registry_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_registry_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_registry_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_times(struct timeval time, wdb_component_t type) {

    w_mutex_lock(&db_stats_t_mutex);

    switch (type) {
    case WDB_SYSCOLLECTOR_PROCESSES:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time);
        break;
    case WDB_SYSCOLLECTOR_PACKAGES:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time);
        break;
    case WDB_SYSCOLLECTOR_HOTFIXES:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time);
        break;
    case WDB_SYSCOLLECTOR_PORTS:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time);
        break;
    case WDB_SYSCOLLECTOR_NETPROTO:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time);
        break;
    case WDB_SYSCOLLECTOR_NETADDRESS:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time);
        break;
    case WDB_SYSCOLLECTOR_NETINFO:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time);
        break;
    case WDB_SYSCOLLECTOR_HWINFO:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time);
        break;
    case WDB_SYSCOLLECTOR_OSINFO:
        timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time);
        break;
    default:
        break;
    }

    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_process_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.process_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.process_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hotfixes_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hotfix_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hotfix_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_packages_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.package_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.package_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_ports_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.port_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.port_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hardware_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hardware_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hardware_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_osinfo_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.osinfo_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.osinfo_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_address_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netaddr_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netaddr_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_protocol_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netproto_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netproto_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_info_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netinfo_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netinfo_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_sql_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.sql_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.sql_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_remove_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.remove_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.remove_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_begin_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.begin_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.begin_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_commit_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.commit_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.commit_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_close_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.close_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.close_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_rootcheck_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.rootcheck_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.rootcheck_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_ciscat_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.ciscat_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.ciscat_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_dbsync_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.dbsync_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.dbsync_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_sca_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.sca_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.sca_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_vul_detector_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.agent_breakdown.vulnerability_detector_time, &time, &wazuhdb_stats.queries_breakdown.agent_breakdown.vulnerability_detector_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_mitre_sql_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.mitre_breakdown.sql_time, &time, &wazuhdb_stats.queries_breakdown.mitre_breakdown.sql_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_insert_agent_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.insert_agent_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.insert_agent_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_agent_data_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_agent_data_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_agent_data_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_agent_name_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_agent_name_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_agent_name_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_keepalive_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_keepalive_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_keepalive_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_update_connection_status_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_connection_status_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.update_connection_status_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_reset_agents_connection_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.reset_agents_connection_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.reset_agents_connection_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_sync_agent_info_set_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_info_set_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_delete_agent_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.delete_agent_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.delete_agent_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_select_agent_name_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.select_agent_name_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.select_agent_name_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_select_agent_group_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.select_agent_group_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.select_agent_group_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_find_agent_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.find_agent_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.find_agent_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_agent_info_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_agent_info_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_agent_info_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_all_agents_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_all_agents_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_all_agents_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_agents_by_connection_status_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_disconnect_agents_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.disconnect_agents_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.disconnect_agents_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_sync_agent_info_get_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_info_get_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_sync_agent_groups_get_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_set_agent_groups_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.set_agent_groups_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.set_agent_groups_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_agent_get_groups_integrity_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_groups_integrity_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.agent.get_groups_integrity_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_insert_agent_group_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.group.insert_agent_group_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.group.insert_agent_group_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_delete_group_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.group.delete_group_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.group.delete_group_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_select_groups_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.group.select_groups_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.group.select_groups_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_group_find_group_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.group.find_group_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.group.find_group_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_belongs_select_group_belong_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.belongs.select_group_belong_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.belongs.select_group_belong_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_belongs_get_group_agent_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.belongs.get_group_agent_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.belongs.get_group_agent_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_labels_get_labels_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.labels.get_labels_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.labels.get_labels_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_custom_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_custom_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_get_status_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_get_status_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_update_status_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_update_status_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_result_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_result_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_result_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_upgrade_cancel_tasks_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.upgrade.upgrade_cancel_tasks_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_sql_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.sql_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.sql_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_set_timeout_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.set_timeout_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.set_timeout_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_task_delete_old_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.task_breakdown.delete_old_time, &time, &wazuhdb_stats.queries_breakdown.task_breakdown.delete_old_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_sql_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.sql_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.sql_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_global_backup_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.global_breakdown.backup_time, &time, &wazuhdb_stats.queries_breakdown.global_breakdown.backup_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_get_config_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.get_config_time, &time, &wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.get_config_time);
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_remove_time(struct timeval time) {
    w_mutex_lock(&db_stats_t_mutex);
    timeradd(&wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.remove_time, &time, &wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.remove_time);
    w_mutex_unlock(&db_stats_t_mutex);
}
