#include "state.h"
#include "shared.h"

pthread_mutex_t db_stats_t_mutex = PTHREAD_MUTEX_INITIALIZER;

db_stats_t wazuhdb_stats = {0};



void w_inc_queries_total(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_total++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.wazuhdb_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_remove_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.remove_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_wazuhdb_unknown_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.wazuhdb_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_sql_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.sql_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_remove_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.remove_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_begin_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.begin_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_commit_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.commit_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_close_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.close_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_rootcheck_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.rootcheck_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_sca_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.sca_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_ciscat_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.ciscat_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_vul_detector_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.vulnerability_detector_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_dbsync_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.dbsync_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_unknown_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.unknown_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscheck_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.syscheck_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_fim_file_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_file_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_fim_registry_queries(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscheck.fim_registry_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_processes(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_packages(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_hotfixes(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_ports(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_network_protocol(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_network_address(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_network_iface(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_hwinfo(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_osinfo(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_process(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.process_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_packages(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.package_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hotfixes(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hotfix_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_ports(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.port_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_protocol(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netproto_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_address(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netaddr_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_network_info(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.netinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_hardware(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.hardware_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}

void w_inc_agent_syscollector_deprecated_osinfo(){
    w_mutex_lock(&db_stats_t_mutex);
    wazuhdb_stats.queries_breakdown.agent_breakdown.syscollector.osinfo_queries++;
    w_mutex_unlock(&db_stats_t_mutex);
}
