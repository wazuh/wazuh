// Weak stub implementations of wmodules Read_* functions
// These are needed by config.c dispatcher but won't be called by executables
// that don't use CWMODULE flag (like agentd, logcollector)

#include "config.h"

__attribute__((weak)) int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2) {
    (void)xml; (void)node; (void)d1; (void)d2;
    return 0;
}

__attribute__((weak)) int Read_SCA(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_AGENT_INFO(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_GCP_pubsub(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_GCP_bucket(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_AgentUpgrade(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_Github(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_Office365(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_MS_Graph(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_Vulnerability_Detection(const OS_XML *xml, xml_node **nodes, void *d1, const bool old_vd) {
    (void)xml; (void)nodes; (void)d1; (void)old_vd;
    return 0;
}

__attribute__((weak)) int Read_TaskManager(const OS_XML *xml, xml_node *node, void *d1) {
    (void)xml; (void)node; (void)d1;
    return 0;
}

__attribute__((weak)) int Read_WazuhDB_Backup(const OS_XML *xml, xml_node * node, int const BACKUP_NODE) {
    (void)xml; (void)node; (void)BACKUP_NODE;
    return 0;
}

__attribute__((weak)) int Read_WazuhDB(const OS_XML *xml, xml_node **nodes) {
    (void)xml; (void)nodes;
    return 0;
}
