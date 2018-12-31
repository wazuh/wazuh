#include "yaml.h"
#include "analysisd.h"
#include "os_net/os_net.h"

int agents_num;

typedef struct agent_conf{
    char id[7];
    char **keys;
    int num_keys;
}agent_conf;

typedef struct netaddr_info{
    char *ipv6;
    char *address;
}netaddr_info;

typedef struct osinfo_info{
    char *name;
    char *version;
    char *hostname;
    char *timezone;
}osinfo_info;

agent_conf * metadata_config;

/* Hash table with info of the agents to enrich the alerts */
OSHash *agents_info;
void init_agent_metadata();
void set_agent_metadata(char * agent_metadata, size_t size, wlabel_t *agent_data);
cJSON *set_agent_metadata_json(wlabel_t *agent_data);
int send_query_wazuhdb(char *wazuhdb_query, char **output);
int get_netaddr_values(char *db_result, netaddr_info **netaddr_value);
void get_osinfo_values(char *db_result, osinfo_info *netaddr_value);
int get_netinfo_values(char *db_result, char** mac);