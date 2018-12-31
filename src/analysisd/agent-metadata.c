#include "agent-metadata.h"

void init_agent_metadata(){
    /* Here it read the config*/
    
    wlabel_t **agent_metadata;
    agents_info = OSHash_Create();

}


void set_agent_metadata(char *agent_metadata, size_t size, wlabel_t* agent_data){
    size_t z = 0;

    if(agent_data != NULL){
        int j;
        for(j = 0; j < 3; j++){
            z += snprintf(agent_metadata + z, size - z ,"%s: %s \n",agent_data[j].key,agent_data[j].value);
        }
    } else{
        agent_metadata[0] = '\0';
    }
}

cJSON *set_agent_metadata_json(wlabel_t* agent_data){
    cJSON* agent_metadata = cJSON_CreateObject();

    if(agent_data != NULL){
        int i;
        for(i = 0; i < 3; i++){
            cJSON_AddStringToObject(agent_metadata,agent_data[i].key,agent_data[i].value);
        }
    }
    else{
        mdebug2("No metadata for agent");
        return NULL;
    }
    
    return agent_metadata;
}

int send_query_wazuhdb(char *wazuhdb_query, char **output) {
    char response[OS_SIZE_6144];
    fd_set fdset;
    struct timeval timeout = {0, 1000};
    int size = strlen(wazuhdb_query);
    int retval = 0;
    int socket = -1;

    // Connect to socket if disconnected
    if (socket < 0) {
        socket = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144);
        if (socket < 0) {
            mterror(ARGV0, "AGENT METADATA decoder: Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            return -2;
        }
    }

    // Send query to Wazuh DB
    if (OS_SendSecureTCP(socket, size + 1, wazuhdb_query) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            mterror(ARGV0, "AGENT METADATA decoder: database socket is full");
        } else if (errno == EPIPE) {
            // Retry to connect
            mterror(ARGV0, "AGENT METADATA decoder: Connection with wazuh-db lost. Reconnecting.");
            close(socket);

            if (socket = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144), socket < 0) {
                switch (errno) {
                    case ENOENT:
                        mterror(ARGV0, "AGENT METADATA decoder: Cannot find '%s'. Please check that Wazuh DB is running.", WDB_LOCAL_SOCK);
                        break;
                    default:
                        mterror(ARGV0, "AGENT METADATA decoder: Cannot connect to '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                }
                return (-2);
            }

            if (OS_SendSecureTCP(socket, size + 1, wazuhdb_query)) {
                mterror(ARGV0, "AGENT METADATA decoder: in send reattempt (%d) '%s'.", errno, strerror(errno));
                return (-2);
            }
        } else {
            mterror(ARGV0, "AGENT METADATA decoder: in send (%d) '%s'.", errno, strerror(errno));
        }
    }

    // Wait for socket
    FD_ZERO(&fdset);
    FD_SET(socket, &fdset);

    if (select(socket + 1, &fdset, NULL, NULL, &timeout) < 0) {
        mterror(ARGV0, "AGENT METADATA decoder: in select (%d) '%s'.", errno, strerror(errno));
        return (-2);
    }

    // Receive response from socket
    if (OS_RecvSecureTCP(socket, response, OS_SIZE_6144 - 1) > 0) {
        os_strdup(response, *output);
        return retval;
    } else {
        mterror(ARGV0, "AGENT METADATA decoder: no response from wazuh-db.");
        return retval;
    }
    return retval;
}

int get_netaddr_values(char *db_result, netaddr_info **netaddr_value){
    char * next = NULL;
    char * current = NULL;
    char * proto = NULL;
    int size = 0;
    int size_ipv6 = 0;
    os_strdup(db_result,current);
    
    while(strlen(current) > 0) {

        if (next = strchr(current, '|'), !next) {
            merror("Invalid proto.");
            break;
        } else{
            proto = current;
            *next++ = '\0';
            current = next;
        }

        if (strcmp(proto,"ipv4") == 0){
            os_calloc(1,sizeof(netaddr_info),netaddr_value[size]);
            os_calloc(30,sizeof(char),netaddr_value[size]->address);

            if (next = strchr(current, '|'), !next) {
                merror("Invalid address.");
                break;
            } else{
                netaddr_value[size]->address = current;
                *next++ = '\0';
                current = next;
            }
            size++;
        } else{
            os_calloc(30,sizeof(char),netaddr_value[size_ipv6]->ipv6);

            if (next = strchr(current, '|'), !next) {
                if(strlen(current)){
                    netaddr_value[size_ipv6]->ipv6 = current;
                    current = "\0";
                }
                else{
                    merror("Invalid address.");
                    break;
                }
            } else{
                netaddr_value[size_ipv6]->ipv6 = current;
                *next++ = '\0';
                current = next;
            }
            size_ipv6++;
        }
        
    }

    if(size != size_ipv6){
        merror("Mismatching number of interfaces");
    }
    return size;
}

void get_osinfo_values(char *db_result, osinfo_info *osinfo_value){
    char * next = NULL;
    char * current = NULL;

    os_strdup(db_result,current);
    os_calloc(30,sizeof(char),osinfo_value->name);
    os_calloc(30,sizeof(char),osinfo_value->version);
    os_calloc(30,sizeof(char),osinfo_value->hostname);
    os_calloc(30,sizeof(char),osinfo_value->timezone);

    if (next = strchr(current, '|'), !next) {
        merror("Invalid name.");
    }
    else{
        osinfo_value->name = current;
        *next++ = '\0';
        current = next;
    }

    if (next = strchr(current, '|'), !next) {
        merror("Invalid version.");
    }
    else{
        osinfo_value->version = current;
        *next++ = '\0';
        current = next;
    }
    if (next = strchr(current, '|'), !next) {
        merror("Invalid hostname.");
    }
    else{
        osinfo_value->hostname = current;
        *next++ = '\0';
        current = next;
    }
    if (next = strchr(current, '|'), next) {
        merror("Invalid timezone");
    }
    else{
        osinfo_value->timezone = current;
    }

    next = strchr(osinfo_value->timezone,' ')+1;
    osinfo_value->timezone = strchr(next,' ');
}

int get_netinfo_values(char *db_result, char** mac){
    char * next = NULL;
    char * current = NULL;
    int size = 0;
    os_strdup(db_result,current);

    while(strlen(current) > 0) {
        if (next = strchr(current, '|'), !next) {
            if(strlen(current)){
                    os_calloc(30,sizeof(char),mac[size]);
                    mac[size] = current;
                    current = "\0";
            }
            else{
                merror("Error parsing MAC information.");
                break;
            }
        } else{
            os_calloc(30,sizeof(char),mac[size]);
            mac[size] = current;
            *next++ = '\0';
            current = next;
        }
        size++;
    }
    return size;
}