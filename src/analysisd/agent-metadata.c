#include "analysisd.h"

void init_agent_metadata(){
    /* Here it read the config*/
    int key_num;
    int agents_num;
    int i;
    wlabel_t *agent_metadata;
    os_calloc(1,sizeof(wlabel_t) * key_num,agent_metadata);
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