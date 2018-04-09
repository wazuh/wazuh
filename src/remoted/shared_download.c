/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* remote daemon
 * Listen to remote packets and forward them to the analysis system
 */

#include "shared.h"
#include "shared_download.h"

OSHash *ptable;

void *w_parser_get_group(const char *name){
    return OSHash_Get(ptable,name);
}

void *w_parser_get_agent(const char *name){
    return OSHash_Get(ptable,name);
}

const char *w_read_scalar_value(yaml_event_t * event){
    return (const char *)event->data.scalar.value;
}

int w_move_next(yaml_parser_t * parser,yaml_event_t * event){
    if (!yaml_parser_parse(parser, event)) {
        merror("Parser error %d\n", parser->error);
        return W_PARSER_ERROR;
    }
    return 1;
}

int w_read_agents(yaml_parser_t * parser,yaml_event_t * event,agent_group **agents_group,int *num_agents_readed){

    int n_agents = 1;

    do {
        w_move_next(parser,event); //Get agent id
        if(event->type == YAML_MAPPING_END_EVENT)
        {
            *num_agents_readed = n_agents - 1;
            return 1;
        }
        
        agent_group *agt_group;
        if(event->type == YAML_SCALAR_EVENT)
        {
            *agents_group = realloc(*agents_group,n_agents*sizeof(agent_group));
            agt_group = *agents_group;
            os_calloc(OS_SIZE_256,sizeof(char),agt_group[n_agents-1].name);
            memcpy(agt_group[n_agents-1].name,w_read_scalar_value(event),strlen(w_read_scalar_value(event)));
        }
        else{
            merror(W_PARSER_EXPECTED_AGENT_ID);
            return W_PARSER_ERROR;
        }
       
        w_move_next(parser,event); //Get group name
        if(event->type == YAML_SCALAR_EVENT)
        {
            os_calloc(OS_SIZE_256,sizeof(char),agt_group[n_agents-1].group);
            memcpy(agt_group[n_agents-1].group,w_read_scalar_value(event),strlen(w_read_scalar_value(event)));
            n_agents+=1;
        }
        else{
            merror(W_PARSER_EXPECTED_GROUP_NAME,agt_group[n_agents-1].name);
            return W_PARSER_ERROR;
        }

        if(event->type != YAML_STREAM_END_EVENT){
            yaml_event_delete(event);
        }
        else{
            return W_PARSER_ERROR;
        }

    } while(event->type != YAML_MAPPING_END_EVENT);

    *num_agents_readed = n_agents - 1;

    return 1;
}

int w_read_group_files(yaml_parser_t * parser,yaml_event_t * event,remote_files_group *agent_remote_group){
    
    int n_files = 1;

    do {
        if (!yaml_parser_parse(parser, event)) {
            merror("Parser error %d\n", parser->error);
            return W_PARSER_ERROR;
        }

        w_move_next(parser,event); //Move to name: 
        if(event->type == YAML_SCALAR_EVENT && !strcmp(w_read_scalar_value(event),"name"))
        {
            w_move_next(parser,event);
            os_calloc(OS_SIZE_1024+1,sizeof(char),agent_remote_group->files_group->name);
            agent_remote_group->files_group->file = NULL;
            agent_remote_group->files_group->num_files = 0;
            memcpy(agent_remote_group->files_group->name,w_read_scalar_value(event),strlen(w_read_scalar_value(event)));
        }
        //Read each file
        do{
            w_move_next(parser,event); //Read file name

            if(event->type == YAML_MAPPING_END_EVENT)
                break;

            agent_remote_group->files_group->file = realloc(agent_remote_group->files_group->file,n_files*sizeof(file));
            os_calloc(OS_SIZE_1024+1,sizeof(char),agent_remote_group->files_group->file[n_files-1].name);
            os_calloc(OS_SIZE_1024+1,sizeof(char),agent_remote_group->files_group->file[n_files-1].url);
            agent_remote_group->files_group->num_files++;

            if(event->type == YAML_SCALAR_EVENT)
            {
                memcpy(agent_remote_group->files_group->file[n_files-1].name,w_read_scalar_value(event),strlen(w_read_scalar_value(event)));
                //Check if the file name is merged.mg
                if(!strncmp(agent_remote_group->files_group->file[n_files-1].name,SHAREDCFG_FILENAME,9)){
                    agent_remote_group->merge_file_index = n_files-1;
                } 
            }

            w_move_next(parser,event); //Read file url
            if(event->type == YAML_SCALAR_EVENT)
            {
                memcpy(agent_remote_group->files_group->file[n_files-1].url,w_read_scalar_value(event),strlen(w_read_scalar_value(event)));
                n_files++;
            }
            else
            {
                merror(W_PARSER_ERROR_EXPECTED_VALUE,agent_remote_group->files_group->file[n_files-1].name);
                return W_PARSER_ERROR;
            }

            if(event->type != YAML_STREAM_END_EVENT)
                yaml_event_delete(event);

        }while(event->type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(event);
        break;

    } while(event->type != YAML_MAPPING_END_EVENT);

    return 1;
}

int w_do_parsing(remote_files_group **agent_remote_group,int *num_groups,const char *yaml_file,agent_group **agents_group,int *num_agents_readed){
    FILE *fh = fopen(yaml_file, "r");
    yaml_parser_t parser;
    yaml_event_t  event;
    int n_groups = 1;
    int has_groups = 0;

    if(!yaml_parser_initialize(&parser)){
      merror(W_PARSER_ERROR_INIT);
      return OS_INVALID;
    }
    if(fh == NULL){
      merror(W_PARSER_ERROR_FILE,yaml_file);
      return OS_FILERR;
    }

    minfo(W_PARSER_STARTED,yaml_file);
  
    yaml_parser_set_input_file(&parser, fh);
  
    do {
        if (!yaml_parser_parse(&parser, &event)) {
            merror("Parser error %d\n", parser.error);
            return W_PARSER_ERROR;
        }
  
        remote_files_group *agt_r_g;

        //Read groups:
        if(event.type == YAML_SCALAR_EVENT && !strncmp(w_read_scalar_value(&event),"groups",6)){
            has_groups = 1;
        }

        if(has_groups){
            //Read group name and malloc the structure
            if(event.type == YAML_SCALAR_EVENT && !strncmp(w_read_scalar_value(&event),"group",5)){
                *agent_remote_group = realloc(*agent_remote_group,n_groups*sizeof(remote_files_group));
                agt_r_g = *agent_remote_group;
                os_calloc(OS_SIZE_256,sizeof(char),agt_r_g[n_groups-1].name);
                agt_r_g[n_groups-1].merge_file_index = -1;
                memcpy(agt_r_g[n_groups-1].name,w_read_scalar_value(&event)+6,strlen(w_read_scalar_value(&event))-5);
            }
    
            //Read group files
            if(event.type == YAML_SCALAR_EVENT && !strcmp(w_read_scalar_value(&event),"files"))
            {
                agt_r_g[n_groups-1].files_group = malloc(1*sizeof(files_group));
                w_read_group_files(&parser,&event,&agt_r_g[n_groups-1]);
            }
    
            //Read group poll
            if(event.type == YAML_SCALAR_EVENT && !strncmp(w_read_scalar_value(&event),"poll",4)){
                w_move_next(&parser,&event);

                if(event.type != YAML_SCALAR_EVENT)
                {
                    //parser error
                    merror(W_PARSER_ERROR_EXPECTED_VALUE,"poll");
                    return W_PARSER_ERROR;
                }

                agt_r_g[n_groups-1].poll = strtol(w_read_scalar_value(&event),NULL,10);
                agt_r_g[n_groups-1].current_polling_time = 0;
                agt_r_g[n_groups-1].merged_is_downloaded = 0;
                n_groups++;
            }
        }

        //Read agents
        if(event.type == YAML_SCALAR_EVENT && !strncmp(w_read_scalar_value(&event),"agents",6)){
            w_move_next(&parser,&event); // Mapping start
            w_read_agents(&parser,&event,agents_group,num_agents_readed);
        }

        if(event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
  
    } while(event.type != YAML_STREAM_END_EVENT);
  
    *num_groups = n_groups - 1;
    
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fh);

    return 1;
}

void w_free_groups(){
    /*for(i = 0;i < num_groups;i++){
        if(agent_remote_group[i].files_group != NULL){
            j = 0;

            for(j=0;j<agent_remote_group[i].files_group->num_files;j++){
                free(agent_remote_group[i].files_group->file[j].name);
                free(agent_remote_group[i].files_group->file[j].url);
            }

            free(agent_remote_group[i].files_group->file);
            free(agent_remote_group[i].files_group->name);
        }
        free(agent_remote_group[i].name);
        free(agent_remote_group[i].files_group);
    }

    free(agent_remote_group);
    agent_remote_group = NULL;*/
    OSHash_Free(ptable);
}


int w_init_shared_download()
{
    remote_files_group *agent_remote_group = NULL;
    agent_group *agents_group = NULL;

    char yaml_file[OS_SIZE_1024 + 1];
    int num_groups = 0;
    int num_agents = 0;
    int parse_ok = 0;

    if (ptable = OSHash_Create(), !ptable){
        merror(W_PARSER_HASH_TABLE_ERROR);
        return OS_INVALID;
    }

    snprintf(yaml_file, OS_SIZE_1024, "%s/%s", SHAREDCFG_DIR,W_SHARED_YAML_FILE);
    parse_ok = w_do_parsing(&agent_remote_group,&num_groups,yaml_file,&agents_group,&num_agents);

    if(parse_ok == 1){
        int i = 0;

        minfo(W_PARSER_SUCCESS,yaml_file);

        // Add the groups
        for(i = 0; i < num_groups; i++){
            OSHash_Add(ptable, agent_remote_group[i].name, &agent_remote_group[i]);
        }

        //Add the agents
        for(i = 0; i < num_agents; i++){
            OSHash_Add(ptable, agents_group[i].name, &agents_group[i]);
        }
    }
    else{
        minfo(W_PARSER_FAILED,yaml_file);
    }

    return 0;
}
