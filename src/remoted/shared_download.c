/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "shared_download.h"
#include <pthread.h>

OSHash *ptable;
static remote_files_group *agent_remote_group;
static agent_group *agents_group;
static char yaml_file[OS_SIZE_1024 + 1];
static time_t yaml_file_date;
static ino_t yaml_file_inode;
static pthread_mutex_t rem_yaml_mutex = PTHREAD_MUTEX_INITIALIZER;

remote_files_group * w_parser_get_group(const char * name) {
    remote_files_group * group = NULL;

    w_mutex_lock(&rem_yaml_mutex);

    if (ptable) {
        group = OSHash_Get(ptable,name);
    }

    w_mutex_unlock(&rem_yaml_mutex);
    return group;
}

agent_group * w_parser_get_agent(const char * name) {
    agent_group * group = NULL;

    w_mutex_lock(&rem_yaml_mutex);

    if (ptable) {
        group = OSHash_Get(ptable,name);
    }

    w_mutex_unlock(&rem_yaml_mutex);
    return group;
}

void w_yaml_create_groups() {
    int i;

    if (agent_remote_group) {
        for (i = 0; agent_remote_group[i].name; i++) {
            w_create_group(agent_remote_group[i].name);
        }
    }
}

const char *w_read_scalar_value(yaml_event_t * event){
    return (const char *)event->data.scalar.value;
}

int w_move_next(yaml_parser_t * parser, yaml_event_t * event){
    if (!yaml_parser_parse(parser, event)) {
        merror("Parser error %d", parser->error);
        return W_PARSER_ERROR;
    }
    return 0;
}

agent_group * w_read_agents(yaml_parser_t * parser) {
    agent_group * agents;
    yaml_event_t event;
    int index = 0;

    os_calloc(1, sizeof(agent_group), agents);

    if (w_move_next(parser, &event)) {
        goto error;
    }

    switch (event.type) {
    case YAML_MAPPING_START_EVENT:
        do {
            yaml_event_delete(&event);

            if (w_move_next(parser, &event)) {
                goto error;
            }

            switch (event.type) {
            case YAML_SCALAR_EVENT:
                os_realloc(agents, sizeof(agent_group) * (index + 2), agents);
                memset(agents + index + 1, 0, sizeof(agent_group));
                os_strdup(w_read_scalar_value(&event), agents[index].name);
                yaml_event_delete(&event);

                if (!(yaml_parser_parse(parser, &event) && event.type == YAML_SCALAR_EVENT)) {
                    merror(W_PARSER_ERROR_EXPECTED_VALUE, agents[index].name);
                    goto error;
                }

                os_strdup(w_read_scalar_value(&event), agents[index].group);

                index++;
                break;
            case YAML_MAPPING_END_EVENT:
                break;

            default:
                merror("Parsing error: unexpected token %d", event.type);
                goto error;
            }

        } while (event.type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(&event);
        return agents;

    default:
        merror("Parsing error: unexpected token %d", event.type);
    }

error:
    if(agents)
    {
        int i;
        for(i = 0; agents[i].name; i++){
            free(agents[i].name);
            free(agents[i].group);
        }
        free(agents);
        agents = NULL;
    }
    yaml_event_delete(&event);
    return NULL;
}

int w_read_group(yaml_parser_t * parser, remote_files_group * group) {
    yaml_event_t event;
    int i;

    // Load default values
    group->merge_file_index = -1;
    group->poll = 1800;

    if (w_move_next(parser, &event)) {
        goto error;
    }

    switch (event.type) {
    case YAML_MAPPING_START_EVENT:
        do {
            yaml_event_delete(&event);

            if (w_move_next(parser, &event)) {
                goto error;
            }

            switch (event.type) {
            case YAML_SCALAR_EVENT:
                if (!strcmp(w_read_scalar_value(&event), "files")) {

                    // Read group files
                    if (group->files = w_read_group_files(parser), !group->files) {
                        goto error;
                    }

                    // Check if the file name is merged.mg
                    for (i = 0; group->files[i].name; i++) {
                        if (!strcmp(group->files[i].name, SHAREDCFG_FILENAME)) {
                            group->merge_file_index = i;
                            break;
                        }
                    }

                } else if (!strcmp(w_read_scalar_value(&event), "poll")){
                    yaml_event_delete(&event);

                    // Read group poll
                    if (w_move_next(parser,&event)) {
                        goto error;
                    }

                    if (event.type != YAML_SCALAR_EVENT) {
                        //parser error
                        merror(W_PARSER_ERROR_EXPECTED_VALUE, "poll");
                        goto error;
                    }

                    char * end;
                    if (group->poll = strtol(w_read_scalar_value(&event), &end, 10), *end || group->poll < 0) {
                        merror(W_PARSER_POLL, w_read_scalar_value(&event));
                        goto error;
                    }
                }
                break;

            case YAML_MAPPING_END_EVENT:
                break;

            default:
                merror("Parsing error: unexpected token %d", event.type);
                goto error;
            }
        } while (event.type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(&event);
        return 0;

    default:
        merror("Parsing error: unexpected token %d", event.type);
    }

error:
    yaml_event_delete(&event);
    return -1;
}

remote_files_group * w_read_groups(yaml_parser_t * parser) {
    remote_files_group *groups;
    yaml_event_t event;
    int index = 0;

    os_calloc(1, sizeof(remote_files_group), groups);

    if (w_move_next(parser, &event)) {
        goto error;
    }

    switch (event.type) {
    case YAML_MAPPING_START_EVENT:
        do {
            yaml_event_delete(&event);

            if (w_move_next(parser, &event)) {
                goto error;
            }

            switch (event.type) {
            case YAML_SCALAR_EVENT:
                os_realloc(groups, sizeof(remote_files_group) * (index + 2), groups);
                memset(groups + index + 1, 0, sizeof(remote_files_group));
                os_strdup(w_read_scalar_value(&event), groups[index].name);

                if (w_read_group(parser, groups + index) < 0) {
                    goto error;
                }

                index++;
                break;

            case YAML_MAPPING_END_EVENT:
                break;

            default:
                merror("Parsing error: unexpected token %d", event.type);
                goto error;
            }

        } while (event.type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(&event);
        return groups;

    default:
        merror("Parsing error: unexpected token %d", event.type);
    }

error:
    if(groups)
    {
        free(groups);
        groups = NULL;
    }
    yaml_event_delete(&event);
    return NULL;
}

file * w_read_group_files(yaml_parser_t * parser) {
    file * files;
    yaml_event_t event;
    int index = 0;

    os_calloc(1, sizeof(file), files);

    if (w_move_next(parser, &event)) {
        goto error;
    }

    switch (event.type) {
    case YAML_MAPPING_START_EVENT:
        do {
            yaml_event_delete(&event);

            if (w_move_next(parser, &event)) {
                goto error;
            }

            switch (event.type) {
            case YAML_SCALAR_EVENT:
                os_realloc(files, sizeof(file) * (index + 2), files);
                memset(files + index + 1, 0, sizeof(file));
                os_strdup(w_read_scalar_value(&event), files[index].name);

                yaml_event_delete(&event);

                if (!(yaml_parser_parse(parser, &event) && event.type == YAML_SCALAR_EVENT)) {
                    merror(W_PARSER_ERROR_EXPECTED_VALUE, files[index].name);
                    goto error;
                }

                os_strdup(w_read_scalar_value(&event), files[index].url);
                index++;
                break;
            case YAML_MAPPING_END_EVENT:
                break;

            default:
                merror("Parsing error: unexpected token %d", event.type);
                goto error;
            }

        } while (event.type != YAML_MAPPING_END_EVENT);

        yaml_event_delete(&event);
        return files;

    default:
        merror("Parsing error: unexpected token %d", event.type);
        goto error;
    }

error:
    if(files)
    {
         int i;
         for(i=0;files[i].name;i++){
            free(files[i].url);
            free(files[i].name);
        }

        free(files);
        files = NULL;
    }
    yaml_event_delete(&event);
    return NULL;
}

int w_do_parsing(const char * yaml_file, remote_files_group ** agent_remote_group, agent_group ** agents_group) {
    FILE *fh = fopen(yaml_file, "r");
    yaml_parser_t parser;
    yaml_event_t  event;
    int retval = W_PARSER_ERROR;

    *agent_remote_group = NULL;
    *agents_group = NULL;

    if(fh == NULL){
      merror(W_PARSER_ERROR_FILE,yaml_file);
      return OS_FILERR;
    }

    if(!yaml_parser_initialize(&parser)){
      merror(W_PARSER_ERROR_INIT);
      fclose(fh);
      return OS_INVALID;
    }

    mdebug1(W_PARSER_STARTED,yaml_file);

    yaml_parser_set_input_file(&parser, fh);

    if (!(yaml_parser_parse(&parser, &event) && event.type == YAML_STREAM_START_EVENT)) {
        merror("Parser error %d: expecting file begin", parser.error);
        goto end;
    }

    yaml_event_delete(&event);

    if (!yaml_parser_parse(&parser, &event)) {
        merror("Parser error %d", parser.error);
        goto end;
    }

    switch (event.type) {
    case YAML_DOCUMENT_START_EVENT:
        yaml_event_delete(&event);

        if (w_move_next(&parser, &event)) {
            goto end;
        }

        switch (event.type) {
        case YAML_MAPPING_START_EVENT:
            do {
                yaml_event_delete(&event);

                if (w_move_next(&parser, &event)) {
                    goto end;
                }

                switch (event.type) {
                case YAML_SCALAR_EVENT:
                    // Read groups
                    if (!strcmp(w_read_scalar_value(&event), "groups")) {
                        if (*agent_remote_group) {
                            mwarn("Parsing '%s': redefinition of 'group'. Ignoring repeated sections", yaml_file);
                        } else {
                            if (!(*agent_remote_group = w_read_groups(&parser))) {
                                goto end;
                            }
                        }
                    } else if (!strcmp(w_read_scalar_value(&event), "agents")){
                        //Read agents
                        if (*agents_group) {
                            mwarn("Parsing '%s': redefinition of 'agent'. Ignoring repeated sections", yaml_file);
                        }
                        else {
                            if(*agents_group = w_read_agents(&parser), !*agents_group) {
                                goto end;
                            }
                        }
                    } else {
                        merror("Parsing file '%s': unexpected identifier: '%s'", yaml_file, w_read_scalar_value(&event));
                    }

                    break;
                case YAML_MAPPING_END_EVENT:
                    break;

                default:
                    merror("Parsing '%s': unexpected token %d", yaml_file, event.type);
                    goto end;
                }

            } while (event.type != YAML_MAPPING_END_EVENT);
            break;

        default:
            merror("Parsing '%s': unexpected token %d", yaml_file, event.type);
            goto end;
        }

        break;

    default:
        mwarn("Parsing '%s': file empty", yaml_file);
    }

    yaml_event_delete(&event);

    if (!(yaml_parser_parse(&parser, &event) && event.type == YAML_DOCUMENT_END_EVENT)) {
        merror("Parser error %d: expecting document end", parser.error);
        goto end;
    }

    yaml_event_delete(&event);

    if (!(yaml_parser_parse(&parser, &event) && event.type == YAML_STREAM_END_EVENT)) {
        merror("Parser error %d: expecting file end", parser.error);
        goto end;
    }

    retval = 1;

end:
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fh);
    return retval;
}

void w_free_groups(){
    int i = 0;

    if(agent_remote_group)
    {
        for(i = 0; agent_remote_group[i].name; i++){
            int j = 0;
            if(agent_remote_group[i].files){
                for(j=0;agent_remote_group[i].files[j].name;j++){
                    free(agent_remote_group[i].files[j].url);
                    free(agent_remote_group[i].files[j].name);
                }
                free(agent_remote_group[i].files);
            }
            free(agent_remote_group[i].name);
        }

        free(agent_remote_group);
    }

    if(agents_group)
    {
        for(i = 0; agents_group[i].name; i++){
            free(agents_group[i].name);
            free(agents_group[i].group);
        }

        free(agents_group);
    }

    if(ptable){
        OSHash_Free(ptable);
    }
    agent_remote_group = NULL;
    agents_group = NULL;
    ptable = NULL;
}

int w_yaml_file_has_changed()
{
    return yaml_file_date != File_DateofChange(yaml_file) || yaml_file_inode != File_Inode(yaml_file);
}

int w_yaml_file_update_structs(){

    minfo(W_PARSER_FILE_CHANGED,yaml_file);
    w_mutex_lock(&rem_yaml_mutex);
    w_free_groups();

    if (ptable = OSHash_Create(), !ptable){
        w_mutex_unlock(&rem_yaml_mutex);
        merror(W_PARSER_HASH_TABLE_ERROR);
        return OS_INVALID;
    }

    w_prepare_parsing();
    w_mutex_unlock(&rem_yaml_mutex);
    return 0;
}

void w_create_group(char *group){

    char group_path[PATH_MAX] = {0};

    if(snprintf(group_path,PATH_MAX,isChroot() ? "/etc/shared/%s" : DEFAULTDIR"/etc/shared/%s",group) >= PATH_MAX){
        mwarn(W_PARSER_GROUP_TOO_LARGE,PATH_MAX);
    }
    else{
        /* Check if group exists */
        DIR *group_dir = opendir(group_path);

        if (!group_dir) {
            /* Create the group */
            if(mkdir(group_path,0770) < 0){
                switch (errno) {
                    case EEXIST:
                        if (IsDir(group_path) < 0) {
                            merror("Couldn't make dir '%s': not a directory.", group_path);
                        }
                        break;

                    case EISDIR:
                        break;

                    default:
                        merror("Couldn't make dir '%s': %s", group_path, strerror(errno));
                        break;
                }
            } else {
                if(chmod(group_path,0770) < 0){
                    merror("Error in chmod setting permissions for path: %s",group_path);
                }
            }
        } else {
            closedir(group_dir);
        }
    }
}

int w_prepare_parsing()
{

    int parse_ok;

    // Save date and inode of the yaml file
    yaml_file_inode = File_Inode(yaml_file);
    yaml_file_date = File_DateofChange(yaml_file);

    if (yaml_file_inode != (ino_t)-1 && yaml_file_date != -1) {
        if (parse_ok = w_do_parsing(yaml_file, &agent_remote_group, &agents_group), parse_ok == 1) {
            int i = 0;

            minfo(W_PARSER_SUCCESS,yaml_file);

            // Add the groups
            if (agent_remote_group) {
                for(i = 0; agent_remote_group[i].name; i++) {
                    OSHash_Add(ptable, agent_remote_group[i].name, &agent_remote_group[i]);
                }
            }

            // Add the agents
            if (agents_group) {
                for(i = 0; agents_group[i].name; i++) {
                    OSHash_Add(ptable, agents_group[i].name, &agents_group[i]);
                }
            }
        }
    } else {
        mdebug1("Shared configuration file not found.");
        w_free_groups();
    }

    return 0;
}

int w_init_shared_download()
{
    agent_remote_group = NULL;
    agents_group = NULL;

    if (ptable = OSHash_Create(), !ptable){
        merror(W_PARSER_HASH_TABLE_ERROR);
        return OS_INVALID;
    }

    snprintf(yaml_file, OS_SIZE_1024, "%s%s/%s", isChroot() ? "" : DEFAULTDIR, SHAREDCFG_DIR, W_SHARED_YAML_FILE);
    w_prepare_parsing();

    return 0;
}
