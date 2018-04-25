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
            if (w_move_next(parser, &event)) {
                goto error;
            }

            switch (event.type) {
            case YAML_SCALAR_EVENT:
                os_realloc(agents, sizeof(agent_group) * (index + 2), agents);
                memset(agents + index + 1, 0, sizeof(agent_group));
                os_strdup(w_read_scalar_value(&event), agents[index].name);

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

        return agents;

    default:
        merror("Parsing error: unexpected token %d", event.type);
    }

error:
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
            if (w_move_next(parser, &event)) {
                goto error;
            }

            switch (event.type) {
            case YAML_SCALAR_EVENT:
                if (!strcmp(w_read_scalar_value(&event), "files")) {
                    // Read group files
                    if (group->files = w_read_group_files(parser), !group) {
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
                    // Read group poll
                    if (w_move_next(parser,&event)) {
                        goto error;
                    }

                    if (event.type != YAML_SCALAR_EVENT) {
                        //parser error
                        merror(W_PARSER_ERROR_EXPECTED_VALUE, "poll");
                        goto error;
                    }

                    group->poll = strtol(w_read_scalar_value(&event), NULL, 10);

                    if(group->poll == 0)
                    {
                        merror(W_PARSER_ZERO_POLL);
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
        
        return 0;

    default:
        merror("Parsing error: unexpected token %d", event.type);
    }

error:
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
        
        return groups;

    default:
        merror("Parsing error: unexpected token %d", event.type);
    }

error:
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
            if (w_move_next(parser, &event)) {
                goto error;
            }

            switch (event.type) {
            case YAML_SCALAR_EVENT:
                os_realloc(files, sizeof(file) * (index + 2), files);
                memset(files + index + 1, 0, sizeof(file));
                os_strdup(w_read_scalar_value(&event), files[index].name);

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

        return files;

    default:
        merror("Parsing error: unexpected token %d", event.type);
    }

error:
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

    if (!yaml_parser_parse(&parser, &event)) {
        merror("Parser error %d", parser.error);
        goto end;
    }

    switch (event.type) {
    case YAML_DOCUMENT_START_EVENT:
        if (w_move_next(&parser, &event)) {
            goto end;
        }

        switch (event.type) {
        case YAML_MAPPING_START_EVENT:
            do {
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

    if (!(yaml_parser_parse(&parser, &event) && event.type == YAML_DOCUMENT_END_EVENT)) {
        merror("Parser error %d: expecting document end", parser.error);
        goto end;
    }

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
    int parse_ok = 0;

    if (ptable = OSHash_Create(), !ptable){
        merror(W_PARSER_HASH_TABLE_ERROR);
        return OS_INVALID;
    }

    snprintf(yaml_file, OS_SIZE_1024, "%s%s/%s", isChroot() ? "" : DEFAULTDIR, SHAREDCFG_DIR, W_SHARED_YAML_FILE);
    parse_ok = w_do_parsing(yaml_file, &agent_remote_group, &agents_group);

    if(parse_ok == 1){
        int i = 0;

        minfo(W_PARSER_SUCCESS,yaml_file);

        // Add the groups
        if(agent_remote_group){
            for(i = 0; agent_remote_group[i].name; i++){
                OSHash_Add(ptable, agent_remote_group[i].name, &agent_remote_group[i]);
            }
        }

        // Add the agents
        if(agents_group){
            for(i = 0; agents_group[i].name; i++){
                OSHash_Add(ptable, agents_group[i].name, &agents_group[i]);
            }
        }
        
    }
    else{
        minfo(W_PARSER_FAILED,yaml_file);
    }

    return 0;
}
