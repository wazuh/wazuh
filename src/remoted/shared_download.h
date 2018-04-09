/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2018 Wazuh Inc.
 * April 3, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __SHARED_DOWNLOAD_H
#define __SHARED_DOWNLOAD_H

#include <external/libyaml/include/yaml.h>

#define W_PARSER_ERROR -1
#define W_SHARED_YAML_FILE "files.yml"
#define W_PARSER_STARTED "Started yaml parsing of file: %s"
#define W_PARSER_SUCCESS "Successfully parsed of yaml file: %s"
#define W_PARSER_FAILED "Failed yaml parsing of file: %s"
#define W_PARSER_ERROR_INIT "Initializing yaml parser"
#define W_PARSER_ERROR_FILE "File %s not found"
#define W_PARSER_ERROR_EXPECTED_VALUE "Expected value after '%s' token"
#define W_PARSER_HASH_TABLE_ERROR "Creating OSHash"
#define W_PARSER_EXPECTED_GROUP_NAME "Expected group name after agent ID %s"
#define W_PARSER_EXPECTED_AGENT_ID "Expected agent ID"

typedef struct _file{
    char *name;
    char *url;
} file;
  
typedef struct _files_group{
    char *name;
    file *file;
    int num_files;
} files_group;

typedef struct _remote_files_group{
    char *name;
    files_group *files_group;
    int poll;
    int current_polling_time;
    int merge_file_index;
    int merged_is_downloaded;
} remote_files_group;

typedef struct _agent_group{
    char *name;
    char *group;
    char *url;
} agent_group;  

void *w_parser_get_group(const char *name);
void *w_parser_get_agent(const char *name);
const char *w_read_scalar_value(yaml_event_t * event);
int w_move_next(yaml_parser_t * parser,yaml_event_t * event);
int w_read_agents(yaml_parser_t * parser,yaml_event_t * event,agent_group **agents_group,int *num_agents_readed);
int w_read_group_files(yaml_parser_t * parser,yaml_event_t * event,remote_files_group *agent_remote_group);
int w_do_parsing(remote_files_group **agent_remote_group,int *num_groups_readed,const char *yaml_file,agent_group **agents_group,int *num_agents_readed);
void w_free_groups();
int w_init_shared_download();

#endif /* __SHARED_DOWNLOAD_H */
