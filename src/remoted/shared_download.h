/**
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <pthread.h>
#include "shared.h"

#define W_PARSER_ERROR -1
#define W_SHARED_YAML_FILE "files.yml"
#define W_PARSER_LOAD_ERROR "Failed to load YAML document in %s:%u"
#define W_PARSER_STARTED "Started yaml parsing of file: %s"
#define W_PARSER_SUCCESS "Successfully parsed of yaml file: %s"
#define W_PARSER_FAILED "Failed yaml parsing of file: %s"
#define W_PARSER_ERROR_INIT "Initializing yaml parser"
#define W_PARSER_ERROR_FILE "File %s not found"
#define W_PARSER_ERROR_EXPECTED_VALUE "Expected value after '%s' token"
#define W_PARSER_HASH_TABLE_ERROR "Creating OSHash"
#define W_PARSER_EXPECTED_GROUP_NAME "Expected group name after agent ID %s"
#define W_PARSER_EXPECTED_AGENT_ID "Expected agent ID"
#define W_PARSER_POLL "Wrong poll value: %s."
#define W_PARSER_FILE_CHANGED "File '%s' changed. Reloading data"
#define W_PARSER_GROUP_TOO_LARGE "The group name is too large. The maximum length is %d"

/**
 * A structure to represent files.
 */
typedef struct _sd_file {
    char *name; /**< The file's name. */
    char *url;  /**< The file's url. */
    int files_number;
} sd_file_t;

/**
 * A structure to represent groups.
 */
typedef struct _sd_group {
    char *name;                 /**< The group's name. */
    sd_file_t *files;           /**< Pointer to the _sd_file structure */
    int poll;                   /**< Time to reload the files. */
    int current_polling_time;   /**< Current time to reload the files */
    int merge_file_index;       /**< Check if the file name is merged.mg. */
    int merged_is_downloaded;   /**< Check if the merged.mg file is downloaded. */
    int groups_number;
    int n_files;
} sd_group_t;

typedef struct _sd_yaml_node {
    yaml_node_t *key;
    yaml_node_t *value;
    yaml_node_pair_t *pair_i;
    char *scalar;
} sd_yaml_node;

/**
 * A structure to represent agents.
 */
typedef struct _sd_agent {
    char *name;     /**< The agent's name. */
    char *group;    /**< The agent's group name. */
    int agents_number;
} sd_agent_t;

/**
 * A structure to represent the configuration.
 */
typedef struct _sd_config {
    unsigned int n_agents;          /**< Agents' number. */
    unsigned int n_files;           /**< Files' number. */
    sd_agent_t *agents;             /**< Pointer to sd_agent_t structure. */
    unsigned int n_groups;          /**< Group's number. */
    sd_group_t *groups;             /**< Pointer to sd_group_t structure. */
    char file[OS_SIZE_1024 + 1];    /**< YAML file. */
    time_t file_date;               /**< Controll file's date modifications. */
    ino_t file_inode;               /** File serial number. **/
    OSHash *ptable;                 /**< Pointer to ptable structure. */
    pthread_mutex_t mutex;          /**< Thread lock. */
    char file_path[PATH_MAX];       /**< File path. */
} sd_config_t;



/** 
 * @brief It initializes the configuration struct to 0,
 * creates the Hash table and initializes the lock.
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 0 if the Hash table creatin wasn't successful and
 * @c 1 in other case.
 */
int sd_init(sd_config_t **config);

/**
 * @brief
 * 
 * @returns
 */
int sd_load(sd_config_t **config/*, const char *filepath*/);

/**
 * @brief It checks if the yaml file has changed.
 * 
 * @param config The shared download configuration.
 *
 * @returns @c 1 if the file has changed or @c 0 in other case.
 */
int sd_file_changed(sd_config_t *config);

/**
 * @brief It deallocates the memory previously allocated 
 * from our configuration and destroy the lock.
 * 
 * @param config The shared download configuration.
 * 
 * @post It deallocates the memory previously allocated 
 * from our configuration and destroy de lock.
 */
void sd_destroy(sd_config_t **config);

/**
 * @brief It deallocates the memory previously allocated. 
 * 
 * @param config The shared download configuration.
 * 
 * @post It deallocates the memory previously allocated from our configuration.
 */
void sd_destroy_content(sd_config_t **config);

/**
 * @brief We get a pointer to the sd_group_t structure.
 * 
 * @param config The shared download configuration.
 * 
 * @param name The group's name.
 * 
 * @returns A pointer to the sd_group_t structure from our configuration.
 */
sd_group_t *sd_get_group(sd_config_t *config, const char *name);

/**
 * @brief We get a pointer to the sd_agent_t structure.
 * 
 * @param config The shared download configuration.
 * 
 * @param name The agent's name.
 * 
 * @returns A pointer to the sd_agent_t structure from our configuration.
 */
sd_agent_t *sd_get_agent(sd_config_t *config, const char *name);

/**
 * @brief It reloads the file's configuration
 * in case it was changed and the parse was
 * successfully. 
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 1 in case it was successfully, 
 * @c 0 in other case.
 */
int sd_reload(sd_config_t **config);

void sd_add_agent(sd_config_t **config);

void sd_add_group(sd_config_t **config);

void sd_create_directory(char *group);

void sd_create_groups(sd_group_t *groups);

/**
 * @brief Checks if our files' parse was successful.
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 1 if files' parse was successful and @c 0 in other case.
 */
char *sd_get_scalar(yaml_node_t *data);

/**
 * @brief We get the scalar value of a yaml node.
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 1 if files' parse was successful and @c 0 in other case.
 */
int sd_parse_files(yaml_document_t * document, yaml_node_t *root_node, sd_file_t **files);

/**
 * @brief Checks if our files' parse was successful.
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 1 if files' parse was successful and @c 0 in other case.
 */
int sd_parse_poll(yaml_node_t *root_node, sd_group_t **group);

/**
 * @brief Checks if our files' parse was successful. 
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 1 if files' parse was successful and @c 0 in other case.
 */
int sd_parse_groups(yaml_document_t * document, yaml_node_t *root_node, sd_group_t **groups);

/**
 * @brief Checks if our files' parse was successful.
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 1 if files' parse was successful and @c 0 in other case.
 */
int sd_parse_agents(yaml_document_t *document, yaml_node_t *root_node, sd_agent_t **agents);

/**
 * @brief Checks if our files' parse was successful.
 * 
 * @param config The shared download configuration.
 * 
 * @returns @c 1 if files' parse was successful and @c 0 in other case.
 */
int sd_parse(sd_config_t **config);

#endif /* __SHARED_DOWNLOAD_H */
