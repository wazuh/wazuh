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

#include "shared_download.h"
#include "shared.h"

/** 
 * @brief It deallocates config memory and make it points
 * to config_tmp structure.
 * 
 * @param config The shared download configuration.
 * @param config_tmp The temporal shared download configuration.
 */
static void sd_move(sd_config_t **config, sd_config_t **config_tmp);

int sd_init(sd_config_t **config) {

    os_calloc(1, sizeof(sd_config_t), *config);
    (*config)->agents = NULL;
    (*config)->groups = NULL;
    (*config)->ptable = NULL;

    if ((*config)->ptable = OSHash_Create(), !(*config)->ptable) {
        merror(W_PARSER_HASH_TABLE_ERROR);
        return 0;
    }

    (*config)->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    return 1;
}

sd_group_t *sd_get_group(sd_config_t *config, const char *name) {
    sd_group_t *group = NULL;

    w_mutex_lock(&config->mutex);

    if (config->ptable) {
        group = OSHash_Get(config->ptable, name);
    }

    w_mutex_unlock(&config->mutex);
    return group;
}

sd_agent_t *sd_get_agent(sd_config_t *config, const char *name) {
    sd_agent_t *agent = NULL;

    w_mutex_lock(&config->mutex);

    if (config->ptable) {
        agent = OSHash_Get(config->ptable, name);
    }

    w_mutex_unlock(&config->mutex);
    return agent;
}

void sd_add_agent(sd_config_t *config) {
    int i;

    if (config->agents) {
        for (i = 0; i < config->n_agents; i++) {
            OSHash_Add(config->ptable, config->agents[i].name, &config->agents[i]);
        }
    }
}

void sd_add_group(sd_config_t *config) {
    int i;

    if (config->groups) {
        for (i = 0; i < config->n_groups; i++) {
            OSHash_Add(config->ptable, config->groups[i].name, &config->groups[i]);
        }
    }
}

void sd_create_groups_directory(sd_config_t *config) {
    int i;

    if (config->groups) {
        for (i = 0; i < config->n_groups; i++) {
            sd_create_directory(config->groups[i].name);
        }
    }
}

void sd_create_directory(char *group) {

    char group_path[PATH_MAX] = { 0 };

    if(snprintf(group_path, PATH_MAX,isChroot() ? "/etc/shared/%s" : DEFAULTDIR"/etc/shared/%s", group) >= PATH_MAX) {
        mwarn(W_PARSER_GROUP_TOO_LARGE, PATH_MAX);
        return;
    }

    /* Check if group exists */
    DIR *group_dir = opendir(group_path);

    if (!group_dir) {
        /* Create the group */
        if(mkdir(group_path,0770) < 0) {
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
            if(chmod(group_path,0770) < 0) {
                merror("Error in chmod setting permissions for path: %s",group_path);
            }
        }
    } else {
        closedir(group_dir);
    }
}

char *sd_get_scalar(yaml_node_t *data) {
    return (char *)data->data.scalar.value;
}

int sd_parse_files(yaml_document_t * document, yaml_node_t *root_node, sd_file_t **files, int *n_files) {
    sd_yaml_node yaml_node;
    int index = 0;
    *n_files = 0;

    os_calloc(1, sizeof(sd_file_t), *files);

    if (root_node->type == YAML_MAPPING_NODE) {
        for (yaml_node.pair_i = root_node->data.mapping.pairs.start; yaml_node.pair_i < root_node->data.mapping.pairs.top; ++yaml_node.pair_i) {
            yaml_node.key = yaml_document_get_node(document, yaml_node.pair_i->key);
            yaml_node.value = yaml_document_get_node(document, yaml_node.pair_i->value);

            if (yaml_node.value->type == YAML_SCALAR_NODE) {

                yaml_node.scalar = sd_get_scalar(yaml_node.key);

                os_realloc(*files, sizeof(sd_file_t) * (index + 2), *files);
                memset(*files + index + 1, 0, sizeof(sd_file_t));
                os_strdup(yaml_node.scalar, (*files)[index].name);

                yaml_node.scalar = sd_get_scalar(yaml_node.value);

                os_strdup(yaml_node.scalar, (*files)[index].url);

                if (!strcmp(yaml_node.scalar, "")) {
                    mwarn("Expected value after '%s' token. Ignoring it", (*files)[index].name);
                }

                index++;
                *n_files += 1;

            } else {
                merror("Mapping key must be scalar (line %u)", (unsigned int)yaml_node.key->start_mark.line);
                return 0;
            }
        }
    } else {
        merror("Node must be mapping (line %u). Could't parse groups", (unsigned int)root_node->start_mark.line);
        return 0;
    }
    return 1;
}

int sd_parse_poll(yaml_node_t *root_node, sd_group_t *group) {
    group->poll_download_rate = 1800;
    if (root_node->type == YAML_SCALAR_NODE) {
        char *scalar = sd_get_scalar(root_node); 
        char *end;
        if (group->poll_download_rate = strtol(scalar, &end, 10), *end || group->poll_download_rate < 0) {
            merror(W_PARSER_POLL, scalar);
            return 0;
        }
    }
    return 1;
}

int sd_parse_group(yaml_document_t *document, yaml_node_t *root_node, sd_group_t *group) {
    sd_yaml_node yaml_node_map;
    int i;

    group->merge_file_index = -1;

    for (yaml_node_map.pair_i = root_node->data.mapping.pairs.start; 
                        yaml_node_map.pair_i < root_node->data.mapping.pairs.top;
                         ++yaml_node_map.pair_i) 
    {
        yaml_node_map.key = yaml_document_get_node(document, yaml_node_map.pair_i->key);
        yaml_node_map.value = yaml_document_get_node(document, yaml_node_map.pair_i->value);

        yaml_node_map.scalar = sd_get_scalar(yaml_node_map.key);

        if (!strcmp(yaml_node_map.scalar, "files")) {

            if (!sd_parse_files(document, yaml_node_map.value, &(group->files), &(group->n_files))) {
                return 0;
            } else {

                // Check if the file name is merged.mg
                for (i = 0; i < group->n_files; i++) {
                    if (!strcmp(group->files[i].name, SHAREDCFG_FILENAME)) {
                        group->merge_file_index = i;
                        break;
                    }
                }
            }

        } else if (!strcmp(yaml_node_map.scalar, "poll")) {
            if (!sd_parse_poll(yaml_node_map.value, group)) {
                return 0;
            }
        } else {
            merror("Parsing error on line %d:, unknown token '%s'", (unsigned int)yaml_node_map.value->start_mark.line, yaml_node_map.scalar);
            return 0;
        }
    }
    return 1;
}

int sd_parse_groups(yaml_document_t * document, yaml_node_t *root_node, sd_group_t **groups, int *n_groups) {
    sd_yaml_node yaml_node;

    if (!*groups) {
        os_calloc(1, sizeof(sd_group_t), *groups);
        *n_groups = 0;
    }

    int index = 0;
    if (root_node->type == YAML_MAPPING_NODE) {
        for (yaml_node.pair_i = root_node->data.mapping.pairs.start; 
                yaml_node.pair_i < root_node->data.mapping.pairs.top; ++yaml_node.pair_i) {

            yaml_node.key = yaml_document_get_node(document, yaml_node.pair_i->key);
            yaml_node.value = yaml_document_get_node(document, yaml_node.pair_i->value);

            yaml_node.scalar = sd_get_scalar(yaml_node.key);

            os_realloc(*groups, sizeof(sd_group_t) * (index + 2), *groups);
            memset(&(*groups)[index + 1], 0, sizeof(sd_group_t));
            os_strdup(yaml_node.scalar, (*groups)[index].name);

            if (yaml_node.value->type == YAML_MAPPING_NODE) {
                if(!sd_parse_group(document, yaml_node.value, *groups + index)) {
                    return 0;
                }
            } else {
                merror("Node must be mapping (line %u)Could't parse groups", (unsigned int)root_node->start_mark.line);
                return 0;
            }

            ++index;
            *n_groups += 1;
        }
    } else {
        merror("Node must be mapping (line %u). Could't parse groups", (unsigned int)root_node->start_mark.line);
        return 0;
    }
    return 1;
}

int sd_parse_agents(yaml_document_t *document, yaml_node_t *root_node, sd_agent_t **agents, int *n_agents) {
    sd_yaml_node yaml_node;
    int index = 0;

    if (!*agents) {
        os_calloc(1, sizeof(sd_agent_t), *agents);
        *n_agents = 0;  
    }

    if (root_node->type == YAML_MAPPING_NODE) {
        for (yaml_node.pair_i = root_node->data.mapping.pairs.start; 
                yaml_node.pair_i < root_node->data.mapping.pairs.top; ++yaml_node.pair_i) {
            yaml_node.key = yaml_document_get_node(document, yaml_node.pair_i->key);
            yaml_node.value = yaml_document_get_node(document, yaml_node.pair_i->value);

            yaml_node.scalar = sd_get_scalar(yaml_node.key);

            os_realloc(*agents, sizeof(sd_agent_t) * (index + 2), *agents);
            memset(*agents + index + 1, 0, sizeof(sd_agent_t));
            os_strdup(yaml_node.scalar, (*agents)[index].name);

            yaml_node.scalar = sd_get_scalar(yaml_node.value);

            if (!strcmp(yaml_node.scalar, "")) {
                mwarn("Expected value after '%s' token. Ignoring it", (*agents)[index].name);
            }

            os_strdup(yaml_node.scalar, (*agents)[index].group);

            index++;
            *n_agents += 1;
        }
    } else {
        merror("Node must be mapping (line %u). Couldn't parse agents", (unsigned int)root_node->start_mark.line);
        return 0;
    }
    return 1;
}

int sd_parse(sd_config_t **config) {
    FILE *config_file;
    yaml_node_t *root_node;
    sd_yaml_node yaml_node;
    yaml_parser_t parser;
    yaml_document_t document;

    int ret_val = 0;
    int index = 0;

    if (config_file = fopen((*config)->file_name, "rb"), !config_file) {
        merror(W_PARSER_ERROR_FILE, (*config)->file_name);
        return 0;
    }

    if (!yaml_parser_initialize(&parser)) {
        merror(W_PARSER_ERROR_INIT);
        fclose(config_file);
        return 0;
    }

    mdebug1(W_PARSER_STARTED, (*config)->file_name);

    yaml_parser_set_input_file(&parser, config_file);

    if (!yaml_parser_load(&parser, &document)) {
        merror(W_PARSER_FAILED" line: %u", (*config)->file_name, (unsigned int)parser.problem_mark.line);
        goto end;
    }

    if (root_node = yaml_document_get_root_node(&document), !root_node) {
        merror("No YAML document defined in %s: ", (*config)->file_name);
        goto end;
    }

    if (root_node->type == YAML_MAPPING_NODE) {
        for (yaml_node.pair_i = root_node->data.mapping.pairs.start; 
                yaml_node.pair_i < root_node->data.mapping.pairs.top; ++yaml_node.pair_i) {
            yaml_node.key = yaml_document_get_node(&document, yaml_node.pair_i->key);
            yaml_node.value = yaml_document_get_node(&document, yaml_node.pair_i->value);

            if (yaml_node.key->type == YAML_SCALAR_NODE) {
                yaml_node.scalar = sd_get_scalar(yaml_node.key);

                os_realloc((*config), sizeof(sd_config_t) * (index + 2), (*config));
                memset((*config) + index + 1, 0, sizeof(sd_config_t));
                index++;
 
                if (!strcmp(yaml_node.scalar, "groups")) {
                    if ((*config)->groups) {
                        mwarn("Parsing '%s': redefinition of 'groups'. Ignoring repeated sections", (*config)->file_name);
                    } else {
                        if (!sd_parse_groups(&document, yaml_node.value, &(*config)->groups, &(*config)->n_groups)) {
                            goto end;
                        }
                    }
                } else if (!strcmp(yaml_node.scalar, "agents")) {
                    if ((*config)->agents) {
                        mwarn("Parsing '%s': redefinition of 'agents'. Ignoring repeated sections", (*config)->file_name);
                    } else {
                        if (!sd_parse_agents(&document, yaml_node.value, &(*config)->agents, &(*config)->n_agents)) {
                            goto end;
                        }
                    }
                } else {
                    merror("Parsing error on line %d:, unknown token '%s'", (unsigned int)yaml_node.value->start_mark.line, yaml_node.scalar);
                    goto end;
                }       
            } else {
                merror("Mapping key must be scalar (line %u)", (unsigned int)yaml_node.key->start_mark.line);
                goto end;
            }
        }
    } else {
        merror("Root node must be mapping (line %u)", (unsigned int)root_node->start_mark.line);
        goto end;
    }

    ret_val = 1;

end:
    yaml_parser_delete(&parser);
    yaml_document_delete(&document);
    fclose(config_file);
    return ret_val;
}

int sd_load(sd_config_t **config) {

    snprintf((*config)->file_name, OS_SIZE_1024, "%s%s/%s", isChroot() ? "" : DEFAULTDIR, SHAREDCFG_DIR, W_SHARED_YAML_FILE);

    /* Save date and inode of the yaml file */
    (*config)->file_inode = File_Inode((*config)->file_name);
    (*config)->file_date = File_DateofChange((*config)->file_name);

    if ((*config)->file_inode != (ino_t) -1 && (*config)->file_date != -1) {
        if (sd_parse(&(*config))) {

            minfo(W_PARSER_SUCCESS, (*config)->file_name);

            /* Add group and agent to the HASH table */
            sd_add_group(*config);
            sd_add_agent(*config);

            if (!(*config)->checked_url_connection) {
                check_download_module_connection();
                (*config)->checked_url_connection = 1;
            }
            return 1;

        } else {
            return 0;
        }
    } else {
        mdebug1("Shared configuration file not found.");
        sd_destroy_content(config);
        return 0;
    }
}

void sd_destroy_content(sd_config_t **config) {
    int i;
    int j;

    if ((*config)->agents) {
        for (i = 0; i < (*config)->n_agents; i++) {
            os_free((*config)->agents[i].name);
            os_free((*config)->agents[i].group);
        }
        os_free((*config)->agents);
    }

    if ((*config)->groups) {
        for (i = 0; i < (*config)->n_groups; i++) {
            for (j = 0; j < (*config)->groups[i].n_files; j++) {
                os_free((*config)->groups[i].files[j].name);
                os_free((*config)->groups[i].files[j].url);
            }
            os_free((*config)->groups[i].files);
            os_free((*config)->groups[i].name);
        }
        os_free((*config)->groups);
    }

    if ((*config)->ptable) {
        OSHash_Free((*config)->ptable);
        (*config)->ptable = NULL;
    }

    os_free(*config);
}

int sd_reload(sd_config_t **config) {
    minfo(W_PARSER_FILE_CHANGED, (*config)->file_name);
    sd_config_t *config_tmp = NULL;

    if (sd_init(&config_tmp)) {
        if (sd_load(&config_tmp)) {
            sd_move(&(*config), &config_tmp);
        } else {
            (*config)->file_date = config_tmp->file_date;
            (*config)->file_inode = config_tmp->file_inode;
            sd_destroy_content(&config_tmp);
        }
    }
    return 0;
}

int sd_file_changed(sd_config_t *config) {
    return config->file_date != File_DateofChange(config->file_name) || config->file_inode != File_Inode(config->file_name);
}

void check_download_module_connection() {
    int i;

    for (i = SOCK_ATTEMPTS; i > 0; --i) {
        if (wurl_check_connection() == 0) {
            break;
        } else {
            mdebug2("Download module not yet available. Remaining attempts: %d", i - 1);
            sleep(1);
        }
    }

    if (i == 0) {
        merror("Cannot connect to the download module socket. External shared file download is not available.");
    }
}

static void sd_move(sd_config_t **config, sd_config_t **config_tmp) {
    w_mutex_lock(&(*config)->mutex);

    sd_destroy_content(config);
    *config = *config_tmp;

    w_mutex_unlock(&(*config)->mutex);    
}
