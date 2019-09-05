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

/* Internal functions prototypes */
static void sd_move(sd_config_t **config, sd_config_t **config_cp);

/*
    El problema que tengo ahora mismo es que los libros del segundo grupo
    los interpreta como si fueran del primero :(
    A parte, es el único que se descarga.
    El problema lo tengo con el "index". Es 0 al entrar en la función y nos lo cargamos todo.
    
    2019/09/04 16:59:09 ossec-remoted: ERROR: Invalid shared file 'book.pdf' in group 'my_group_1'. Ignoring it.
*/

int sd_init(sd_config_t **config) {
 
    *config = NULL;
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

void sd_add_agent(sd_config_t **config) {
    if ((*config)->agents) {
        for(int i = 0; (*config)->agents[i].name; i++) {
            OSHash_Add((*config)->ptable, (*config)->agents[i].name, &(*config)->agents[i]);
        }
    }
}

void sd_add_group(sd_config_t **config) {
    if ((*config)->groups) {
        for (int i = 0; (*config)->groups[i].name; i++) {
            OSHash_Add((*config)->ptable, (*config)->groups[i].name, &(*config)->groups[i]);
        }
    }
}

void sd_create_groups(sd_group_t *groups) {
    if (groups) {
        for(int i = 0; groups[i].name; i++) {
            sd_create_directory(groups->name);
        }
    }
}

void sd_create_directory(char *group) {
    
    char group_path[PATH_MAX] = { 0 };

    if(snprintf(group_path, PATH_MAX,isChroot() ? "/etc/shared/%s" : DEFAULTDIR"/etc/shared/%s", group) >= PATH_MAX) {
        mwarn(W_PARSER_GROUP_TOO_LARGE, PATH_MAX);
    }
    else{
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
}

char *sd_get_scalar(yaml_node_t *data) {
    return (char *)data->data.scalar.value;
}

int sd_parse_files(yaml_document_t * document, yaml_node_t *root_node, sd_file_t **files) {
    sd_yaml_node yaml_node;
    static int index = 0;

    if (!*files) {
        os_calloc(1, sizeof(sd_file_t), *files);
        (*files)->files_number = 0;
    }

    if (root_node->type == YAML_MAPPING_NODE) {
        for (yaml_node.pair_i = root_node->data.mapping.pairs.start; yaml_node.pair_i < root_node->data.mapping.pairs.top; ++yaml_node.pair_i) {
            yaml_node.key = yaml_document_get_node(document, yaml_node.pair_i->key);
            yaml_node.value = yaml_document_get_node(document, yaml_node.pair_i->value);

            if (yaml_node.value->type == YAML_SCALAR_NODE) {

                yaml_node.scalar = sd_get_scalar(yaml_node.key);

                os_realloc(*files, sizeof(sd_file_t) * (index + 2), *files);
                memset(*files + index + 1, 0, sizeof(sd_file_t));
                os_strdup(yaml_node.scalar, (*files)[index].name);
                (*files)->files_number++;

                yaml_node.scalar = sd_get_scalar(yaml_node.value);

                os_strdup(yaml_node.scalar, (*files)[index].url);
                index++;
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

int sd_parse_poll(yaml_node_t *root_node, sd_group_t **group) {
    char *scalar;
    char *end;

    (*group)->poll = 1800;

    if (root_node->type == YAML_SCALAR_NODE) {
        scalar = sd_get_scalar(root_node); 

        if ((*group)->poll = strtol(scalar, &end, 10), *end || (*group)->poll < 0) {
            merror(W_PARSER_POLL, scalar);
            return 0;
        }
    }

    return 1;
}

int sd_parse_groups(yaml_document_t * document, yaml_node_t *root_node, sd_group_t **groups) {
    sd_yaml_node yaml_node;
    sd_yaml_node yaml_node_map;
    int index = 0;

    if (!*groups) {
        os_calloc(1, sizeof(sd_group_t), *groups);
        (*groups)->groups_number = 0;
    }
    
    (*groups)->merge_file_index = -1;
    
    if (root_node->type == YAML_MAPPING_NODE) {
        for (yaml_node.pair_i = root_node->data.mapping.pairs.start; 
                yaml_node.pair_i < root_node->data.mapping.pairs.top; ++yaml_node.pair_i) {
            yaml_node.key = yaml_document_get_node(document, yaml_node.pair_i->key);
            yaml_node.value = yaml_document_get_node(document, yaml_node.pair_i->value);

            yaml_node.scalar = sd_get_scalar(yaml_node.key);

            (*groups)->groups_number++;
            os_realloc(*groups, sizeof(sd_group_t) * (index + 2), *groups);
            memset(*groups + index + 1, 0, sizeof(sd_group_t));
            os_strdup(yaml_node.scalar, (*groups)[index].name);

            index++;

            if (yaml_node.value->type == YAML_MAPPING_NODE) {
                for(yaml_node_map.pair_i = yaml_node.value->data.mapping.pairs.start; 
                        yaml_node_map.pair_i < yaml_node.value->data.mapping.pairs.top; ++yaml_node_map.pair_i) {
                    yaml_node_map.key = yaml_document_get_node(document, yaml_node_map.pair_i->key);
                    yaml_node_map.value = yaml_document_get_node(document, yaml_node_map.pair_i->value);

                    yaml_node.scalar = sd_get_scalar(yaml_node_map.key);

                    if (!strcmp(yaml_node.scalar, "files")) {
                        if (!sd_parse_files(document, yaml_node_map.value, &(*groups)->files)) {
                            return 0;
                        } else {
                            // Check if the file name is merged.mg
                            for (int i = 0; (*groups)->files[i].name; i++) {
                                if (!strcmp((*groups)->files[i].name, SHAREDCFG_FILENAME)) {
                                    (*groups)->merge_file_index = i;
                                    break;
                                }
                            }
                        }
                    } else if (!strcmp(yaml_node.scalar, "poll")) {
                        if (!sd_parse_poll(yaml_node_map.value, &(*groups))) {
                            return 0;
                        }
                        
                    } else {
                        merror("Parsing error on line %d:, unknown token '%s'", (unsigned int)yaml_node.value->start_mark.line, yaml_node.scalar);
                        return 0;
                    }
                }      
            } else {
                merror("Node must be mapping (line %u)Could't parse groups", (unsigned int)root_node->start_mark.line);
                return 0;
            }
        }
    } else {
        merror("Node must be mapping (line %u). Could't parse groups", (unsigned int)root_node->start_mark.line);
        return 0;
    }
    return 1;
}

int sd_parse_agents(yaml_document_t *document, yaml_node_t *root_node, sd_agent_t **agents) {
    sd_yaml_node yaml_node;
    int index = 0;

    if (!*agents) {
        os_calloc(1, sizeof(sd_agent_t), *agents);
        (*agents)->agents_number = 0;
    }

    if (root_node->type == YAML_MAPPING_NODE) {
        for (yaml_node.pair_i = root_node->data.mapping.pairs.start; 
                yaml_node.pair_i < root_node->data.mapping.pairs.top; ++yaml_node.pair_i) {
            yaml_node.key = yaml_document_get_node(document, yaml_node.pair_i->key);
            yaml_node.value = yaml_document_get_node(document, yaml_node.pair_i->value);
            
            yaml_node.scalar = sd_get_scalar(yaml_node.key);

            (*agents)->agents_number++;
            os_realloc(*agents, sizeof(sd_agent_t) * (index + 2), *agents);
            memset(*agents + index + 1, 0, sizeof(sd_agent_t));
            os_strdup(yaml_node.scalar, (*agents)[index].name);

            yaml_node.scalar = sd_get_scalar(yaml_node.value);

            os_strdup(yaml_node.scalar, (*agents)[index].group);
            index++;
        }
    } else {
        merror("Node must be mapping (line %u). Couldn't parse agents", (unsigned int)root_node->start_mark.line);
        return 0;
    }
    return 1;
}

int sd_parse(sd_config_t **config) {
    FILE *fh;
    yaml_node_t *root_node;
    sd_yaml_node yaml_node;
    yaml_parser_t parser;
    yaml_document_t document;

    int index = 0;

    if (fh = fopen((*config)->file, "rb"), !fh) {
        merror(W_PARSER_ERROR_FILE, (*config)->file);
        return 0;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fh);

    if (!yaml_parser_load(&parser, &document)) {
        merror("Failed to load YAML document in %s:%u", (*config)->file, (unsigned int)parser.problem_mark.line);
        return 0;
    }

    if (root_node = yaml_document_get_root_node(&document), !root_node) {
        merror("No YAML document defined in %s: ", (*config)->file);
        return 0;
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
                        mwarn("Parsing '%s': redefinition of 'group'. Ignoring repeated sections", (*config)->file);
                    } else {
                        if (!sd_parse_groups(&document, yaml_node.value, &(*config)->groups)) {
                            return 0;
                        }
                    }
                } else if (!strcmp(yaml_node.scalar, "agents")) {
                    if (!sd_parse_agents(&document, yaml_node.value, &(*config)->agents)) {
                        return 0;
                    }
                } else {
                    merror("Parsing error on line %d:, unknown token '%s'", (unsigned int)yaml_node.value->start_mark.line, yaml_node.scalar);
                    return 0;
                }       
            } else {
                merror("Mapping key must be scalar (line %u)", (unsigned int)yaml_node.key->start_mark.line);
                return 0;
            }
        }
    } else {
        merror("Root node must be mapping (line %u)", (unsigned int)root_node->start_mark.line);
        return 0;
    }

    yaml_parser_delete(&parser);
    yaml_document_delete(&document);
    fclose(fh);
    return 1;
}

int sd_load(sd_config_t **config) {

    snprintf((*config)->file, OS_SIZE_1024, "%s%s/%s", isChroot() ? "" : DEFAULTDIR, SHAREDCFG_DIR, W_SHARED_YAML_FILE);

    /* Save date and inode of the yaml file */
    (*config)->file_inode = File_Inode((*config)->file);
    (*config)->file_date = File_DateofChange((*config)->file);

    if ((*config)->file_inode != (ino_t) -1 && (*config)->file_date != -1) {
        if (sd_parse(&(*config))) {

            /* Add group and agent to the HASH table */
            sd_add_group(&(*config));
            sd_add_agent(&(*config));

            return 1;

        } else {
            merror("Parse error");
            return 0;
        }
    } else {
        mdebug1("Shared configuration file not found.");
        //¿Liberar?
        return 0;
    }
}

void sd_destroy(sd_config_t **config) {
    sd_destroy_content(&(*config));
    w_mutex_destroy(&(*config)->mutex);
    os_free((*config));
}

void sd_destroy_content(sd_config_t **config) {
    
    if ((*config)->agents) {
        for (int i = 0; i < (*config)->agents->agents_number; i++) {
            os_free((*config)->agents[i].name);
            os_free((*config)->agents[i].group);
        }
        os_free((*config)->agents);
    }

    if ((*config)->groups) {
        for (int i = 0; i < (*config)->groups->groups_number; i++) {
            
            for (int j = 0; j < (*config)->groups->files->files_number; j++) {
                free((*config)->groups[i].files[j].name);
                free((*config)->groups[i].files[j].url);
            }
            free((*config)->groups[i].files);
            free((*config)->groups[i].name);
        }
        os_free((*config)->groups);
    }

    if ((*config)->ptable) {
        OSHash_Free((*config)->ptable);
        (*config)->ptable = NULL;
    }
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

int sd_reload(sd_config_t **config) {
    sd_config_t *config_tmp = NULL;

    if (sd_init(&config_tmp)) {
        if (sd_load(&config_tmp)) {
            sd_move(&(*config), &config_tmp);
        } else {
            (*config)->file_date = config_tmp->file_date;
            (*config)->file_inode = config_tmp->file_inode;
        }
    }
    
    return 0;
}

int sd_file_changed(sd_config_t *config) {
    return config->file_date != File_DateofChange(config->file) || config->file_inode != File_Inode(config->file);
}

static void sd_move(sd_config_t **config, sd_config_t **config_cp) {
    w_mutex_lock(&(*config)->mutex);

    //sd_destroy_content(config);
    /*int index = 0;
    os_calloc(1, sizeof(sd_config_t), *config);
    os_realloc(*config, sizeof(sd_config_t) * (index + 2), *config);
    os_calloc(1, sizeof(sd_group_t), (*config)->groups);
    os_realloc((*config)->groups, sizeof(sd_config_t) * (index + 2), (*config)->groups);
    os_calloc(1, sizeof(sd_agent_t), (*config)->agents);
    os_realloc((*config)->agents, sizeof(sd_agent_t) * (index + 2), (*config)->agents);
    os_calloc(1, sizeof(sd_file_t), (*config)->groups->files);
    os_realloc((*config)->groups->files, sizeof(sd_file_t) * (index + 2), (*config)->groups->files);*/

    //sd_destroy_content(config);
    (*config)->groups->groups_number = (*config_cp)->groups->groups_number;
    (*config)->groups->files->files_number = (*config_cp)->groups->files->files_number;
    (*config)->agents->agents_number = (*config_cp)->agents->agents_number;
    (*config)->file_date = (*config_cp)->file_date;
    (*config)->file_inode = (*config_cp)->file_inode;
    
    /* Copy groups */
    for (int i = 0; i < (*config)->groups->groups_number; i++) {
        for (int j = 0; j < (*config)->groups->files->files_number; j++) {
                (*config)->groups[i].files[j].name = (*config_cp)->groups[i].files[j].name;
                (*config)->groups[i].files[j].url = (*config_cp)->groups[i].files[j].url;
        }
        (*config)->groups[i].files = (*config_cp)->groups[i].files; 
        (*config)->groups[i].name = (*config_cp)->groups[i].name;
    }
    (*config)->groups = (*config_cp)->groups;

    /* Copy agents */
    for (int i = 0; i < (*config)->agents->agents_number; i++) {
        (*config)->agents[i].name = (*config_cp)->agents[i].name;
        (*config)->agents[i].group = (*config_cp)->agents[i].group;
    }
    (*config)->agents = (*config_cp)->agents;
    
    /* Copy Hash */
    (*config)->ptable = OSHash_Duplicate((*config_cp)->ptable);

    //sd_destroy_content(config_cp);

    w_mutex_unlock(&(*config)->mutex);    
}
