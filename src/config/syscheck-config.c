/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck-config.h"
#include "config.h"

/* Extract the value (one or multiples paths) from environment variable */
static char **get_paths_from_env_variable (char *environment_variable);
/* Used for options nodiff_regex and ignore_regex */
static int process_option_regex(char *option, OSMatch ***syscheck_option, xml_node *node);
/* Used for options ignore and nodiff */
static void process_option(char ***syscheck_option, xml_node *node);
/* Set check_all options in a directory/file */
static void fim_set_check_all(int *opt);

directory_t *fim_create_directory(const char *path,
                                  int options,
                                  const char *filerestrict,
                                  int recursion_level,
                                  const char *tag,
                                  int diff_size_limit,
                                  unsigned int is_wildcard) {
    directory_t *new_entry;

    os_calloc(1, sizeof(directory_t), new_entry);

    new_entry->options = options;
    new_entry->diff_size_limit = diff_size_limit;
    new_entry->recursion_level = recursion_level;
    os_strdup(path, new_entry->path);
    new_entry->is_wildcard = is_wildcard;
    new_entry->is_expanded = 0;

#ifndef WIN32
    if (CHECK_FOLLOW & options) {
        new_entry->symbolic_links = realpath(new_entry->path, NULL);
    }
#endif
    if (filerestrict) {
        os_calloc(1, sizeof(OSMatch), new_entry->filerestrict);
        if (!OSMatch_Compile(filerestrict, new_entry->filerestrict, 0)) {
            merror(REGEX_COMPILE, filerestrict, new_entry->filerestrict->error);
            os_free(new_entry->filerestrict);
        }
    }

    if (tag) {
        os_strdup(tag, new_entry->tag);
    }

    return new_entry;
}

int initialize_syscheck_configuration(syscheck_config *syscheck) {
    if (syscheck == NULL) {
        return OS_INVALID;
    }

    syscheck->rootcheck                       = 0;
    syscheck->disabled                        = SK_CONF_UNPARSED;
    syscheck->database_store                  = FIM_DB_DISK;
    syscheck->skip_fs.nfs                     = 1;
    syscheck->skip_fs.dev                     = 1;
    syscheck->skip_fs.sys                     = 1;
    syscheck->skip_fs.proc                    = 1;
    syscheck->scan_on_start                   = 1;
    syscheck->time                            = 43200;
    syscheck->ignore                          = NULL;
    syscheck->ignore_regex                    = NULL;
    syscheck->nodiff                          = NULL;
    syscheck->nodiff_regex                    = NULL;
    syscheck->scan_day                        = NULL;
    syscheck->scan_time                       = NULL;
    syscheck->file_limit_enabled              = true;
    syscheck->file_entry_limit                = 100000;
    syscheck->directories                     = OSList_Create();

    if (syscheck->directories == NULL) {
        return (OS_INVALID);
    }

    OSList_SetFreeDataPointer(syscheck->directories, (void (*)(void *))free_directory);
    syscheck->wildcards                       = NULL;
    syscheck->enable_synchronization          = 1;
    syscheck->restart_audit                   = 1;
    syscheck->enable_whodata                  = 0;
    syscheck->whodata_provider                = AUDIT_PROVIDER;
    syscheck->realtime                        = NULL;
    syscheck->audit_healthcheck               = 1;
    syscheck->process_priority                = 10;
#ifdef WIN_WHODATA
    syscheck->wdata.interval_scan             = 0;
    syscheck->wdata.fd                        = NULL;
#endif
#ifdef WIN32
    syscheck->registry_limit_enabled          = true;
    syscheck->db_entry_registry_limit         = 100000;
    syscheck->realtime_change                 = 0;
    syscheck->registry                        = NULL;
    syscheck->key_ignore                      = NULL;
    syscheck->key_ignore_regex                = NULL;
    syscheck->value_ignore                    = NULL;
    syscheck->value_ignore_regex              = NULL;
    syscheck->max_fd_win_rt                   = 0;
    syscheck->registry_nodiff                 = NULL;
    syscheck->registry_nodiff_regex           = NULL;
    syscheck->enable_registry_synchronization = 1;
#else
    syscheck->queue_size                      = 16384;
#endif
    syscheck->prefilter_cmd                   = NULL;
    syscheck->sync_interval                   = 300;
    syscheck->sync_response_timeout           = 30;
    syscheck->sync_max_interval               = 3600;
    syscheck->sync_thread_pool                = 1;
    syscheck->sync_max_eps                    = 10;
    syscheck->sync_queue_size                 = 16384;
    syscheck->max_eps                         = 50;
    syscheck->max_files_per_second            = 0;
    syscheck->allow_remote_prefilter_cmd      = false;
    syscheck->disk_quota_enabled              = true;
    syscheck->disk_quota_limit                = 1024 * 1024; // 1 GB
    syscheck->file_size_enabled               = true;
    syscheck->file_size_limit                 = 50 * 1024;   // 50 MB
    syscheck->diff_folder_size                = 0;
    syscheck->comp_estimation_perc            = 0.9;         // 90%
    syscheck->disk_quota_full_msg             = true;
    syscheck->audit_key                       = NULL;

    return OS_SUCCESS;
}

void fim_insert_directory(OSList *config_list,
                          directory_t *new_entry) {
    OSListNode *node_it;
    directory_t *dir_it;

    OSList_foreach (node_it, config_list) {
        dir_it = node_it->data;
        int cmp = strcmp(dir_it->path, new_entry->path);
        if (cmp == 0) {
            // Duplicated entry, replace existing with new one
            if (dir_it->is_wildcard == new_entry->is_wildcard || new_entry->is_wildcard == 0) {
                // Before replacing the configuration, we will keep the previous symbolic_links,
                // this value should only be changed by symlink_checker_thread.
                // TODO: unify symlink update logic with wildcards.
                os_free(new_entry->symbolic_links);

                if (dir_it->symbolic_links != NULL) {
                    os_strdup(dir_it->symbolic_links, new_entry->symbolic_links);
                }

                free_directory(dir_it);
                node_it->data = new_entry;
            } else {
                free_directory(new_entry);
            }
            return;
        } else if (cmp > 0) {
            // Insert the new entry before the current node.
            OSList_InsertData(config_list, node_it, new_entry);
            return;
        }
    }

    // Add as new entry or last entry
    OSList_InsertData(config_list, NULL, new_entry);
}

directory_t *fim_copy_directory(const directory_t *_dir) {
    if (_dir == NULL) {
        return NULL;
    }
    char *filerestrict = NULL;

    if (_dir->filerestrict) {
        filerestrict = _dir->filerestrict->raw;
    }

    return fim_create_directory(_dir->path, _dir->options, filerestrict, _dir->recursion_level,
                                _dir->tag, _dir->diff_size_limit, _dir->is_wildcard);
}

#ifdef WIN32
void dump_syscheck_registry(syscheck_config *syscheck,
                            char *entry,
                            int opts,
                            const char *restrict_key,
                            const char *restrict_value,
                            int recursion_level,
                            const char *tag,
                            int arch,
                            int diff_size) {
    unsigned int pl = 0;
    int overwrite = -1;

    if (syscheck->registry == NULL) {
        os_calloc(2, sizeof(registry_t), syscheck->registry);
        syscheck->registry[pl + 1].entry = NULL;
        syscheck->registry[pl].tag = NULL;
        syscheck->registry[pl + 1].tag = NULL;
        syscheck->registry[pl + 1].recursion_level = 0;
        syscheck->registry[pl + 1].restrict_key = NULL;
        syscheck->registry[pl + 1].restrict_value = NULL;
        syscheck->registry[pl + 1].diff_size_limit = -1;
    } else {
        while (syscheck->registry[pl].entry != NULL) {
            /* Duplicated entry */
            if (strcasecmp(syscheck->registry[pl].entry, entry) == 0 && arch == syscheck->registry[pl].arch) {
                overwrite = pl;
                mdebug2("Duplicated registration entry: %s", syscheck->registry[pl].entry);
                break;
            }
            pl++;
        }
        if (overwrite < 0) {
            os_realloc(syscheck->registry, (pl + 2) * sizeof(registry_t), syscheck->registry);
            syscheck->registry[pl + 1].entry = NULL;
            syscheck->registry[pl].tag = NULL;
            syscheck->registry[pl + 1].tag = NULL;
            syscheck->registry[pl + 1].recursion_level = 0;
            syscheck->registry[pl + 1].restrict_key = NULL;
            syscheck->registry[pl + 1].restrict_value = NULL;
            syscheck->registry[pl + 1].diff_size_limit = -1;
        } else {
            if (syscheck->registry[pl].restrict_key) {
                OSMatch_FreePattern(syscheck->registry[pl].restrict_key);
                os_free(syscheck->registry[pl].restrict_key);
            }
            if (syscheck->registry[pl].restrict_value) {
                OSMatch_FreePattern(syscheck->registry[pl].restrict_value);
                os_free(syscheck->registry[pl].restrict_value);
            }
            os_free(syscheck->registry[pl].tag);
            os_free(syscheck->registry[pl].entry);
        }
    }

    os_strdup(entry, syscheck->registry[pl].entry);
    syscheck->registry[pl].recursion_level = recursion_level;
    syscheck->registry[pl].arch = arch;
    syscheck->registry[pl].opts = opts;
    syscheck->registry[pl].diff_size_limit = diff_size;

    if (tag) {
        os_strdup(tag, syscheck->registry[pl].tag);
    }
    if (restrict_key) {
        os_calloc(1, sizeof(OSMatch), syscheck->registry[pl].restrict_key);
        if (!OSMatch_Compile(restrict_key, syscheck->registry[pl].restrict_key, 0)) {
            merror(REGEX_COMPILE, restrict_key, syscheck->registry[pl].restrict_key->error);
            os_free(syscheck->registry[pl].restrict_key);
        }
    }
    if (restrict_value) {
        os_calloc(1, sizeof(OSMatch), syscheck->registry[pl].restrict_value);
        if (!OSMatch_Compile(restrict_value, syscheck->registry[pl].restrict_value, 0)) {
            merror(REGEX_COMPILE, restrict_value, syscheck->registry[pl].restrict_value->error);
            os_free(syscheck->registry[pl].restrict_value);
        }
    }
}
#endif

#ifdef WIN32

void dump_registry_ignore(syscheck_config *syscheck, char *entry, int arch, int value) {
    int ign_size = 0;
    registry_ignore **ignore_list = value ? &syscheck->value_ignore : &syscheck->key_ignore;

    if (*ignore_list) {
        /* We do not add duplicated entries */
        for (ign_size = 0; (*ignore_list)[ign_size].entry; ign_size++)
            if ((*ignore_list)[ign_size].arch == arch &&
                    strcmp((*ignore_list)[ign_size].entry, entry) == 0)
                return;

        os_realloc((*ignore_list), sizeof(registry_ignore) * (ign_size + 2), *ignore_list);
        (*ignore_list)[ign_size + 1].entry = NULL;
    } else {
        ign_size = 0;
        os_calloc(2, sizeof(registry_ignore), *ignore_list);
        (*ignore_list)[0].entry = NULL;
        (*ignore_list)[1].entry = NULL;
    }

    os_strdup(entry, (*ignore_list)[ign_size].entry);
    (*ignore_list)[ign_size].arch = arch;
}

int dump_registry_ignore_regex(syscheck_config *syscheck, char *regex, int arch, int value) {
    OSMatch *mt_pt;
    int ign_size = 0;
    registry_ignore_regex **ignore_list_regex = value ? &syscheck->value_ignore_regex : &syscheck->key_ignore_regex;

    if (!(*ignore_list_regex)) {
        os_calloc(2, sizeof(registry_ignore_regex), (*ignore_list_regex));
        (*ignore_list_regex)[0].regex = NULL;
        (*ignore_list_regex)[1].regex = NULL;
    } else {
        while ((*ignore_list_regex)[ign_size].regex != NULL) {
            ign_size++;
        }
        os_realloc((*ignore_list_regex), sizeof(registry_ignore_regex) * (ign_size + 2), (*ignore_list_regex));
        (*ignore_list_regex)[ign_size + 1].regex = NULL;
    }

    os_calloc(1, sizeof(OSMatch), (*ignore_list_regex)[ign_size].regex);

    if (!OSMatch_Compile(regex, (*ignore_list_regex)[ign_size].regex, 0)) {
        mt_pt = (*ignore_list_regex)[ign_size].regex;
        merror(REGEX_COMPILE, regex, mt_pt->error);
        os_free((*ignore_list_regex)[ign_size].regex);
        return (0);
    }
    (*ignore_list_regex)[ign_size].arch = arch;
    return 1;
}

void dump_registry_nodiff(syscheck_config *syscheck, const char *entry, int arch) {
    int ign_size = 0;

    if (syscheck->registry_nodiff) {
        /* We do not add duplicated entries */
        for (ign_size = 0; syscheck->registry_nodiff[ign_size].entry; ign_size++)
            if (syscheck->registry_nodiff[ign_size].arch == arch &&
                    strcmp(syscheck->registry_nodiff[ign_size].entry, entry) == 0)
                return;

        os_realloc(syscheck->registry_nodiff, sizeof(registry_t) * (ign_size + 2),
                   syscheck->registry_nodiff);

        syscheck->registry_nodiff[ign_size + 1].entry = NULL;
    } else {
        os_calloc(2, sizeof(registry_t), syscheck->registry_nodiff);
        syscheck->registry_nodiff[0].entry = NULL;
        syscheck->registry_nodiff[1].entry = NULL;
    }

    os_strdup(entry, syscheck->registry_nodiff[ign_size].entry);
    syscheck->registry_nodiff[ign_size].arch = arch;
}

int dump_registry_nodiff_regex(syscheck_config *syscheck, const char *regex, int arch) {
    OSMatch *mt_pt;
    int ign_size = 0;

    if (!syscheck->registry_nodiff_regex) {
        os_calloc(2, sizeof(registry_ignore_regex), syscheck->registry_nodiff_regex);
        syscheck->registry_nodiff_regex[0].regex = NULL;
        syscheck->registry_nodiff_regex[1].regex = NULL;
    } else {
        while (syscheck->registry_nodiff_regex[ign_size].regex != NULL) {
            ign_size++;
        }

        os_realloc(syscheck->registry_nodiff_regex, sizeof(registry_ignore_regex) * (ign_size + 2),
                   syscheck->registry_nodiff_regex);
        syscheck->registry_nodiff_regex[ign_size + 1].regex = NULL;
    }

    os_calloc(1, sizeof(OSMatch), syscheck->registry_nodiff_regex[ign_size].regex);

    if (!OSMatch_Compile(regex, syscheck->registry_nodiff_regex[ign_size].regex, 0)) {
        mt_pt = syscheck->registry_nodiff_regex[ign_size].regex;
        merror(REGEX_COMPILE, regex, mt_pt->error);
        return (0);
    }

    syscheck->registry_nodiff_regex[ign_size].arch = arch;
    return 1;
}

/* Read Windows registry configuration */
int read_reg(syscheck_config *syscheck, const char *entries, char **attributes, char **values) {
    const char *xml_arch = "arch";
    const char *xml_32bit = "32bit";
    const char *xml_64bit = "64bit";
    const char *xml_both = "both";
    const char *xml_tag = "tags";
    const char *xml_recursion_level = "recursion_level";
    const char *xml_report_changes = "report_changes";
    const char *xml_check_all = "check_all";
    const char *xml_check_sum = "check_sum";
    const char *xml_check_md5sum = "check_md5sum";
    const char *xml_check_sha1sum = "check_sha1sum";
    const char *xml_check_sha256sum = "check_sha256sum";
    const char *xml_check_size = "check_size";
    const char *xml_check_owner = "check_owner";
    const char *xml_check_group = "check_group";
    const char *xml_check_perm = "check_perm";
    const char *xml_check_mtime = "check_mtime";
    const char *xml_check_type = "check_type";
    const char *xml_restrict_registry = "restrict_key";
    const char *xml_restrict_value = "restrict_value";
    const char *xml_diff_size_limit = "diff_size_limit";

    int i;
    char **entry;
    char *tag = NULL;
    char *restrict_key = NULL;
    char *restrict_value = NULL;
    int arch = ARCH_32BIT;
    int recursion_level = MAX_REGISTRY_DEPTH;
    int opts = REGISTRY_CHECK_ALL;
    int retval = 0;
    int tmp_diff_size = -1;

    if (attributes && values) {
        for (i = 0; attributes[i]; i++) {
            if (values[i] == NULL) {
                mdebug1("Empty value for attribute %s", attributes[i]);
                break;
            }
            if (strcmp(attributes[i], xml_tag) == 0) {
                os_free(tag);

                if (tag = os_strip_char(values[i], ' '), !tag) {
                    merror("Processing tag for registry entry '%s'.", entries);
                }
            } else if (strcmp(attributes[i], xml_arch) == 0) {
                if (strcmp(values[i], xml_32bit) == 0) {
                } else if (strcmp(values[i], xml_64bit) == 0) {
                    arch = ARCH_64BIT;
                } else if (strcmp(values[i], xml_both) == 0) {
                    arch = ARCH_BOTH;
                } else {
                    mwarn(XML_INVATTR, attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_recursion_level) == 0) {
                if (!OS_StrIsNum(values[i])) {
                    mwarn(XML_VALUEERR, xml_recursion_level, entries);
                    goto clean_reg;
                }
                recursion_level = atoi(values[i]);
                if (recursion_level < 0 || recursion_level > MAX_REGISTRY_DEPTH) {
                    mwarn("Invalid recursion level value: %d. Setting default (%d).", recursion_level,
                          MAX_REGISTRY_DEPTH);
                    recursion_level = MAX_REGISTRY_DEPTH;
                }
            } else if (strcmp(attributes[i], xml_report_changes) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_SEECHANGES;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_SEECHANGES;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_restrict_registry) == 0) {
                os_free(restrict_key);
                os_strdup(values[i], restrict_key);
            } else if (strcmp(attributes[i], xml_restrict_value) == 0) {
                os_free(restrict_value);
                os_strdup(values[i], restrict_value);
            } else if (strcmp(attributes[i], xml_check_all) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= REGISTRY_CHECK_ALL;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~REGISTRY_CHECK_ALL;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_sum) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_SUM;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_SUM;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_md5sum) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_MD5SUM;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_MD5SUM;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_sha1sum) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_SHA1SUM;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_SHA1SUM;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_sha256sum) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_SHA256SUM;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_SHA256SUM;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_size) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_SIZE;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_SIZE;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_owner) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_OWNER;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_OWNER;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_group) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_GROUP;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_GROUP;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_perm) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_PERM;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_PERM;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_mtime) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_MTIME;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_MTIME;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_check_type) == 0) {
                if (strcmp(values[i], "yes") == 0) {
                    opts |= CHECK_TYPE;
                } else if (strcmp(values[i], "no") == 0) {
                    opts &= ~CHECK_TYPE;
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }
            } else if (strcmp(attributes[i], xml_diff_size_limit) == 0) {
                if (values[i]) {
                    tmp_diff_size = read_data_unit(values[i]);
                    if (tmp_diff_size == -1) {
                        mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                        goto clean_reg;
                    }
                    if (tmp_diff_size < 1) {
                        tmp_diff_size = 1;      // 1 KB is the minimum
                    }
                } else {
                    mwarn(FIM_INVALID_REG_OPTION_SKIP, values[i], attributes[i], entries);
                    goto clean_reg;
                }

            } else {
                mwarn(XML_INVATTR, attributes[i], entries);
                goto clean_reg;
            }
        }
    }

    /* Get each entry separately */
    entry = OS_StrBreak(',', entries, MAX_DIR_SIZE + 1); /* Max number */

    if (entry == NULL) {
        goto clean_reg;
    }

    for (i = 0; entry[i]; i++) {
        char *tmp_entry;

        /* When the maximum number of registries monitored in the same tag is reached,
           the excess is discarded and warned */
        if (i >= MAX_DIR_SIZE) {
            mwarn(FIM_WARN_MAX_REG_REACH, MAX_DIR_SIZE, entry[i]);
            free(entry[i]);
            continue;
        }

        /* Remove spaces at the end */
        tmp_entry = entry[i] + strlen(entry[i]) - 1;
        while(*tmp_entry == ' ') {
            *tmp_entry = '\0';
            tmp_entry--;
        }

        /* Remove spaces at the beginning */
        tmp_entry = entry[i];
        while (*tmp_entry == ' ') {
            tmp_entry++;
        }

        if (*tmp_entry == '\0') {
            mdebug2(FIM_EMPTY_REGISTRY_CONFIG);
            free(entry[i]);
            continue;
        }

        /* Expand any wildcard */
        char** paths_wildcard = NULL;
        os_calloc(OS_SIZE_8192, sizeof(char*), paths_wildcard);
        expand_wildcard_registers(entry[i], paths_wildcard);

        if (*paths_wildcard != NULL) {
            mdebug1(FIM_WILDCARDS_REGISTERS_START);
            char** current_path = paths_wildcard;
            while(*current_path != NULL){
                mdebug2(FIM_WILDCARDS_ADD_REGISTER, entry[i], *current_path);
                /* Add new entry */
                if (arch == ARCH_BOTH) {
                    dump_syscheck_registry(syscheck, *current_path, opts, restrict_key, restrict_value, recursion_level, tag, ARCH_64BIT, tmp_diff_size);
                    dump_syscheck_registry(syscheck, *current_path, opts, restrict_key, restrict_value, recursion_level, tag, ARCH_32BIT, tmp_diff_size);
                } else {
                    dump_syscheck_registry(syscheck, *current_path, opts, restrict_key, restrict_value, recursion_level, tag, arch, tmp_diff_size);
                }
                current_path++;
            }
            mdebug1(FIM_WILDCARDS_REGISTERS_FINALIZE);
        } else {
            /* Add new entry */
            if (arch == ARCH_BOTH) {
                dump_syscheck_registry(syscheck, tmp_entry, opts, restrict_key, restrict_value, recursion_level, tag, ARCH_64BIT, tmp_diff_size);
                dump_syscheck_registry(syscheck, tmp_entry, opts, restrict_key, restrict_value, recursion_level, tag, ARCH_32BIT, tmp_diff_size);
            } else {
                dump_syscheck_registry(syscheck, tmp_entry, opts, restrict_key, restrict_value, recursion_level, tag, arch, tmp_diff_size);
            }
        }
        free_strarray(paths_wildcard);
        /* Next entry */
        free(entry[i]);
    }
    free(entry);

    retval = 1;
clean_reg:
    os_free(tag);
    os_free(restrict_key);
    os_free(restrict_value);
    return retval;
}
#endif /* WIN32 */

char *format_path(char *dir) {
    char *clean_path;
    char *tmp_str;

    if(dir == NULL || *dir == '\0') {
        return NULL;
    }

#ifdef WIN32
    char buffer[PATH_MAX];

    /* Change forward slashes to backslashes on entry */
    tmp_str = strchr(dir, '/');
    while (tmp_str) {
        *tmp_str = '\\';
        tmp_str++;
        tmp_str = strchr(tmp_str, '/');
    }

    if (strlen(dir) == 2) {
        wm_strcat(&dir, "\\", '\0');
    }

    if (!GetFullPathName(dir, PATH_MAX, buffer, NULL)) {
        return NULL;
    }
    os_strdup(buffer, clean_path);
    str_lowercase(clean_path);
#else
    os_strdup(dir, clean_path);
#endif

    // Remove any trailling path separators
    int path_length = strlen(clean_path);
#ifdef WIN32
    if (path_length != 3) { // Drives need :\ attached in order to work properly
#else
    if (path_length != 1) {
#endif
        tmp_str = clean_path + path_length - 1;
        if (*tmp_str == PATH_SEP) {
            *tmp_str = '\0';
        }
    }

    return clean_path;
}

char **expand_wildcards(const char *path) {
#ifndef WIN32
    /* Check for glob */
    int gstatus;
    glob_t g;
    char **paths;

    gstatus = glob(path, 0, NULL, &g);
    if (gstatus == GLOB_NOMATCH) {
        mdebug2(GLOB_NO_MATCH, path);
        return NULL;
    } else if (gstatus != 0) {
        merror(GLOB_ERROR, path);
        return NULL;
    }

    if (g.gl_pathv[0] == NULL) {
        merror(GLOB_NFOUND, path);
        return NULL;
    }

    os_calloc(g.gl_pathc + 1, sizeof(char *), paths);
    for (int gindex = 0; g.gl_pathv[gindex]; gindex++) {
        os_strdup(g.gl_pathv[gindex], paths[gindex]);
    }

    globfree(&g);
    return paths;
#else
    return expand_win32_wildcards(path);
#endif
}


/* Read directories attributes */
static int read_attr(syscheck_config *syscheck, const char *dirs, char **g_attrs, char **g_values)
{
    const char *xml_check_all = "check_all";
    const char *xml_check_sum = "check_sum";
    const char *xml_check_sha1sum = "check_sha1sum";
    const char *xml_check_md5sum = "check_md5sum";
    const char *xml_check_size = "check_size";
    const char *xml_check_owner = "check_owner";
    const char *xml_check_group = "check_group";
    const char *xml_check_perm = "check_perm";
    const char *xml_check_mtime = "check_mtime";
    const char *xml_check_inode = "check_inode";
    const char *xml_check_attrs = "check_attrs";
    const char *xml_follow_symbolic_link = "follow_symbolic_link";
    const char *xml_real_time = "realtime";
    const char *xml_report_changes = "report_changes";
    const char *xml_restrict = "restrict";
    const char *xml_check_sha256sum = "check_sha256sum";
    const char *xml_whodata = "whodata";
    const char *xml_recursion_level = "recursion_level";
    const char *xml_tag = "tags";
    const char *xml_diff_size_limit = "diff_size_limit";

    /* Variables for extract options */
    char *restrictfile = NULL;
    int recursion_limit = syscheck->max_depth;
    char *tag = NULL;
    char *clean_tag = NULL;
    char **attrs = g_attrs;
    char **values = g_values;
    int opts = 0;
    int tmp_diff_size = -1;

    /* Variables for extract directories and free memory after that */
    char **dir;
    dir = OS_StrBreak(',', dirs, MAX_DIR_SIZE + 1); /* Max number */
    char **dir_org = dir;
    int i;

    /* Dir can not be null */
    if (dir == NULL) {
        return (0);
    }

    /* Default values */
    opts &= ~ CHECK_FOLLOW;
    opts |= SCHEDULED_ACTIVE;
    fim_set_check_all(&opts);

    /* Extract all options */
    while (attrs && values && *attrs && *values) {
        /* Check all */
        if (strcmp(*attrs, xml_check_all) == 0) {
            if (strcmp(*values, "yes") == 0) {
                fim_set_check_all(&opts);
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ ( CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_PERM | CHECK_SHA256SUM | CHECK_SIZE
                        | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE);

#ifdef WIN32
                opts &= ~ CHECK_ATTRS;
#endif
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check sum */
        else if (strcmp(*attrs, xml_check_sum) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_MD5SUM;
                opts |= CHECK_SHA1SUM;
                opts |= CHECK_SHA256SUM;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM);
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check md5sum */
        else if (strcmp(*attrs, xml_check_md5sum) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_MD5SUM;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_MD5SUM;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check sha1sum */
        else if (strcmp(*attrs, xml_check_sha1sum) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_SHA1SUM;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_SHA1SUM;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check sha256sum */
        else if (strcmp(*attrs, xml_check_sha256sum) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_SHA256SUM;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_SHA256SUM;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check whodata */
        else if (strcmp(*attrs, xml_whodata) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts &= ~ SCHEDULED_ACTIVE;
                opts |= WHODATA_ACTIVE;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ WHODATA_ACTIVE;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check permission */
        else if (strcmp(*attrs, xml_check_perm) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_PERM;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_PERM;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check size */
        else if (strcmp(*attrs, xml_check_size) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_SIZE;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_SIZE;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check owner */
        else if (strcmp(*attrs, xml_check_owner) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_OWNER;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_OWNER;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check group */
        else if (strcmp(*attrs, xml_check_group) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_GROUP;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_GROUP;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check modification time */
        else if (strcmp(*attrs, xml_check_mtime) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_MTIME;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_MTIME;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check inode */
        else if (strcmp(*attrs, xml_check_inode) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_INODE;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_INODE;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check attributes */
        else if (strcmp(*attrs, xml_check_attrs) == 0) {
#ifdef WIN32
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_ATTRS;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_ATTRS;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
#else
            mdebug1("Option '%s' is only available on Windows systems.", xml_check_attrs);
#endif
        }
        /* Check real time */
        else if (strcmp(*attrs, xml_real_time) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts &= ~ SCHEDULED_ACTIVE;
                opts |= REALTIME_ACTIVE;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ REALTIME_ACTIVE;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check report changes */
        else if (strcmp(*attrs, xml_report_changes) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_SEECHANGES;
            } else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_SEECHANGES;
            } else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        /* Check file restriction */
        else if (strcmp(*attrs, xml_restrict) == 0) {
            os_free(restrictfile);
            os_strdup(*values, restrictfile);
#ifdef WIN32
            str_lowercase(restrictfile);
#endif
        }
        /* Check recursion limit */
        else if (strcmp(*attrs, xml_recursion_level) == 0) {
            if (!OS_StrIsNum(*values)) {
                mwarn(XML_VALUEERR, xml_recursion_level, *values);
                goto out_free;
            }
            recursion_limit = (unsigned int) atoi(*values);
            if (recursion_limit < 0) {
                mwarn("Invalid recursion level value: %d. Setting default (%d).", recursion_limit, syscheck->max_depth);
                recursion_limit = syscheck->max_depth;
            } else if (recursion_limit > MAX_DEPTH_ALLOWED) {
                mwarn("Recursion level '%d' exceeding limit. Setting %d.", recursion_limit, MAX_DEPTH_ALLOWED);
                recursion_limit = syscheck->max_depth;
            }
        }
        /* Check tag */
        else if (strcmp(*attrs, xml_tag) == 0) {
            os_free(tag);
            os_strdup(*values, tag);
        }
        /* Check follow symbolic links */
        else if (strcmp(*attrs, xml_follow_symbolic_link) == 0) {
            if (strcmp(*values, "yes") == 0) {
                opts |= CHECK_FOLLOW;
            }
            else if (strcmp(*values, "no") == 0) {
                opts &= ~ CHECK_FOLLOW;
            }
            else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        else if (strcmp(*attrs, xml_diff_size_limit) == 0) {
            if (*values) {
                char *value;

                os_calloc(strlen(*values) + 1, sizeof(char), value);
                strcpy(value, *values);

                tmp_diff_size = read_data_unit(value);

                if (tmp_diff_size == -1) {
                    mwarn(FIM_INVALID_OPTION_SKIP, value, *attrs, dirs);
                    os_free(value);
                    goto out_free;
                }

                if (tmp_diff_size < 1) {
                    tmp_diff_size = 1;      // 1 KB is the minimum
                }

                os_free(value);
            }
            else {
                mwarn(FIM_INVALID_OPTION_SKIP, *values, *attrs, dirs);
                goto out_free;
            }
        }
        else {
            mwarn(FIM_UNKNOWN_ATTRIBUTE, *attrs);
        }

        attrs++;
        values++;
    }

    /* You must have something set */
    if (opts == 0) {
        mwarn(FIM_NO_OPTIONS, dirs);
        goto out_free;
    }

    /* Whodata prevails over Realtime */
    if ((opts & WHODATA_ACTIVE) && (opts & REALTIME_ACTIVE)) {
        opts &= ~ REALTIME_ACTIVE;
    }

    /* Remove spaces from tag */
    if (tag) {
        if (clean_tag = os_strip_char(tag, ' '), !clean_tag) {
            merror("Processing tag '%s'", tag);
            goto out_free;
        } else {
            os_free(tag);
            os_strdup(clean_tag, tag);
            os_free(clean_tag);
        }
        if (clean_tag = os_strip_char(tag, '!'), !clean_tag) {
            merror("Processing tag '%s'", tag);
            goto out_free;
        } else {
            os_free(tag);
            os_strdup(clean_tag, tag);
            os_free(clean_tag);
        }
        if (clean_tag = os_strip_char(tag, ':'), !clean_tag) {
            merror("Processing tag '%s'", tag);
            goto out_free;
        }
    }

    /* Extract all directories */
    char *clean_path;
    char *tmp_dir;
    char **env_variable;
    int j = 0;
    char **paths;
    directory_t *new_entry;

    while (*dir) {
        /* When the maximum number of directories monitored in the same tag is reached,
           the excess are discarded and warned */
        if (j++ >= MAX_DIR_SIZE){
            mwarn(FIM_WARN_MAX_DIR_REACH, MAX_DIR_SIZE, *dir);
            dir++;
            continue;
        }

        tmp_dir = w_strtrim(*dir);
        if (!tmp_dir) {
            dir++;
            continue;
        }

        // Skip if the content is empty.
        if (*tmp_dir == '\0') {
            mdebug2(FIM_EMPTY_DIRECTORIES_CONFIG);
            dir++;
            continue;
        }

        /* If it's an environment variable, expand it */
        env_variable = get_paths_from_env_variable(tmp_dir);

        for (int i = 0; env_variable[i]; i++) {
            if(*env_variable[i] == '\0') {
                mwarn(FIM_WARN_FORMAT_PATH, env_variable[i]);
                continue;
            }

            clean_path = format_path(env_variable[i]);
            if (clean_path == NULL) {
                continue;
            }

            // Fill wildcards array
            if (strchr(clean_path, '*') || strchr(clean_path, '?') || strchr(clean_path, '[')) {
                if (syscheck->wildcards == NULL) {
                    syscheck->wildcards = OSList_Create();
                    if (syscheck->wildcards == NULL) {
                        os_free(clean_path);
                        merror(MEM_ERROR, errno, strerror(errno));
                        continue;
                    }
                    OSList_SetFreeDataPointer(syscheck->wildcards, (void (*)(void *))free_directory);
                }

                // Create the wildcard directory
                directory_t *wildcard = fim_create_directory(clean_path, opts, restrictfile, recursion_limit,
                                                             clean_tag, tmp_diff_size, 1);

                // Check directories options to determine whether to start the whodata thread or not
                if (wildcard->options & WHODATA_ACTIVE) {
                    syscheck->enable_whodata = 1;
                }

                paths = expand_wildcards(clean_path);
                if (paths) {
                    for (int j = 0; paths[j]; j++) {
                        new_entry = fim_copy_directory(wildcard);
                        os_free(new_entry->path);
                        new_entry->path = paths[j];
#ifndef WIN32
                        if (CHECK_FOLLOW & new_entry->options) {
                            new_entry->symbolic_links = realpath(new_entry->path, NULL);
                        }
#endif
                        if (new_entry->diff_size_limit == -1) {
                            new_entry->diff_size_limit = syscheck->file_size_limit;
                        }

                        fim_insert_directory(syscheck->directories, new_entry);
                    }
                    os_free(paths);
                }

                fim_insert_directory(syscheck->wildcards, wildcard);
            } else {
                new_entry = fim_create_directory(clean_path, opts, restrictfile, recursion_limit,
                                     clean_tag, tmp_diff_size, 0);
                fim_insert_directory(syscheck->directories, new_entry);
            }

            os_free(clean_path);
        }
        free_strarray(env_variable);
        dir++;
    }

out_free:

    i = 0;
    while (dir_org[i]) {
        free(dir_org[i++]);
    }

    free(dir_org);
    os_free(restrictfile);
    os_free(tag);
    os_free(clean_tag);

    return 1;
}

static void parse_synchronization(syscheck_config * syscheck, XML_NODE node) {
    const char *xml_enabled = "enabled";
    const char *xml_sync_interval = "interval";
    const char *xml_sync_max_interval = "max_interval";
    const char *xml_response_timeout = "response_timeout";
    const char *xml_sync_queue_size = "queue_size";
    const char *xml_max_eps = "max_eps";
    const char *xml_registry_enabled = "registry_enabled";
    const char *xml_sync_thread_pool = "thread_pool";

    for (int i = 0; node[i]; i++) {
        if (strcmp(node[i]->element, xml_enabled) == 0) {
            int r = w_parse_bool(node[i]->content);

            if (r < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->enable_synchronization = r;
            }
        } else if (strcmp(node[i]->element, xml_sync_interval) == 0) {
            long t = w_parse_time(node[i]->content);

            if (t <= 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_interval = t;
            }
        } else if (strcmp(node[i]->element, xml_sync_max_interval) == 0) {
            long max_interval = w_parse_time(node[i]->content);

            if (max_interval < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_max_interval = (uint32_t) max_interval;
            }
        } else if (strcmp(node[i]->element, xml_response_timeout) == 0) {
            long response_timeout = w_parse_time(node[i]->content);

            if (response_timeout < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_response_timeout = (uint32_t) response_timeout;
            }
        } else if (strcmp(node[i]->element, xml_sync_queue_size) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 2 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
            else {
                syscheck->sync_queue_size = value;
            }
        } else if (strcmp(node[i]->element, xml_max_eps) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->sync_max_eps = value;
            }
        } else if (strcmp(node[i]->element, xml_registry_enabled) == 0) {
#ifdef WIN32
            int r = w_parse_bool(node[i]->content);

            if (r < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->enable_registry_synchronization = r;
            }
#endif
        } else if (strcmp(node[i]->element, xml_sync_thread_pool) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                int value = atoi(node[i]->content);

                if (value < 1) {
                    mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    syscheck->sync_thread_pool = value;
                }
            }
        } else {
            mwarn(XML_INVELEM, node[i]->element);
        }
    }

    if (syscheck->sync_max_interval < syscheck->sync_interval) {
        syscheck->sync_max_interval = syscheck->sync_interval;
        mwarn("'max_interval' cannot be less than 'interval'. New 'max_interval' value: '%d'", syscheck->sync_interval);
    }
}

int read_data_unit(const char *content) {
    size_t len_value_str = strlen(content);
    int converted_value = 0;
    int read_value = 0;
    char *value_str;

    // Check that the last character is a 'B' or a 'b', if it is, translate data unit
    // Else, use written value as KB
    if (content[len_value_str - 1] == 'B' || content[len_value_str - 1] == 'b') {
        if (isalpha(content[len_value_str - 2])){
            os_calloc(len_value_str, sizeof(char), value_str);
            memcpy(value_str, content, len_value_str - 2);

            if (OS_StrIsNum(value_str)) {
                read_value = atoi(value_str);

                switch (content[len_value_str - 2]) {
                    case 'M':
                        // Fallthrough
                    case 'm':
                        converted_value = read_value * 1024;
                        break;
                    case 'G':
                        // Fallthrough
                    case 'g':
                        converted_value = read_value * (1024 * 1024);
                        break;
                    case 'T':
                        // Fallthrough
                    case 't':
                        converted_value = read_value * (1024 * 1024 * 1024);
                        break;
                    case 'K':
                        // Fallthrough
                    case 'k':
                        // Fallthrough
                    default:
                        converted_value = read_value;
                        break;
                }

                if (converted_value < 0 && read_value > 0) {  // Overflow
                    converted_value = INT_MAX;
                }
            }
            else {
                os_free(value_str);
                return -1;
            }
            os_free(value_str);
        }
        else if (isdigit(content[len_value_str - 2])) {
            return -1;  // Error: limit cannot be set to bytes
        }
    }
    else if (isdigit(content[len_value_str - 1])) {
        if (!OS_StrIsNum(content)) {
            return -1;
        }

        converted_value = atoi(content);     // In KB
    }
    else {
        return -1;
    }

    return converted_value;
}

void parse_diff(const OS_XML *xml, syscheck_config * syscheck, XML_NODE node) {
    const char *xml_disk_quota = "disk_quota";
    const char *xml_disk_quota_enabled = "enabled";
    const char *xml_disk_quota_limit = "limit";
    const char *xml_file_size = "file_size";
    const char *xml_file_size_enabled = "enabled";
    const char *xml_file_size_limit = "limit";
    const char *xml_nodiff = "nodiff";
#ifdef WIN32
    const char *xml_registry_nodiff = "registry_nodiff";
    const char *xml_arch = "arch";
    const char *xml_32bit = "32bit";
    const char *xml_64bit = "64bit";
    const char *xml_both = "both";
#endif

    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    unsigned int nodiff_size = 0;

    for (i = 0; node[i]; i++) {
        /* Getting file/dir nodiff */
        if (strcmp(node[i]->element,xml_nodiff) == 0) {
#ifdef WIN32
            /* For Windows, we attempt to expand environment variables */
            char *new_nodiff = NULL;
            os_calloc(2048, sizeof(char), new_nodiff);

            if (!ExpandEnvironmentStrings(node[i]->content, new_nodiff, 2047)){
                merror("Could not expand the environment variable %s (%ld)", node[i]->content, GetLastError());
                free(new_nodiff);
                continue;
            }

            free(node[i]->content);
            str_lowercase(new_nodiff);
            node[i]->content = new_nodiff;
#endif
            /* Add if regex */
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0] && node[i]->values[0]) {
                if (!strcmp(node[i]->attributes[0], "type") && !strcmp(node[i]->values[0], "sregex")) {
                    OSMatch *mt_pt;

                    if (!syscheck->nodiff_regex) {
                        os_calloc(2, sizeof(OSMatch *), syscheck->nodiff_regex);
                        syscheck->nodiff_regex[0] = NULL;
                        syscheck->nodiff_regex[1] = NULL;
                    }
                    else {
                        while (syscheck->nodiff_regex[nodiff_size] != NULL) {
                            nodiff_size++;
                        }

                        os_realloc(syscheck->nodiff_regex,
                                   sizeof(OSMatch *) * (nodiff_size + 2),
                                   syscheck->nodiff_regex);

                        syscheck->nodiff_regex[nodiff_size + 1] = NULL;
                    }

                    os_calloc(1, sizeof(OSMatch), syscheck->nodiff_regex[nodiff_size]);
                    mdebug1("Found nodiff regex node %s", node[i]->content);

                    if (!OSMatch_Compile(node[i]->content, syscheck->nodiff_regex[nodiff_size], 0)) {
                        mt_pt = (OSMatch *)syscheck->nodiff_regex[nodiff_size];
                        merror(REGEX_COMPILE, node[i]->content, mt_pt->error);
                        return;
                    }
                }
                else {
                    mwarn(FIM_INVALID_ATTRIBUTE, node[i]->attributes[0], node[i]->element);
                    return;
                }
            }
            /* Add if simple entry -- check for duplicates */
            else if (!os_IsStrOnArray(node[i]->content, syscheck->nodiff)) {
                if (!syscheck->nodiff) {
                    os_calloc(2, sizeof(char *), syscheck->nodiff);

                    syscheck->nodiff[0] = NULL;
                    syscheck->nodiff[1] = NULL;
                }
                else {
                    while (syscheck->nodiff[nodiff_size] != NULL) {
                        nodiff_size++;
                    }

                    os_realloc(syscheck->nodiff, sizeof(char *) * (nodiff_size + 2), syscheck->nodiff);

                    syscheck->nodiff[nodiff_size + 1] = NULL;
                }

                os_strdup(node[i]->content, syscheck->nodiff[nodiff_size]);
            }
        }

#ifdef WIN32
        if (strcmp(node[i]->element,xml_registry_nodiff) == 0) {
            char *new_nodiff = NULL;
            os_calloc(2048, sizeof(char), new_nodiff);

            if (!ExpandEnvironmentStrings(node[i]->content, new_nodiff, 2047)){
                merror("Could not expand the environment variable %s (%ld)", node[i]->content, GetLastError());
                free(new_nodiff);
                continue;
            }

            free(node[i]->content);
            node[i]->content = new_nodiff;

            int sregex = 0;
            int arch = ARCH_32BIT;

            /* Add if regex */
            if (node[i]->attributes && node[i]->values) {
                int j;

                for (j = 0; node[i]->attributes[j] && node[i]->values[j]; j++) {
                    if (strcmp(node[i]->attributes[j], "type") == 0 &&
                    strcmp(node[i]->values[j], "sregex") == 0) {
                        sregex = 1;
                    } else if (strcmp(node[i]->attributes[j], xml_arch) == 0) {
                        if (strcmp(node[i]->values[j], xml_32bit) == 0)
                            arch = ARCH_32BIT;
                        else if  (strcmp(node[i]->values[j], xml_64bit) == 0)
                            arch = ARCH_64BIT;
                        else if (strcmp(node[i]->values[j], xml_both) == 0)
                            arch = ARCH_BOTH;
                        else {
                            mwarn(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                            return;
                        }
                    } else {
                        mwarn(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                        return;
                    }
                }
            }

            if (sregex) {
                if (arch != ARCH_BOTH)
                    dump_registry_nodiff_regex(syscheck, node[i]->content, arch);
                else {
                    dump_registry_nodiff_regex(syscheck, node[i]->content, ARCH_32BIT);
                    dump_registry_nodiff_regex(syscheck, node[i]->content, ARCH_64BIT);
                }
            } else {
                if (arch != ARCH_BOTH)
                    dump_registry_nodiff(syscheck, node[i]->content, arch);
                else {
                    dump_registry_nodiff(syscheck, node[i]->content, ARCH_32BIT);
                    dump_registry_nodiff(syscheck, node[i]->content, ARCH_64BIT);
                }
            }
        }
#endif

        else if (strcmp(node[i]->element, xml_disk_quota) == 0) {
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }

            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_disk_quota_enabled) == 0) {
                    if (strcmp(children[j]->content, "yes") == 0) {
                        syscheck->disk_quota_enabled = true;
                    }
                    else if (strcmp(children[j]->content, "no") == 0) {
                        syscheck->disk_quota_enabled = false;
                    }
                    else {
                        mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return;
                    }
                }
                else if (strcmp(children[j]->element, xml_disk_quota_limit) == 0) {
                    if (children[j]->content) {
                        syscheck->disk_quota_limit = read_data_unit(children[j]->content);

                        if (syscheck->disk_quota_limit == -1) {
                            mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                            OS_ClearNode(children);
                            return;
                        }

                        if (syscheck->disk_quota_limit < 1) {
                            syscheck->disk_quota_limit = 1;     // 1 KB is the minimum
                        }
                    }
                    else {
                        mwarn(XML_VALUEERR, children[j]->element, "");     // Null children[j]->content
                        OS_ClearNode(children);
                        return;
                    }
                }
            }

            OS_ClearNode(children);
        }
        else if (strcmp(node[i]->element, xml_file_size) == 0) {
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }

            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_file_size_enabled) == 0) {
                    if (strcmp(children[j]->content, "yes") == 0) {
                        syscheck->file_size_enabled = true;
                    }
                    else if (strcmp(children[j]->content, "no") == 0) {
                        syscheck->file_size_enabled = false;
                    }
                    else {
                        mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return;
                    }
                }
                else if (strcmp(children[j]->element, xml_file_size_limit) == 0) {
                    if (children[j]->content) {
                        syscheck->file_size_limit = read_data_unit(children[j]->content);

                        if (syscheck->file_size_limit == -1) {
                            mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                            OS_ClearNode(children);
                            return;
                        }

                        if (syscheck->file_size_limit < 1) {
                            syscheck->file_size_limit = 1;      // 1 KB is the minimum
                        }
                    }
                    else {
                        mwarn(XML_VALUEERR, children[j]->element, "");     // Null children[j]->content
                        OS_ClearNode(children);
                        return;
                    }
                }
            }

            OS_ClearNode(children);
        }
    }

    if (syscheck->file_size_enabled && syscheck->disk_quota_limit < syscheck->file_size_limit) {
        syscheck->disk_quota_limit = syscheck->file_size_limit;

        mdebug2("Setting 'disk_quota' to %d, 'disk_quota' must be greater than 'file_size'",
                syscheck->disk_quota_limit);
    }
}

int Read_Syscheck(const OS_XML *xml, XML_NODE node, void *configp, __attribute__((unused)) void *mailp, int modules)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;

    /* XML Definitions */
    const char *xml_directories = "directories";
    const char *xml_registry = "windows_registry";
    const char *xml_time = "frequency";
    const char *xml_scanday = "scan_day";
    const char *xml_database = "database";
    const char *xml_scantime = "scan_time";
    const char *xml_file_limit = "file_limit";
    const char *xml_enabled = "enabled";
    const char *xml_entries = "entries";
#ifdef WIN32
    const char *xml_registry_limit = "registry_limit";
#endif
    const char *xml_ignore = "ignore";
    const char *xml_registry_ignore = "registry_ignore";
#ifdef WIN32
    const char *xml_registry_ignore_value = "registry_ignore_value";
#endif
    const char *xml_auto_ignore = "auto_ignore"; // TODO: Deprecated since 3.11.0
    const char *xml_alert_new_files = "alert_new_files"; // TODO: Deprecated since 3.11.0
    const char *xml_remove_old_diff = "remove_old_diff"; // Deprecated since 3.8.0
    const char *xml_disabled = "disabled";
    const char *xml_scan_on_start = "scan_on_start";
    const char *xml_prefilter_cmd = "prefilter_cmd";
    const char *xml_skip_nfs = "skip_nfs";
    const char *xml_skip_dev = "skip_dev";
    const char *xml_skip_sys = "skip_sys";
    const char *xml_skip_proc = "skip_proc";
    const char *xml_nodiff = "nodiff";
    const char *xml_restart_audit = "restart_audit";
    const char *xml_windows_audit_interval = "windows_audit_interval";
    const char *xml_max_files_per_second = "max_files_per_second";
#ifdef WIN32
    const char *xml_arch = "arch";
    const char *xml_32bit = "32bit";
    const char *xml_64bit = "64bit";
    const char *xml_both = "both";
#else
    const char *xml_queue_size = "queue_size";
#endif
    const char *xml_whodata_options = "whodata";
    const char *xml_audit_key = "audit_key";
    const char *xml_provider = "provider";
    const char *xml_audit_hc = "startup_healthcheck";
    const char *xml_process_priority = "process_priority";
    const char *xml_synchronization = "synchronization";
    const char *xml_max_eps = "max_eps";
    const char *xml_allow_remote_prefilter_cmd = "allow_remote_prefilter_cmd";
    const char *xml_diff = "diff";

    /* Configuration example
        <directories check_all="yes">/etc,/usr/bin</directories>
        <directories check_owner="yes" check_group="yes" check_perm="yes"
        check_sum="yes">/var/log</directories>
    */

    syscheck_config *syscheck;
    syscheck = (syscheck_config *)configp;
    char prefilter_cmd[OS_MAXSTR] = "";

    if (syscheck->disabled == SK_CONF_UNPARSED) {
        syscheck->disabled = SK_CONF_UNDEFINED;
    }

    if(!syscheck->audit_key) {
        os_calloc(1, sizeof(char *), syscheck->audit_key);
    }
    for (i = 0; node && node[i]; i++) {
        if (!node[i]->element) {
            mwarn(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            mwarn(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }

        /* Get directories */
        else if (strcmp(node[i]->element, xml_directories) == 0) {
            char dirs[OS_MAXSTR];
#ifdef WIN32
            fim_adjust_path(&(node[i]->content));
#endif
            strncpy(dirs, node[i]->content, sizeof(dirs) - 1);
            if (!read_attr(syscheck,
                           dirs,
                           node[i]->attributes,
                           node[i]->values)) {
                return (OS_INVALID);
            }
        }
        /* Get Windows registry */
        else if (strcmp(node[i]->element, xml_registry) == 0) {
#ifdef WIN32
            if (!read_reg(syscheck, node[i]->content, node[i]->attributes, node[i]->values)) {
                return (OS_INVALID);
            }
#endif
        }
        /* Get windows audit interval */
        else if (strcmp(node[i]->element, xml_windows_audit_interval) == 0) {
#ifdef WIN32
            if (!OS_StrIsNum(node[i]->content)) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            syscheck->wdata.interval_scan = atoi(node[i]->content);
#endif
        }

        /*  Store database in memory or in disk.
        *   By default disk.
        */
        else if (strcmp(node[i]->element, xml_database) == 0) {
            if (strcmp(node[i]->content, "memory") == 0) {
                syscheck->database_store = FIM_DB_MEMORY;
            }
            else if (strcmp(node[i]->content, "disk") == 0){
                syscheck->database_store = FIM_DB_DISK;
            }
        }

        /* Get frequency */
        else if (strcmp(node[i]->element, xml_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            syscheck->time = atoi(node[i]->content);
        }
        /* Get scan time */
        else if (strcmp(node[i]->element, xml_scantime) == 0) {
            syscheck->scan_time = OS_IsValidUniqueTime(node[i]->content);
            if (!syscheck->scan_time) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Get scan day */
        else if (strcmp(node[i]->element, xml_scanday) == 0) {
            syscheck->scan_day = OS_IsValidDay(node[i]->content);
            if (!syscheck->scan_day) {
                mwarn(INVALID_DAY, node[i]->content);
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Get file limit */
        else if (strcmp(node[i]->element, xml_file_limit) == 0) {
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }
            for(j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_enabled) == 0) {
                    if (strcmp(children[j]->content, "yes") == 0) {
                        syscheck->file_limit_enabled = true;
                    }
                    else if (strcmp(children[j]->content, "no") == 0) {
                        syscheck->file_limit_enabled = false;
                    }
                    else {
                        mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return (OS_INVALID);
                    }
                }
                else if (strcmp(children[j]->element, xml_entries) == 0) {
                    if (!OS_StrIsNum(children[j]->content)) {
                        mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return (OS_INVALID);
                    }

                    syscheck->file_entry_limit = atoi(children[j]->content);

                    if (syscheck->file_entry_limit < 0) {
                        mdebug2("Maximum value allowed for file_limit is '%d'", MAX_FILE_LIMIT);
                        syscheck->file_entry_limit = MAX_FILE_LIMIT;
                    }
                }
            }

            if (!syscheck->file_limit_enabled) {
                syscheck->file_entry_limit = 0;
            }

            OS_ClearNode(children);
        }

#ifdef WIN32
        // Get registry limit
        else if (strcmp(node[i]->element, xml_registry_limit) == 0) {
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }
            for(j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_enabled) == 0) {
                    if (strcmp(children[j]->content, "yes") == 0) {
                        syscheck->registry_limit_enabled = true;
                    }
                    else if (strcmp(children[j]->content, "no") == 0) {
                        syscheck->registry_limit_enabled = false;
                    }
                    else {
                        mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return (OS_INVALID);
                    }
                }
                else if (strcmp(children[j]->element, xml_entries) == 0) {
                    if (!OS_StrIsNum(children[j]->content)) {
                        mwarn(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return (OS_INVALID);
                    }

                    syscheck->db_entry_registry_limit = atoi(children[j]->content);

                    if (syscheck->db_entry_registry_limit < 0) {
                        mdebug2("Maximum value allowed for registry_limit is '%d'", MAX_FILE_LIMIT);
                        syscheck->db_entry_registry_limit = MAX_FILE_LIMIT;
                    }
                }
            }

            if (!syscheck->registry_limit_enabled) {
                syscheck->db_entry_registry_limit = 0;
            }

            OS_ClearNode(children);
        }
#endif

        /* Get if xml_scan_on_start */
        else if (strcmp(node[i]->element, xml_scan_on_start) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                syscheck->scan_on_start = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                syscheck->scan_on_start = 0;
            } else {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Get if disabled */
        else if (strcmp(node[i]->element, xml_disabled) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                syscheck->disabled = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                syscheck->disabled = 0;
            } else {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }

        /* Getting if skip_nfs. */
        else if (strcmp(node[i]->element,xml_skip_nfs) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.nfs = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.nfs = 0;
            else
            {
                mwarn(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting if skip_dev. */
        else if (strcmp(node[i]->element,xml_skip_dev) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.dev = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.dev = 0;
            else
            {
                mwarn(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting if skip_sys */
        else if (strcmp(node[i]->element,xml_skip_sys) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.sys = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.sys = 0;
            else
            {
                mwarn(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting if skip_proc. */
        else if (strcmp(node[i]->element,xml_skip_proc) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->skip_fs.proc = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->skip_fs.proc = 0;
            else
            {
                mwarn(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }

        /* Getting file/dir ignore */
        else if (strcmp(node[i]->element,xml_ignore) == 0) {
            /* If it is a regex, add it */
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0] && node[i]->values[0]) {
                if (!strcmp(node[i]->attributes[0], "type") && !strcmp(node[i]->values[0], "sregex")) {
                    int result = process_option_regex("ignore", &syscheck->ignore_regex, node[i]);
                    if (result < 1) {
                        return result;
                    }
                } else {
                    mwarn(FIM_INVALID_ATTRIBUTE, node[i]->attributes[0], node[i]->element);
                    return (OS_INVALID);
                }
            } else {
                process_option(&syscheck->ignore, node[i]);
            }
        }

        /* Get registry ignore list for values and keys*/
        else if (strncmp(node[i]->element, xml_registry_ignore, strlen(xml_registry_ignore)) == 0) {
#ifdef WIN32
            int sregex = 0;
            int arch = ARCH_32BIT;
            int value = strcmp(xml_registry_ignore_value, node[i]->element) == 0;

            /* Add if regex */
            if (node[i]->attributes && node[i]->values) {
                int j;

                for (j = 0; node[i]->attributes[j]; j++) {
                    if (strcmp(node[i]->attributes[j], "type") == 0 &&
                    strcmp(node[i]->values[j], "sregex") == 0) {
                        sregex = 1;
                    } else if (strcmp(node[i]->attributes[j], xml_arch) == 0) {
                        if (strcmp(node[i]->values[j], xml_32bit) == 0)
                            arch = ARCH_32BIT;
                        else if  (strcmp(node[i]->values[j], xml_64bit) == 0)
                            arch = ARCH_64BIT;
                        else if (strcmp(node[i]->values[j], xml_both) == 0)
                            arch = ARCH_BOTH;
                        else {
                            mwarn(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                            return OS_INVALID;
                        }
                    } else {
                        mwarn(XML_INVATTR, node[i]->attributes[j], node[i]->content);
                        return OS_INVALID;
                    }
                }
            }

            if (sregex) {
                if (arch != ARCH_BOTH)
                    dump_registry_ignore_regex(syscheck, node[i]->content, arch, value);
                else {
                    dump_registry_ignore_regex(syscheck, node[i]->content, ARCH_32BIT, value);
                    dump_registry_ignore_regex(syscheck, node[i]->content, ARCH_64BIT, value);
                }
            } else {
                if (arch != ARCH_BOTH)
                    dump_registry_ignore(syscheck, node[i]->content, arch, value);
                else {
                    dump_registry_ignore(syscheck, node[i]->content, ARCH_32BIT, value);
                    dump_registry_ignore(syscheck, node[i]->content, ARCH_64BIT, value);
                }
            }

#endif
        /* Getting file/dir nodiff */
        /* This section is checked here for compatibility reasons, nodiff has been moved to the diff section */
        } else if (strcmp(node[i]->element,xml_nodiff) == 0) {
            /* Add if regex */
            if (node[i]->attributes && node[i]->values && node[i]->attributes[0] && node[i]->values[0]) {
                if (!strcmp(node[i]->attributes[0], "type") && !strcmp(node[i]->values[0], "sregex")) {
                    int result = process_option_regex("nodiff", &syscheck->nodiff_regex, node[i]);
                    if (result < 1) {
                        return result;
                    }
                } else {
                    mwarn(FIM_INVALID_ATTRIBUTE, node[i]->attributes[0], node[i]->element);
                    return (OS_INVALID);
                }
            } else {
                process_option(&syscheck->nodiff, node[i]);
            }

        } else if (strcmp(node[i]->element, xml_auto_ignore) == 0) {
            /* auto_ignore is not read here */
        } else if (strcmp(node[i]->element, xml_alert_new_files) == 0) {
            /* alert_new_files option is not read here */
        } else if (strcmp(node[i]->element, xml_prefilter_cmd) == 0) {
            struct stat statbuf;

#ifdef WIN32
            if(!ExpandEnvironmentStrings(node[i]->content, prefilter_cmd, sizeof(prefilter_cmd) - 1)){
                merror("Could not expand the environment variable %s (%ld)", node[i]->content, GetLastError());
                continue;
            }
            str_lowercase(prefilter_cmd);
#else
            strncpy(prefilter_cmd, node[i]->content, sizeof(prefilter_cmd) - 1);
            prefilter_cmd[sizeof(prefilter_cmd) - 1] = '\0';
#endif

            if (strlen(prefilter_cmd) > 0) {
                char statcmd[OS_MAXSTR];
                char *ix;
                strncpy(statcmd, prefilter_cmd, sizeof(statcmd) - 1);
                statcmd[sizeof(statcmd) - 1] = '\0';
                if (NULL != (ix = strchr(statcmd, ' '))) {
                    *ix = '\0';
                }
                if (stat(statcmd, &statbuf) != 0) {
                    mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                }
            }
        } else if (strcmp(node[i]->element, xml_remove_old_diff) == 0) {
            // Deprecated since 3.8.0, aplied by default...
        } else if (strcmp(node[i]->element, xml_restart_audit) == 0) {
            // To be deprecated. This field is now read inside the <whodata> block.
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->restart_audit = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->restart_audit = 0;
            else
            {
                mwarn(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        /* Whodata options */
        else if (strcmp(node[i]->element, xml_whodata_options) == 0) {

            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                continue;
            }

            for (j = 0; children[j]; j++) {
                /* Listen another audit keys */
                if (strcmp(children[j]->element, xml_audit_key) == 0) {
                    int keyit = 0;
                    char *delim = ",";
                    char *key;
                    char *saveptr;
                    key = strtok_r(children[j]->content, delim, &saveptr);

                    while (key) {
                        if (*key) {
                            os_strdup(key, syscheck->audit_key[keyit]);
                            os_realloc(syscheck->audit_key, (keyit + 2) * sizeof(char *), syscheck->audit_key);
                            syscheck->audit_key[keyit + 1] = NULL;
                            key = strtok_r(NULL, delim, &saveptr);
                            keyit++;
                        }
                    }
                } else if (strcmp(children[j]->element, xml_audit_hc) == 0) {
                    if(strcmp(children[j]->content, "yes") == 0)
                        syscheck->audit_healthcheck = 1;
                    else if(strcmp(children[j]->content, "no") == 0)
                        syscheck->audit_healthcheck = 0;
                    else
                    {
                        mwarn(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                } else if (strcmp(children[j]->element, xml_restart_audit) == 0) {
                    if(strcmp(children[j]->content, "yes") == 0)
                        syscheck->restart_audit = 1;
                    else if(strcmp(children[j]->content, "no") == 0)
                        syscheck->restart_audit = 0;
                    else
                    {
                        mwarn(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                } else if (strcmp(children[j]->element, xml_provider) == 0) {
                    if(strcmp(children[j]->content, "ebpf") == 0)
                        syscheck->whodata_provider = EBPF_PROVIDER;
                    else if(strcmp(children[j]->content, "audit") == 0)
                        syscheck->whodata_provider = AUDIT_PROVIDER;
                    else
                    {
                        mwarn(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
#ifndef WIN32
                } else if (strcmp(children[j]->element, xml_queue_size) == 0) {
                    char * end;
                    long value = strtol(children[j]->content, &end, 10);

                    if (*end || value < 10 || value > 1024 * 1024) {
                        merror(XML_VALUEERR, children[j]->element, children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                    else {
                        syscheck->queue_size = value;
                    }
#endif
                } else {
                    mwarn(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        /* Set priority process this value should be between -20 and 19 */
        } else if (strcmp(node[i]->element, xml_process_priority) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < -20 || value > 19 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                syscheck->process_priority = value;
            }
        } else if (strcmp(node[i]->element, xml_synchronization) == 0) {
            children = OS_GetElementsbyNode(xml, node[i]);

            if (children == NULL) {
                continue;
            }

            parse_synchronization(syscheck, children);
            OS_ClearNode(children);
        }
        else if (strcmp(node[i]->element, xml_diff) == 0) {
            children = OS_GetElementsbyNode(xml, node[i]);

            if (children == NULL) {
                continue;
            }

            parse_diff(xml, syscheck, children);
            OS_ClearNode(children);
        }
        else if (strcmp(node[i]->element, xml_max_eps) == 0) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscheck->max_eps = value;
            }
        } /* Allow prefilter cmd */
        else if (strcmp(node[i]->element, xml_allow_remote_prefilter_cmd) == 0) {
            if (modules & CAGENT_CONFIG) {
                mwarn("'%s' option can't be changed using centralized configuration (agent.conf).",
                      xml_allow_remote_prefilter_cmd);
                i++;
                continue;
            }
            if(strcmp(node[i]->content, "yes") == 0)
                syscheck->allow_remote_prefilter_cmd = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                syscheck->allow_remote_prefilter_cmd = 0;
            else {
                mwarn(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if (strcmp(node[i]->element, xml_max_files_per_second) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            syscheck->max_files_per_second = atoi(node[i]->content);

        } else {
            mwarn(XML_INVELEM, node[i]->element);
        }
    }

    // Set prefilter only if it's expressly allowed (ossec.conf in agent side).

    if (prefilter_cmd[0]) {
        if (!(modules & CAGENT_CONFIG) || syscheck->allow_remote_prefilter_cmd) {
            char *save_ptr;
            int total_vectors = 2;

            os_calloc(total_vectors, sizeof(char *), syscheck->prefilter_cmd);
            strtok_r(prefilter_cmd, " ", &save_ptr);
            os_strdup(prefilter_cmd, syscheck->prefilter_cmd[0]);
            syscheck->prefilter_cmd[1] = NULL;

            while (save_ptr != NULL && *save_ptr != '\0') {
                os_realloc(syscheck->prefilter_cmd, (total_vectors + 1) * sizeof(char *), syscheck->prefilter_cmd);
                syscheck->prefilter_cmd[total_vectors] = NULL;
                os_strdup( save_ptr, syscheck->prefilter_cmd[total_vectors - 1]);
                total_vectors++;
                strtok_r(NULL, " ", &save_ptr);
            }
        } else if (!syscheck->allow_remote_prefilter_cmd) {
            mwarn(FIM_WARN_ALLOW_PREFILTER, prefilter_cmd, xml_allow_remote_prefilter_cmd);
        }
    }

    return (0);
}

void fim_adjust_path(char** path){
    const char *system_32       = "system32";
    const char *system_native   = "sysnative";
    char *new_path              = NULL;

    str_lowercase(*path);

    if (strstr(*path, system_native)) {
        new_path = wstr_replace(*path, system_native, system_32);
    }
    if (new_path) {
        mdebug2(FIM_CONVERT_PATH, *path, new_path);
        free(*path);
        *path = new_path;
    }
}

char *syscheck_opts2str(char *buf, int buflen, int opts) {
    int left = buflen;
    int i;
    int check_bits[] = {
        CHECK_SIZE,
        CHECK_PERM,
        CHECK_OWNER,
        CHECK_GROUP,
        CHECK_MTIME,
        CHECK_INODE,
        CHECK_MD5SUM,
        CHECK_SHA1SUM,
        CHECK_SHA256SUM,
        CHECK_ATTRS,
        CHECK_SEECHANGES,
        CHECK_FOLLOW,
        REALTIME_ACTIVE,
        WHODATA_ACTIVE,
        SCHEDULED_ACTIVE,
        CHECK_TYPE,
	    0
	};
    char *check_strings[] = {
        "size",
        "permissions",
        "owner",
        "group",
    	"mtime",
        "inode",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "attributes",
        "report_changes",
        "follow_symbolic_link",
        "realtime",
        "whodata",
        "scheduled",
        "reg_value_type",
	    NULL
	};

    buf[0] = '\0';
    for (i = 0; check_bits[i]; i++) {
	    if (opts & check_bits[i]) {
            if (left < buflen) {
                strncat(buf, " | ", left);
                left -= 3;
            }
            strncat(buf, check_strings[i], left);
            left = buflen - strlen(buf);
	    }
	}

    return buf;
}

int Test_Syscheck(const char * path){
    int fail = 0;
    syscheck_config test_syscheck;

    if (initialize_syscheck_configuration(&test_syscheck) == OS_INVALID) {
        return OS_INVALID;
    }

    if (ReadConfig(CAGENT_CONFIG | CSYSCHECK, path, &test_syscheck, NULL) < 0) {
		merror(RCONFIG_ERROR,"Syscheck", path);
		fail = 1;
	}

    Free_Syscheck(&test_syscheck);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void free_directory(directory_t *dir) {
    if (dir == NULL) {
        return;
    }

    os_free(dir->path);
    os_free(dir->symbolic_links);
    os_free(dir->tag);

    if (dir->filerestrict) {
        OSMatch_FreePattern(dir->filerestrict);
        free(dir->filerestrict);
    }

    free(dir);
}

void Free_Syscheck(syscheck_config * config) {
    if (config) {
        int i;
        if (config->scan_day) {
            free(config->scan_day);
        }
        if (config->scan_time) {
            free(config->scan_time);
        }
        if (config->ignore) {
            for (i=0; config->ignore[i] != NULL; i++) {
                free(config->ignore[i]);
            }
            free(config->ignore);
        }
        if (config->ignore_regex) {
            for (i=0; config->ignore_regex[i] != NULL; i++) {
                OSMatch_FreePattern(config->ignore_regex[i]);
                free(config->ignore_regex[i]);
            }
            free(config->ignore_regex);
        }
        if (config->nodiff) {
            for (i=0; config->nodiff[i] != NULL; i++) {
                free(config->nodiff[i]);
            }
            free(config->nodiff);
        }
        if (config->nodiff_regex) {
            for (i=0; config->nodiff_regex[i] != NULL; i++) {
                OSMatch_FreePattern(config->nodiff_regex[i]);
                free(config->nodiff_regex[i]);
            }
            free(config->nodiff_regex);
        }
        if (config->directories) {
            OSList_Destroy(config->directories);
            config->directories = NULL;
        }
        if (config->wildcards) {
            OSList_Destroy(config->wildcards);
            config->wildcards = NULL;
        }

#ifdef WIN32
        if (config->key_ignore) {
            for (i=0; config->key_ignore[i].entry != NULL; i++) {
                free(config->key_ignore[i].entry);
            }
            free(config->key_ignore);
        }
        if (config->key_ignore_regex) {
            for (i=0; config->key_ignore_regex[i].regex != NULL; i++) {
                OSMatch_FreePattern(config->key_ignore_regex[i].regex);
                free(config->key_ignore_regex[i].regex);
                config->key_ignore_regex[i].regex = NULL;
            }
            free(config->key_ignore_regex);
        }

        if (config->value_ignore) {
            for (i=0; config->value_ignore[i].entry != NULL; i++) {
                free(config->value_ignore[i].entry);
            }
            free(config->value_ignore);
        }

        if (config->value_ignore_regex) {
            for (i=0; config->value_ignore_regex[i].regex != NULL; i++) {
                OSMatch_FreePattern(config->value_ignore_regex[i].regex);
                free(config->value_ignore_regex[i].regex);
                config->value_ignore_regex[i].regex = NULL;
            }
            free(config->value_ignore_regex);
        }

        if (config->registry_nodiff) {
            for (i=0; config->registry_nodiff[i].entry != NULL; i++) {
                free(config->registry_nodiff[i].entry);
            }
            free(config->registry_nodiff);
        }
        if (config->registry_nodiff_regex) {
            for (i=0; config->registry_nodiff_regex[i].regex != NULL; i++) {
                OSMatch_FreePattern(config->registry_nodiff_regex[i].regex);
                free(config->registry_nodiff_regex[i].regex);
                config->registry_nodiff_regex[i].regex = NULL;
            }
            free(config->registry_nodiff_regex);
        }
        if (config->registry) {
            for (i=0; config->registry[i].entry != NULL; i++) {
                free(config->registry[i].entry);
                if (config->registry[i].tag) {
                    free(config->registry[i].tag);
                }
                if (config->registry[i].restrict_key) {
                    OSMatch_FreePattern(config->registry[i].restrict_key);
                    free(config->registry[i].restrict_key);
                    config->registry[i].restrict_key = NULL;
                }
                if (config->registry[i].restrict_value) {
                    OSMatch_FreePattern(config->registry[i].restrict_value);
                    free(config->registry[i].restrict_value);
                    config->registry[i].restrict_value = NULL;
                }
            }
            free(config->registry);
        }
    #endif

        if (config->realtime) {
            if (config->realtime->dirtb) {
                OSHash_Free(config->realtime->dirtb);
            }
#ifdef WIN32
            CloseEventLog(config->realtime->evt);
#endif
            free(config->realtime);
        }
        if (config->prefilter_cmd) {
            free_strarray(config->prefilter_cmd);
        }

        free_strarray(config->audit_key);
    }
}

static char **get_paths_from_env_variable (char *environment_variable) {
    char **paths = NULL;
    char *expandedpath = NULL;
    int i = 0;

#ifdef WIN32
    static const char *DELIM = ";";
    DWORD env_var_size = ExpandEnvironmentStrings(environment_variable, NULL, 0);
    if (env_var_size <= 0) {
        merror(FIM_ERROR_EXPAND_ENV_VAR, environment_variable, GetLastError());
        goto end;
    }
    os_calloc(env_var_size, sizeof(char), expandedpath);
    if(!ExpandEnvironmentStrings(environment_variable, expandedpath, env_var_size)){
        merror(FIM_ERROR_EXPAND_ENV_VAR, environment_variable, GetLastError());
        os_free(expandedpath);
        goto end;
    }
    str_lowercase(expandedpath);
#else
    static const char *DELIM = ":";
    if(environment_variable[0] != '$') {
        // not an environment variable.
        goto end;
    }
    environment_variable++;
    char *aux = getenv(environment_variable);
    if (!aux) {
        merror(FIM_ERROR_EXPAND_ENV_VAR, environment_variable);
        goto end;
    } else {
        os_strdup(aux, expandedpath);
    }
#endif

    /* The env. variable may have multiples paths split by a delimiter */
    paths = w_string_split(expandedpath, DELIM, 0);

    if (paths[0] == NULL) {
        os_strdup(environment_variable, paths[0]);
    }

    for (i = 0; paths[i]; i++){
        paths[i] = w_strtrim(paths[i]);
    }

    os_free(expandedpath);
    return paths;

end:
    os_calloc(2, sizeof(char *), paths);
    os_strdup(environment_variable, paths[0]);
    return paths;
}

static int process_option_regex(char *option, OSMatch ***syscheck_option, xml_node *node) {

    unsigned int counter_opt = 0;
    OSMatch *mt_pt;

    if (!syscheck_option[0]) {
        os_calloc(2, sizeof(OSMatch *), syscheck_option[0]);
        syscheck_option[0][0] = NULL;
        syscheck_option[0][1] = NULL;
    } else {
        while (syscheck_option[0][counter_opt] != NULL) {
            counter_opt++;
        }
        os_realloc(syscheck_option[0], sizeof(OSMatch *) * (counter_opt + 2),
                    syscheck_option[0]);
        syscheck_option[0][counter_opt + 1] = NULL;
    }

    os_calloc(1, sizeof(OSMatch), syscheck_option[0][counter_opt]);
    mdebug1("Found %s regex node %s", option, node->content);

    if (!OSMatch_Compile(node->content, syscheck_option[0][counter_opt], 0)) {
        mt_pt = (OSMatch *)syscheck_option[0][counter_opt];
        merror(REGEX_COMPILE, node->content, mt_pt->error);
        return (0);
    }
    mdebug1("Found %s regex node %s OK?", option, node->content);
    mdebug1("Found %s regex size %d", option, counter_opt);

    return 1;
}

static void process_option(char ***syscheck_option, xml_node *node) {

    unsigned int counter_opt = 0;
    char *clean_path;
    char *dir = strdup(node->content);
    char *tmp_dir;
    char **new_opt = NULL;

    tmp_dir = w_strtrim(dir);
    if (tmp_dir == NULL) {
        os_free(dir);
        return;
    }

    /* We attempt to expand environment variables */
    new_opt = get_paths_from_env_variable(tmp_dir);

    if (syscheck_option[0]) {
        while (syscheck_option[0][counter_opt] != NULL) {
            counter_opt++;
        }
    }

    for (int i = 0; new_opt[i]; i++) {
        if (*new_opt[i] != '\0') {
            clean_path = format_path(new_opt[i]);
            if (clean_path == NULL) {
                mwarn(FIM_WARN_FORMAT_PATH, new_opt[i]);
                os_free(new_opt[i]);
                continue;
            }

            if (!os_IsStrOnArray(dir, syscheck_option[0])) {
                os_realloc(syscheck_option[0], sizeof(char *) * (counter_opt + 2), syscheck_option[0]);
                os_strdup(clean_path, syscheck_option[0][counter_opt]);
                syscheck_option[0][counter_opt + 1] = NULL;
                counter_opt++;
            }
            os_free(clean_path);
        }
        os_free(new_opt[i]);
    }
    os_free(dir);
    os_free(new_opt);
}

static void fim_set_check_all(int *opt) {
    *opt |= CHECK_MD5SUM;
    *opt |= CHECK_SHA1SUM;
    *opt |= CHECK_SHA256SUM;
    *opt |= CHECK_PERM;
    *opt |= CHECK_SIZE;
    *opt |= CHECK_OWNER;
    *opt |= CHECK_GROUP;
    *opt |= CHECK_MTIME;
    *opt |= CHECK_INODE;
#ifdef WIN32
    *opt |= CHECK_ATTRS;
#endif
}
