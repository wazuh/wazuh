/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "config.h"
#include "shared.h"
#include "global-config.h"
#include "../analysisd/logmsg.h"

#ifndef WIN32

#define DEFAULT_RULE_DIR "ruleset/rules"
#define DEFAULT_DECODER_DIR "ruleset/decoders"

/* Prototypes */
static int cmpr(const void *a, const void *b) __attribute__((nonnull));
static int file_in_list(unsigned int list_size, char *f_name, char *d_name, char **alist) __attribute__((nonnull));


static int cmpr(const void *a, const void *b)
{
    const char * file_a;
    const char * file_b;
    const char *_a = *(const char **)a;
    const char *_b = *(const char **)b;

    file_a = strrchr((const char *)_a, '/');
    file_b = strrchr((const char *)_b, '/');

    if ( file_a != NULL )
      file_a++;
    else
      file_a = _a;

    if ( file_b != NULL )
      file_b++;
    else
      file_b = _b;

    return strcmp(file_a, file_b);
}

static int file_in_list(unsigned int list_size, char *f_name, char *d_name, char **alist)
{
    unsigned int i = 0;
    for (i = 0; (i + 1) < list_size; i++) {
        if ((strcmp(alist[i], f_name) == 0 || strcmp(alist[i], d_name) == 0)) {
            return (1);
        }
    }
    return (0);
}

int Read_Rules(XML_NODE node, void *configp, void * list)
{
    int i = 0;
    int retval = 0;

    unsigned int rules_size = 1;
    unsigned int lists_size = 1;
    unsigned int decoders_size = 1;
    unsigned int rules_exclude_size = 1;
    unsigned int decoders_exclude_size = 1;
    unsigned int dec_dirs_size = 1;
    unsigned int rul_dirs_size = 1;

    unsigned int total_decoders_excluded = 0;
    unsigned int total_rules_excluded = 0;

    char **exclude_rules = NULL;
    char **exclude_decoders = NULL;

    char **decoder_dirs = NULL;
    char **rules_dirs = NULL;
    char **decoder_dirs_pattern = NULL;
    char **rules_dirs_pattern = NULL;

    char path[PATH_MAX + 2];
    char f_name[PATH_MAX + 2];
    int att_count = 0;
    struct dirent *entry = NULL;
    DIR *dfd;
    OSRegex regex;

    os_calloc(1, sizeof(char*), exclude_rules);
    os_calloc(1, sizeof(char*), exclude_decoders);
    os_calloc(1, sizeof(char*), decoder_dirs);
    os_calloc(1, sizeof(char*), rules_dirs);
    os_calloc(1, sizeof(char*), decoder_dirs_pattern);
    os_calloc(1, sizeof(char*), rules_dirs_pattern);

    /* XML definitions */
    const char *xml_rules_rule = "rule_include";
    const char *xml_rules_rules_dir = "rule_dir";
    const char *xml_rules_lists = "list";
    const char *xml_rules_decoders = "decoder_include";
    const char *xml_rules_decoders_dir = "decoder_dir";
    const char *xml_rules_exclude = "rule_exclude";
    const char *xml_rules_exclude_decoder = "decoder_exclude";

    _Config *Config;

    Config = (_Config *)configp;
    OSList * list_msg = (OSList *) list;

    /* Initialize OSRegex */
    memset(&regex, 0, sizeof(OSRegex));
    regex.patterns = NULL;
    regex.prts_closure = NULL;
    regex.d_prts_str = NULL;
    regex.d_sub_strings = NULL;
    w_mutex_init(&regex.mutex, NULL);

    if (node) {
        while (node[i]) {
            if (!node[i]->element) {
                smerror(list_msg, XML_ELEMNULL);
                retval = OS_INVALID;
                goto cleanup;
            } else if (!node[i]->content) {
                smerror(list_msg, XML_VALUENULL, node[i]->element);
                retval = OS_INVALID;
                goto cleanup;
            }
            // <rule_include>
            else if (strcmp(node[i]->element, xml_rules_rule) == 0) {
                rules_size++;
                f_name[PATH_MAX + 1] = '\0';
                os_realloc(Config->includes, sizeof(char *)*rules_size, Config->includes);

                /* If no directory in the rulefile, add the default */
                if ((strchr(node[i]->content, '/')) == NULL) {
                    /* Build the rule file name + path */
                    snprintf(f_name, PATH_MAX + 1, "%s/%s", DEFAULT_RULE_DIR, node[i]->content);
                } else {
                    snprintf(f_name, PATH_MAX + 1, "%s", node[i]->content);
                }

                os_strdup(f_name, Config->includes[rules_size - 2]);
                Config->includes[rules_size - 1] = NULL;
                mdebug1("Adding rule: %s", f_name);
            // <decoder_include>
            } else if (strcmp(node[i]->element, xml_rules_decoders) == 0) {
                decoders_size++;
                f_name[PATH_MAX + 1] = '\0';
                os_realloc(Config->decoders, sizeof(char *)*decoders_size, Config->decoders);

                /* If no directory in the decoder file, add the default */
                if ((strchr(node[i]->content, '/')) == NULL) {
                    /* Build the decoder file name + path */
                    snprintf(f_name, PATH_MAX + 1, "%s/%s", DEFAULT_DECODER_DIR, node[i]->content);
                } else {
                    snprintf(f_name, PATH_MAX + 1, "%s", node[i]->content);
                }

                os_strdup(f_name, Config->decoders[decoders_size - 2]);
                Config->decoders[decoders_size - 1] = NULL;
                mdebug1("Adding decoder: %s", f_name);
            // <list>
            } else if (strcmp(node[i]->element, xml_rules_lists) == 0) {
                lists_size++;
                os_realloc(Config->lists, sizeof(char *)*lists_size, Config->lists);
                os_strdup(node[i]->content, Config->lists[lists_size - 2]);
                Config->lists[lists_size - 1] = NULL;
            // <rule_exclude>
            } else if (strcmp(node[i]->element, xml_rules_exclude) == 0) {
                rules_exclude_size++;
                os_realloc(exclude_rules, sizeof(char *)*rules_exclude_size, exclude_rules);
                os_strdup(node[i]->content, exclude_rules[rules_exclude_size - 2]);
                exclude_rules[rules_exclude_size - 1] = NULL;
                mdebug1("Excluding rule: %s", node[i]->content);
            // <decoder_exclude>
            } else if (strcmp(node[i]->element, xml_rules_exclude_decoder) == 0) {
                decoders_exclude_size++;
                os_realloc(exclude_decoders, sizeof(char *)*decoders_exclude_size, exclude_decoders);
                os_strdup(node[i]->content, exclude_decoders[decoders_exclude_size - 2]);
                exclude_decoders[decoders_exclude_size - 1] = NULL;
                mdebug1("Excluding decoder: %s", node[i]->content);
            // <decoder_dir>
            } else if (strcmp(node[i]->element, xml_rules_decoders_dir) == 0) {
                dec_dirs_size++;
                os_realloc(decoder_dirs, sizeof(char *)*dec_dirs_size, decoder_dirs);
                os_realloc(decoder_dirs_pattern, sizeof(char *)*dec_dirs_size, decoder_dirs_pattern);
                os_strdup(node[i]->content, decoder_dirs[dec_dirs_size - 2]);
                decoder_dirs[dec_dirs_size - 1] = NULL;
                decoder_dirs_pattern[dec_dirs_size - 1] = NULL;
                mdebug1("Adding decoder dir: %s", node[i]->content);

                if (node[i]->attributes && node[i]->values) {
                    att_count = 0;
                    while (node[i]->attributes[att_count]) {
                        if ((strcasecmp(node[i]->attributes[att_count], "pattern") == 0)) {
                            if (node[i]->values[att_count]) {
                                os_strdup(node[i]->values[att_count], decoder_dirs_pattern[dec_dirs_size - 2]);
                            }
                        }
                        att_count++;
                    }
                } else {
                    os_strdup(".xml$", decoder_dirs_pattern[dec_dirs_size - 2]);
                }
            // <rule_dir>
            } else if (strcmp(node[i]->element, xml_rules_rules_dir) == 0) {
                rul_dirs_size++;
                os_realloc(rules_dirs, sizeof(char *)*rul_dirs_size, rules_dirs);
                os_realloc(rules_dirs_pattern, sizeof(char *)*rul_dirs_size, rules_dirs_pattern);

                if (!rules_dirs) {
                    smerror(list_msg, MEM_ERROR, errno, strerror(errno));
                    retval = OS_INVALID;
                    goto cleanup;
                }

                os_strdup(node[i]->content, rules_dirs[rul_dirs_size - 2]);
                rules_dirs[rul_dirs_size - 1] = NULL;
                rules_dirs_pattern[rul_dirs_size - 1] = NULL;
                mdebug1("Adding rules dir: %s", node[i]->content);

                if (node[i]->attributes && node[i]->values) {
                    att_count = 0;
                    while (node[i]->attributes[att_count]) {
                        if ((strcasecmp(node[i]->attributes[att_count], "pattern") == 0)) {
                            if (node[i]->values[att_count]) {
                                os_strdup(node[i]->values[att_count], rules_dirs_pattern[rul_dirs_size - 2]);
                            }
                        }
                        att_count++;
                    }
                } else {
                    os_strdup(".xml$", rules_dirs_pattern[rul_dirs_size - 2]);
                }
            } else {
                smerror(list_msg, XML_INVELEM, node[i]->element);
                OSRegex_FreePattern(&regex);
                retval = OS_INVALID;
                goto cleanup;
            }

            i++;
        }
    }

    /* If we haven't specified the decoders directory, use default */
    if (!decoder_dirs[0]) {
        dec_dirs_size++;
        os_realloc(decoder_dirs, sizeof(char *)*dec_dirs_size, decoder_dirs);
        os_realloc(decoder_dirs_pattern, sizeof(char *)*dec_dirs_size, decoder_dirs_pattern);
        os_strdup(DEFAULT_DECODER_DIR, decoder_dirs[dec_dirs_size - 2]);
        decoder_dirs[dec_dirs_size - 1] = NULL;
        decoder_dirs_pattern[dec_dirs_size - 1] = NULL;
        mdebug1("Adding decoder dir: %s", DEFAULT_DECODER_DIR);

        os_strdup(".xml$", decoder_dirs_pattern[dec_dirs_size - 2]);
    }

    /* If we haven't specified the rules directory, use default*/
    if (!rules_dirs[0]) {
        rul_dirs_size++;
        os_realloc(rules_dirs, sizeof(char *)*rul_dirs_size, rules_dirs);
        os_realloc(rules_dirs_pattern, sizeof(char *)*rul_dirs_size, rules_dirs_pattern);
        os_strdup(DEFAULT_RULE_DIR, rules_dirs[rul_dirs_size - 2]);
        rules_dirs[rul_dirs_size - 1] = NULL;
        rules_dirs_pattern[rul_dirs_size - 1] = NULL;
        mdebug1("Adding rules dir: %s", DEFAULT_RULE_DIR);

        os_strdup(".xml$", rules_dirs_pattern[rul_dirs_size - 2]);
    }

    // Read decoder list

    for (i = 0; decoder_dirs[i]; i++) {
        mdebug1("Reading decoders folder: %s", decoder_dirs[i]);
        snprintf(path, PATH_MAX + 1, "%s", decoder_dirs[i]);

        OSRegex_FreePattern(&regex);
        if (!OSRegex_Compile(decoder_dirs_pattern[i], &regex, 0)) {
            merror(CONFIG_ERROR, "pattern in decoder_dir does not compile");
            merror("Regex would not compile");
            retval = OS_INVALID;
            goto cleanup;
        }

        f_name[PATH_MAX + 1] = '\0';
        dfd = wopendir(path);

        if (dfd != NULL) {

            while ((entry = readdir(dfd)) != NULL) {
                snprintf(f_name, PATH_MAX + 1, "%s/%s", decoder_dirs[i], entry->d_name);

                // Ignore . and ..
                if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
                    continue;
                }

                // Exclude
                if (file_in_list(decoders_exclude_size, f_name, entry->d_name, exclude_decoders)) {
                    total_decoders_excluded++;
                    continue;
                }

                // No duplicates allowed
                if (file_in_list(decoders_size, f_name, entry->d_name, Config->decoders)) {
                    continue;
                }

                if (OSRegex_Execute(f_name, &regex)) {
                    decoders_size++;
                    os_realloc(Config->decoders, sizeof(char *)*decoders_size, Config->decoders);
                    os_strdup(f_name, Config->decoders[decoders_size - 2]);
                    Config->decoders[decoders_size - 1] = NULL;
                    mdebug1("Adding decoder: %s", f_name);
                } else {
                    mdebug1("Regex does not match \"%s\"",  f_name);
                }
            }

            closedir(dfd);
        }
    }

    // Read rules list

    for (i = 0; rules_dirs[i]; i++) {
        mdebug1("Reading rules folder: %s", rules_dirs[i]);
        snprintf(path, PATH_MAX + 1, "%s", rules_dirs[i]);

        OSRegex_FreePattern(&regex);
        if (!OSRegex_Compile(rules_dirs_pattern[i], &regex, 0)) {
            merror(CONFIG_ERROR, "pattern in rules_dir does not compile");
            merror("Regex would not compile");
            retval = OS_INVALID;
            goto cleanup;
        }

        f_name[PATH_MAX + 1] = '\0';
        dfd = wopendir(path);

        if (dfd != NULL) {

          while ((entry = readdir(dfd)) != NULL) {
              snprintf(f_name, PATH_MAX + 1, "%s/%s", rules_dirs[i], entry->d_name);

              // Ignore . and ..
              if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
                  continue;
              }

              // Exclude
              if (file_in_list(rules_exclude_size, f_name, entry->d_name, exclude_rules)) {
                  total_rules_excluded++;
                  continue;
              }

              // No duplicates allowed
              if (file_in_list(rules_size, f_name, entry->d_name, Config->includes)) {
                  continue;
              }

              if (OSRegex_Execute(f_name, &regex)) {
                  rules_size++;
                  os_realloc(Config->includes, sizeof(char *)*rules_size, Config->includes);
                  os_strdup(f_name, Config->includes[rules_size - 2]);
                  Config->includes[rules_size - 1] = NULL;
                  mdebug1("Adding rule: %s", f_name);
              } else {
                  mdebug1("Regex does not match \"%s\"",  f_name);
              }
          }

          closedir(dfd);
        }
    }

    // Sort added items
    qsort(Config->includes, rules_size - 1, sizeof(char *), cmpr);
    qsort(Config->decoders, decoders_size - 1, sizeof(char *), cmpr);

    mdebug1("Decoders added: %d / excluded: %d", decoders_size - 1, total_decoders_excluded);
    mdebug1("Rules added: %d / excluded: %d", rules_size - 1, total_rules_excluded);

    OSRegex_FreePattern(&regex);

cleanup:
    free_strarray(exclude_decoders);
    free_strarray(exclude_rules);
    free_strarray(decoder_dirs);
    free_strarray(rules_dirs);
    free_strarray(decoder_dirs_pattern);
    free_strarray(rules_dirs_pattern);

    return retval;
}
#endif
