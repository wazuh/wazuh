/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "config.h"
#include "shared.h"
#include "global-config.h"

/* Prototypes */
static int cmpr(const void *a, const void *b) __attribute__((nonnull));
static int file_in_list(unsigned int list_size, char *f_name, char *d_name, char **alist) __attribute__((nonnull));


static int cmpr(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
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

int Read_Rules(XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;

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
    unsigned int start_point = 0;
    int att_count = 0;
    struct dirent *entry;
    DIR *dfd;
    OSRegex regex;

    /* XML definitions */
    const char *xml_rules_include = "include";
    const char *xml_rules_rule = "rule";
    const char *xml_rules_rules_dir = "rule_dir";
    const char *xml_rules_lists = "list";
    const char *xml_rules_decoders = "decoder";
    const char *xml_rules_decoders_dir = "decoder_dir";
    const char *xml_rules_exclude = "exclude";
    const char *xml_rules_exclude_decoder = "exclude_decoder";

    _Config *Config;

    Config = (_Config *)configp;

    /* Initialize OSRegex */
    regex.patterns = NULL;
    regex.prts_closure = NULL;
    regex.prts_str = NULL;
    regex.sub_strings = NULL;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL, __local_name);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, __local_name, node[i]->element);
            return (OS_INVALID);
        }
        //<include> & <rule>
        else if ((strcmp(node[i]->element, xml_rules_include) == 0) ||
                 (strcmp(node[i]->element, xml_rules_rule) == 0)) {
            rules_size++;
            Config->includes = (char **) realloc(Config->includes,
                                                 sizeof(char *)*rules_size);
            if (!Config->includes) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, Config->includes[rules_size - 2]);
            Config->includes[rules_size - 1] = NULL;
            debug1("adding rule: %s", node[i]->content);
        //<decoder>
        } else if (strcmp(node[i]->element, xml_rules_decoders) == 0) {
            decoders_size++;
            Config->decoders = (char **) realloc(Config->decoders,
                                                 sizeof(char *)*decoders_size);
            if (!Config->decoders) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, Config->decoders[decoders_size - 2]);
            Config->decoders[decoders_size - 1] = NULL;
            debug1("adding decoder: %s", node[i]->content);
        //<list>
        } else if (strcmp(node[i]->element, xml_rules_lists) == 0) {
            lists_size++;
            Config->lists = (char **) realloc(Config->lists,
                                              sizeof(char *)*lists_size);
            if (!Config->lists) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, Config->lists[lists_size - 2]);
            Config->lists[lists_size - 1] = NULL;
        //<exclude>
        } else if (strcmp(node[i]->element, xml_rules_exclude) == 0) {
            rules_exclude_size++;
            exclude_rules = (char **) realloc(exclude_rules, sizeof(char *)*rules_exclude_size);

            if (!exclude_rules) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, exclude_rules[rules_exclude_size - 2]);
            exclude_rules[rules_exclude_size - 1] = NULL;
            debug1("excluding rule: %s", node[i]->content);
        //<exclude_decoder>
        } else if (strcmp(node[i]->element, xml_rules_exclude_decoder) == 0) {
            decoders_exclude_size++;
            exclude_decoders = (char **) realloc(exclude_decoders, sizeof(char *)*decoders_exclude_size);

            if (!exclude_decoders) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, exclude_decoders[decoders_exclude_size - 2]);
            exclude_decoders[decoders_exclude_size - 1] = NULL;
            debug1("excluding decoder: %s", node[i]->content);
        //<decoder_dir>
        } else if (strcmp(node[i]->element, xml_rules_decoders_dir) == 0) {
            dec_dirs_size++;
            decoder_dirs = (char **) realloc(decoder_dirs, sizeof(char *)*dec_dirs_size);
            decoder_dirs_pattern = (char **) realloc(decoder_dirs_pattern, sizeof(char *)*dec_dirs_size);

            if (!decoder_dirs || !decoder_dirs_pattern) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, decoder_dirs[dec_dirs_size - 2]);
            decoder_dirs[dec_dirs_size - 1] = NULL;
            decoder_dirs_pattern[dec_dirs_size - 1] = NULL;
            debug1("adding decoder dir: %s", node[i]->content);

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
        //<rule_dir>
        } else if (strcmp(node[i]->element, xml_rules_rules_dir) == 0) {
            rul_dirs_size++;
            rules_dirs = (char **) realloc(rules_dirs, sizeof(char *)*rul_dirs_size);
            rules_dirs_pattern = (char **) realloc(rules_dirs_pattern, sizeof(char *)*rul_dirs_size);

            if (!rules_dirs) {
                merror(MEM_ERROR, __local_name, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_strdup(node[i]->content, rules_dirs[rul_dirs_size - 2]);
            rules_dirs[rul_dirs_size - 1] = NULL;
            rules_dirs_pattern[rul_dirs_size - 1] = NULL;
            debug1("adding rules dir: %s", node[i]->content);

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
            merror(XML_INVELEM, __local_name, node[i]->element);
            OSRegex_FreePattern(&regex);
            return (OS_INVALID);
        }

        i++;
    }

    // Read decoder list

    for (i = 0; decoder_dirs[i]; i++) {
        debug1("reading decoders folder: %s", decoder_dirs[i]);
        #ifdef TESTRULE
          snprintf(path, PATH_MAX + 1, "%s", decoder_dirs[i]);
        #else
          snprintf(path, PATH_MAX + 1, "%s/%s", DEFAULTDIR, decoder_dirs[i]);
        #endif

        if (!OSRegex_Compile(decoder_dirs_pattern[i], &regex, 0)) {
            merror(CONFIG_ERROR, __local_name, "pattern in decoder_dir does not compile");
            merror("%s: ERROR: Regex would not compile", __local_name);
            return (-1);
        }

        f_name[PATH_MAX + 1] = '\0';
        dfd = opendir(path);

        if (dfd != NULL) {
            start_point = decoders_size - 1;
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
                    Config->decoders = (char **) realloc(Config->decoders, sizeof(char *)*decoders_size);
                    if (!Config->decoders) {
                        merror(MEM_ERROR, __local_name, errno, strerror(errno));
                        OSRegex_FreePattern(&regex);
                        closedir(dfd);
                        return (-1);
                    }

                    os_strdup(f_name, Config->decoders[decoders_size - 2]);
                    Config->decoders[decoders_size - 1] = NULL;
                    debug1("adding decoder: %s", f_name);
                } else {
                    debug1("Regex does not match \"%s\"",  f_name);
                }
            }

            closedir(dfd);
            // Sort just then newly added items
            qsort(Config->decoders + start_point , decoders_size - start_point - 1, sizeof(char *), cmpr);
        }
    }

    // Read rules list

    for (i = 0; rules_dirs[i]; i++) {
        debug1("reading rules folder: %s", rules_dirs[i]);
        #ifdef TESTRULE
          snprintf(path, PATH_MAX + 1, "%s", rules_dirs[i]);
        #else
          snprintf(path, PATH_MAX + 1, "%s/%s", DEFAULTDIR, rules_dirs[i]);
        #endif

        if (!OSRegex_Compile(rules_dirs_pattern[i], &regex, 0)) {
            merror(CONFIG_ERROR, __local_name, "pattern in rules_dir does not compile");
            merror("%s: ERROR: Regex would not compile", __local_name);
            return (-1);
        }

        f_name[PATH_MAX + 1] = '\0';
        dfd = opendir(path);

        if (dfd != NULL) {
          start_point = rules_size - 1;
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
                  Config->includes = (char **) realloc(Config->includes, sizeof(char *)*rules_size);
                  if (!Config->includes) {
                      merror(MEM_ERROR, __local_name, errno, strerror(errno));
                      OSRegex_FreePattern(&regex);
                      closedir(dfd);
                      return (-1);
                  }

                  os_strdup(f_name, Config->includes[rules_size - 2]);
                  Config->includes[rules_size - 1] = NULL;
                  debug1("adding rule: %s", f_name);
              } else {
                  debug1("Regex does not match \"%s\"",  f_name);
              }
          }

          closedir(dfd);
          // Sort just then newly added items
          qsort(Config->includes + start_point , rules_size - start_point - 1, sizeof(char *), cmpr);
        }
    }

    debug1("decoders added: %d / excluded: %d", decoders_size, total_decoders_excluded);
    debug1("rules added: %d / excluded: %d", rules_size, total_rules_excluded);

    OSRegex_FreePattern(&regex);
    free(exclude_decoders);
    free(exclude_rules);
    free(decoder_dirs);
    free(rules_dirs);
    free(decoder_dirs_pattern);
    free(rules_dirs_pattern);

    return (0);
}
