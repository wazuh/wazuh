/* @(#) $Id: ./src/config/rules-config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle the configuration files
 */

#include "config.h"
#include "shared.h"
#include "global-config.h"

#include "config.h"

static int cmpr(const void *a, const void *b) {
    /*printf("%s - %s\n", *(char **)a, *(char **)b);*/
    return strcmp(*(const char **)a, *(const char **)b);
}

static int file_in_list(unsigned int list_size, char *f_name, char *d_name, char **alist)
{
    unsigned int i = 0;
    for(i=0; (i+1)<list_size; i++)
    {
        if((strcmp(alist[i], f_name) == 0 || strcmp(alist[i], d_name) == 0))
        {
            return(1);
        }
    }
    return(0);
}

int Read_Rules(XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;
    unsigned int ii = 0;

    unsigned int rules_size = 1;
    unsigned int lists_size = 1;
    unsigned int decoders_size = 1;


    char path[PATH_MAX +2];
    char f_name[PATH_MAX +2];
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

    _Config *Config;

    Config = (_Config *)configp;

    /* initialise OSRegex */
    regex.patterns = NULL;
    regex.prts_closure = NULL;
    regex.prts_str = NULL;
    regex.sub_strings = NULL;

    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        /* Mail notification */
        else if((strcmp(node[i]->element, xml_rules_include) == 0) ||
                (strcmp(node[i]->element, xml_rules_rule) == 0))
        {
            rules_size++;
            Config->includes = (char **) realloc(Config->includes,
                                       sizeof(char *)*rules_size);
            if(!Config->includes)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_strdup(node[i]->content,Config->includes[rules_size -2]);
            Config->includes[rules_size -1] = NULL;
            debug1("adding rule: %s", node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_rules_decoders) == 0)
        {
            decoders_size++;
            Config->decoders = (char **) realloc(Config->decoders,
                                       sizeof(char *)*decoders_size);
            if(!Config->decoders)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_strdup(node[i]->content,Config->decoders[decoders_size -2]);
            Config->decoders[decoders_size -1] = NULL;
            debug1("adding decoder: %s", node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_rules_lists) == 0)
        {
            lists_size++;
            Config->lists = (char **) realloc(Config->lists,
                                    sizeof(char *)*lists_size);
            if(!Config->lists)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }
            os_strdup(node[i]->content,Config->lists[lists_size -2]);
            Config->lists[lists_size -1] = NULL;

        }
        else if(strcmp(node[i]->element, xml_rules_decoders_dir) == 0)
        {

            if(node[i]->attributes && node[i]->values)
            {
                while(node[i]->attributes[att_count])
                {
                    if((strcasecmp(node[i]->attributes[att_count], "pattern") == 0))
                    {
                        if(node[i]->values[att_count])
                        {
                            if(!OSRegex_Compile(node[i]->values[att_count], &regex, 0))
                            {
                                merror(CONFIG_ERROR, ARGV0, "pattern in decoders_dir does not compile");
                                merror("%s: ERROR: Regex would not compile", ARGV0);
                                return(-1);
                            }
                        }
                    }
                    att_count++;
                }
            }
            else
            {
                OSRegex_Compile(".xml$", &regex, 0);
            }

            #ifdef TESTRULE
            snprintf(path,PATH_MAX +1,"%s", node[i]->content);
            #else
            snprintf(path,PATH_MAX +1,"%s/%s", DEFAULTDIR, node[i]->content);
            #endif

            f_name[PATH_MAX +1] = '\0';
            dfd = opendir(path);

            if(dfd != NULL) {
                start_point = decoders_size- 1;
                while((entry = readdir(dfd)) != NULL)
                {
                    snprintf(f_name, PATH_MAX +1, "%s/%s", node[i]->content, entry->d_name);

                    /* Just ignore . and ..  */
                    if((strcmp(entry->d_name,".") == 0) || (strcmp(entry->d_name,"..") == 0))
                        continue;

                    /* no dups allowed */
                    if(file_in_list(decoders_size, f_name, entry->d_name, Config->decoders))
                        continue;

                    if(OSRegex_Execute(f_name, &regex))
                    {
                        decoders_size++;
                        Config->decoders= (char **) realloc(Config->decoders, sizeof(char *)*decoders_size);
                        if(!Config->decoders)
                        {
                            merror(MEM_ERROR, ARGV0);
                            OSRegex_FreePattern(&regex);
                            return(-1);
                        }

                        os_strdup(f_name, Config->decoders[decoders_size -2]);
                        Config->decoders[decoders_size -1] = NULL;
                        debug1("adding decoder: %s", f_name);
                    }
                    else
                    {
                        debug1("Regex does not match \"%s\"",  f_name);
                    }
                }

                closedir(dfd);
                /* Sort just then newly added items */
                qsort(Config->decoders + start_point , decoders_size- start_point -1, sizeof(char *), cmpr);
            }
            debug1("decoders_size %d", decoders_size);
            for(ii=0;ii<decoders_size-1;ii++)
                debug1("- %s", Config->decoders[ii]);
        }
        else if(strcmp(node[i]->element, xml_rules_rules_dir) == 0)
        {
            if(node[i]->attributes && node[i]->values)
            {
                while(node[i]->attributes[att_count])
                {
                    if((strcasecmp(node[i]->attributes[att_count], "pattern") == 0))
                    {
                        if(node[i]->values[att_count])
                        {
                            if(!OSRegex_Compile(node[i]->values[att_count], &regex, 0))
                            {
                                merror(CONFIG_ERROR, ARGV0, "pattern in rules_dir does not compile");
                                merror("%s: ERROR: Regex would not compile", ARGV0);
                                return(-1);
                            }
                        }
                    }
                    att_count++;
                }
            }
            else
            {
                OSRegex_Compile(".xml$", &regex, 0);
            }

            #ifdef TESTRULE
            snprintf(path,PATH_MAX +1,"%s", node[i]->content);
            #else
            snprintf(path,PATH_MAX +1,"%s/%s", DEFAULTDIR, node[i]->content);
            #endif

            f_name[PATH_MAX +1] = '\0';
            dfd = opendir(path);

            if(dfd != NULL) {
                start_point = rules_size - 1;
                while((entry = readdir(dfd)) != NULL)
                {
                    snprintf(f_name, PATH_MAX +1, "%s/%s", node[i]->content, entry->d_name);

                    /* Just ignore . and ..  */
                    if((strcmp(entry->d_name,".") == 0) || (strcmp(entry->d_name,"..") == 0))
                        continue;

                    /* no dups allowed */
                    if(file_in_list(rules_size, f_name, entry->d_name, Config->includes))
                        continue;

                    if(OSRegex_Execute(f_name, &regex))
                    {
                        rules_size++;
                        Config->includes = (char **) realloc(Config->includes, sizeof(char *)*rules_size);
                        if(!Config->includes)
                        {
                            merror(MEM_ERROR, ARGV0);
                            OSRegex_FreePattern(&regex);
                            return(-1);
                        }

                        os_strdup(f_name, Config->includes[rules_size -2]);
                        Config->includes[rules_size -1] = NULL;
                        debug1("adding rule: %s", f_name);
                    }
                    else
                    {
                        debug1("Regex does not match \"%s\"",  f_name);
                    }
                }

                closedir(dfd);
                /* Sort just then newly added items */
                qsort(Config->includes + start_point , rules_size - start_point -1, sizeof(char *), cmpr);
            }
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            OSRegex_FreePattern(&regex);
            return(OS_INVALID);
        }
        i++;
    }
    return(0);
}


/* EOF */
