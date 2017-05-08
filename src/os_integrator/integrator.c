/* Copyright (C) 2014 Daniel B. Cid
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */

#include "integrator.h"
#include "os_net/os_net.h"

void OS_IntegratorD(IntegratorConfig **integrator_config)
{
    int s = 0;
    int temp_file_created = 0;
    time_t tm;
    struct tm *p;
    char integration_path[2048 + 1];
    char exec_tmp_file[2048 + 1];
    char exec_full_cmd[4096 + 1];
    FILE *fp;

    file_queue *fileq;
    alert_data *al_data;

    integration_path[2048] = 0;
    exec_tmp_file[2048] = 0;
    exec_full_cmd[4096] = 0;

    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    /* Initating file queue - to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, 0);

    /* Connecting to syslog. */
    while(integrator_config[s])
    {
        integrator_config[s]->enabled = 1;

        snprintf(integration_path, 2048 -1, "%s/%s", INTEGRATORDIRPATH, integrator_config[s]->name);
        if(File_DateofChange(integration_path) > 0)
        {
            os_strdup(integration_path, integrator_config[s]->path);
        }
        else
        {
            integrator_config[s]->enabled = 0;
            merror("%s: ERROR: Unable to enable integration for: '%s'. File not found inside '%s'.",
                   ARGV0, integrator_config[s]->name, INTEGRATORDIRPATH);
            s++;
            continue;
        }

        if(strcmp(integrator_config[s]->name, "slack") == 0)
        {
            if(!integrator_config[s]->hookurl)
            {
                integrator_config[s]->enabled = 0;
                merror("%s: ERROR: Unable to enable integration for: '%s'. Missing hookurl URL.",
                   ARGV0, integrator_config[s]->name);
                s++;
                continue;
            }
        }

        else if(strcmp(integrator_config[s]->name, "pagerduty") == 0)
        {
            if(!integrator_config[s]->apikey)
            {
                integrator_config[s]->enabled = 0;
                merror("%s: ERROR: Unable to enable integration for: '%s'. Missing API Key.",
                   ARGV0, integrator_config[s]->name);
                s++;
                continue;
            }
        }

        else if(strncmp(integrator_config[s]->name, "custom-", 7) == 0)
        {
        }

        else
        {
            integrator_config[s]->enabled = 0;
            merror("%s: ERROR: Invalid integration: '%s'. Not currently supported.", ARGV0, integrator_config[s]->name);
        }

        if(integrator_config[s]->enabled == 1)
        {
            merror("%s: INFO: Enabling integration for: '%s'.",
                   ARGV0, integrator_config[s]->name);
        }

        s++;
    }

    /* Infinite loop reading the alerts and inserting them. */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);


        /* Get message if available (timeout of 5 seconds) */
        debug2("%s: DEBUG: waiting for available alerts...", ARGV0);
        al_data = Read_FileMon(fileq, p, 5);
        if(!al_data)
        {
            continue;
        }

        debug1("%s: DEBUG: sending new alert.", ARGV0);
        temp_file_created = 0;

        /* Sending to the configured integrations */
        s = 0;
        while(integrator_config[s])
        {
            if(integrator_config[s]->enabled == 0)
            {
                s++;
                debug2("%s: DEBUG: skipping: integration disabled", ARGV0);
                continue;
            }

            /* Looking if location is set */
            if(integrator_config[s]->location)
            {
                if(!OSMatch_Execute(al_data->location,
                                   strlen(al_data->location),
                                   integrator_config[s]->location))
                {
                    debug2("%s: DEBUG: skipping: location doesn't match", ARGV0);
                    s++; continue;
                }
            }

            /* Looking for the level */
            if(integrator_config[s]->level)
            {
                if(al_data->level < integrator_config[s]->level)
                {
                    debug2("%s: DEBUG: skipping: alert level is too low", ARGV0);
                    s++; continue;
                }
            }

            /* Looking for the group */
            if(integrator_config[s]->group)
            {
                if(!OSMatch_Execute(al_data->group,
                            strlen(al_data->group),
                            integrator_config[s]->group))
                {
                    debug2("%s: DEBUG: skipping: group doesn't match", ARGV0);
                    s++; continue;
                }
            }

            /* Looking for the rule */
            if(integrator_config[s]->rule_id)
            {
                /* match any rule in array */
                int id_i = 0;
                int rule_match = -1;

                while(integrator_config[s]->rule_id[id_i])
                {
                    if(al_data->rule == integrator_config[s]->rule_id[id_i])
                    {
                        rule_match = id_i;
                        break;
                    }

                    id_i++;
                }

                /* skip integration if none are matched */
                if(rule_match == -1)
                {
                    debug2("%s: DEBUG: skipping: rule doesn't match", ARGV0);
                    s++; continue;
                }
            }

            /* Create temp file once per alert. */
            if(temp_file_created == 0)
            {
                snprintf(exec_tmp_file, 2048, "/tmp/%s-%d-%ld.alert",
                         integrator_config[s]->name, (int)time(0), (long int)os_random());

                fp = fopen(exec_tmp_file, "w");
                if(!fp)
                {
                    debug2("%s: ERROR: file %s couldn't be created.", ARGV0, exec_tmp_file);
                    exec_tmp_file[0] = '\0';
                }
                else
                {
                    int log_count = 0;
                    char *tmpstr = al_data->log[0];
                    while(*tmpstr != '\0')
                    {
                        if(*tmpstr == '\'')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == '\\')
                        {
                            *tmpstr = '/';
                        }
                        else if(*tmpstr == '`')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == '"')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == ';')
                        {
                            *tmpstr = ',';
                        }
                        else if(*tmpstr == '!')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == '$')
                        {
                            *tmpstr = ' ';
                        }

                        else if(*tmpstr < 32 || *tmpstr > 122)
                        {
                            *tmpstr = ' ';
                        }
                        log_count++;
                        tmpstr++;

                        if(log_count >= (int)integrator_config[s]->max_log)
                        {
                            *tmpstr='\0';
                            *(tmpstr -1)='.';
                            *(tmpstr -2)='.';
                            *(tmpstr -3)='.';
                            break;
                        }
                    }
                    if(al_data->srcip != NULL)
                    {
                        tmpstr = al_data->srcip;
                        while(*tmpstr != '\0')
                        {
                            if(*tmpstr == '\'')
                            {
                                *tmpstr = ' ';
                            }
                            else if(*tmpstr == '\\')
                            {
                                *tmpstr = ' ';
                            }
                            else if(*tmpstr == '`')
                            {
                                *tmpstr = ' ';
                            }
                            else if(*tmpstr == ' ')
                            {
                            }
                            else if(*tmpstr < 46 || *tmpstr > 122)
                            {
                                *tmpstr = ' ';
                            }

                            tmpstr++;
                        }
                    }
                    fprintf(fp, "alertdate='%s'\nalertlocation='%s'\nruleid='%d'\nalertlevel='%d'\nruledescription='%s'\nalertlog='%s'\nsrcip='%s'", al_data->date, al_data->location, al_data->rule, al_data->level, al_data->comment, al_data->log[0], al_data->srcip == NULL?"":al_data->srcip);
                    temp_file_created = 1;
                    debug2("%s: DEBUG: file %s was written.", ARGV0, exec_tmp_file);
                    fclose(fp);
                }
            }

            if(temp_file_created == 1)
            {
                snprintf(exec_full_cmd, 4095, "%s '%s' '%s' '%s' > /dev/null 2>&1", integrator_config[s]->path, exec_tmp_file, integrator_config[s]->apikey == NULL?"":integrator_config[s]->apikey, integrator_config[s]->hookurl==NULL?"":integrator_config[s]->hookurl);
                debug2("%s: DEBUG: Running: %s", ARGV0, exec_full_cmd);
                if(system(exec_full_cmd) != 0)
                {
                    integrator_config[s]->enabled = 0;
                    merror("%s: ERROR: Unable to run integration for %s -> %s", ARGV0,  integrator_config[s]->name, integrator_config[s]->path);
                    s++;
                    continue;
                }
                debug1("%s: DEBUG: Command run succesfully", ARGV0);
            }
            s++;
        }

        /* Clearing the memory */
        if(temp_file_created == 1)
            unlink(exec_tmp_file);
        FreeAlertData(al_data);
    }
}
