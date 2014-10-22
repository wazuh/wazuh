/* @(#) $Id: ./src/shared/report_op.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"



/** Helper functions. */
static void l_print_out(const char *msg, ...) __attribute__((format(printf,1,2))) __attribute__((nonnull));
static void *_os_report_sort_compare(void *d1, void *d2) __attribute__((nonnull));
static void _os_header_print(int t, const char *hname) __attribute__((nonnull));
static int _os_report_str_int_compare(const char *str, int id) __attribute__((nonnull));
static int _os_report_check_filters(const alert_data *al_data, const report_filter *r_filter) __attribute__((nonnull));
static int _report_filter_value(const char *filter_by, int prev_filter) __attribute__((nonnull));
static int _os_report_print_related(int print_related, OSList *st_data) __attribute__((nonnull));
static int _os_report_add_tostore(const char *key, OSStore *top, void *data) __attribute__((nonnull(1,2)));
static FILE *__g_rtype = NULL;

static void l_print_out(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

    if(__g_rtype)
    {
        (void)vfprintf(__g_rtype, msg, args);
        (void)fprintf(__g_rtype, "\r\n");
    }
    else
    {
        (void)vfprintf(stderr, msg, args);
        (void)fprintf(stderr, "\r\n");
    }
    va_end(args);
}


/* Sort function used by OSStore sort.
 * Returns if d1 > d2.
 */
static void *_os_report_sort_compare(void *d1, void *d2)
{
   OSList *d1l = (OSList *)d1;
   OSList *d2l = (OSList *)d2;

   if(d1l->currently_size > d2l->currently_size)
   {
       return(d1l);
   }

   return(NULL);
}


/* Print output header. */
static void _os_header_print(int t, const char *hname)
{
    if(!t)
    {
        l_print_out("Top entries for '%s':", hname);
        l_print_out("------------------------------------------------");
    }
    else
    {
        l_print_out("Related entries for '%s':", hname);
        l_print_out("------------------------------------------------");
    }
}


/* Compares if the id is present in the string. */
static int _os_report_str_int_compare(const char *str, int id)
{
    int pt_check = 0;

    do
    {
        if((*str == ',')||(*str == ' '))
        {
            pt_check = 0;
            continue;
        }
        else if(*str == '\0')
        {
            break;
        }
        else if(isdigit((int)*str))
        {
            if(pt_check == 0)
            {
                if(id == atoi(str))
                {
                    return(1);
                }
            }
            pt_check = 1;
        }
        else
        {
            return(-1);
        }
    }while(*str++ != '\0');

    return(0);
}



/* Check if the al_data should be filtered. */
static int _os_report_check_filters(const alert_data *al_data, const report_filter *r_filter)
{
    /* Checking for the filters. */
    if(r_filter->group)
    {
	if(al_data->group)	/* Probably unnecessary, all (?) alerts should have groups) */
	{
        	if(!strstr(al_data->group, r_filter->group))
        	{
            		return(0);
        	}
	}
    }
    if(r_filter->rule)
    {
        if(_os_report_str_int_compare(r_filter->rule, al_data->rule) != 1)
        {
            return(0);
        }
    }
    if(r_filter->location)
    {
        if(!OS_Match(r_filter->location, al_data->location))
        {
            return(0);
        }
    }
    if(r_filter->level)
    {
        if(al_data->level < atoi(r_filter->level))
        {
            return(0);
        }
    }
    if(r_filter->srcip)
    {

	if(al_data->srcip)
	{
        	if(!strstr(al_data->srcip, r_filter->srcip))
        	{
           		return(0);
        	}
	}
    }
    if(r_filter->user)
    {
	if(al_data->user)
	{
        	if(!strstr(al_data->user, r_filter->user))
        	{
            		return(0);
        	}
	}
    }
    if(r_filter->files)
    {
	if(al_data->filename)
	{
        	if(!strstr(al_data->filename, r_filter->files))
        	{
            		return(0);
        	}
	}
    }
    return(1);
}



/* Sets the proper value for the related entries. */
static int _report_filter_value(const char *filter_by, int prev_filter)
{
    if(strcmp(filter_by, "group") == 0)
    {
        if(!(prev_filter & REPORT_REL_GROUP))
        {
            prev_filter|=REPORT_REL_GROUP;
        }
        return(prev_filter);
    }
    else if(strcmp(filter_by, "rule") == 0)
    {
        if(!(prev_filter & REPORT_REL_RULE))
        {
            prev_filter|=REPORT_REL_RULE;
        }
        return(prev_filter);
    }
    else if(strcmp(filter_by, "level") == 0)
    {
        if(!(prev_filter & REPORT_REL_LEVEL))
        {
            prev_filter|=REPORT_REL_LEVEL;
        }
        return(prev_filter);
    }
    else if(strcmp(filter_by, "location") == 0)
    {
        if(!(prev_filter & REPORT_REL_LOCATION))
        {
            prev_filter|=REPORT_REL_LOCATION;
        }
        return(prev_filter);
    }
    else if(strcmp(filter_by, "srcip") == 0)
    {
        if(!(prev_filter & REPORT_REL_SRCIP))
        {
            prev_filter|=REPORT_REL_SRCIP;
        }
        return(prev_filter);
    }
    else if(strcmp(filter_by, "user") == 0)
    {
        if(!(prev_filter & REPORT_REL_USER))
        {
            prev_filter|=REPORT_REL_USER;
        }
        return(prev_filter);
    }
    else if(strcmp(filter_by, "filename") == 0)
    {
        if(!(prev_filter & REPORT_REL_FILE))
        {
            prev_filter|=REPORT_REL_FILE;
        }
        return(prev_filter);
    }
    else
    {
        merror("%s: ERROR: Invalid relation '%s'.", __local_name, filter_by);
        return(-1);
    }
}



/* Prints related entries. */
static int _os_report_print_related(int print_related, OSList *st_data)
{
    OSListNode *list_entry;
    alert_data *list_aldata;
    alert_data *saved_aldata;


    list_entry = OSList_GetFirstNode(st_data);
    while(list_entry)
    {
        saved_aldata = (alert_data *)list_entry->data;

        /* Removing duplicates. */
        list_entry = list_entry->prev;
        while(list_entry)
        {
            if(print_related & REPORT_REL_LOCATION)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(strcmp(list_aldata->location, saved_aldata->location) == 0)
                {
                    break;
                }
            }

            else if(print_related & REPORT_REL_GROUP)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(strcmp(list_aldata->group, saved_aldata->group) == 0)
                {
                    break;
                }
            }

            else if(print_related & REPORT_REL_RULE)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(list_aldata->rule == saved_aldata->rule)
                {
                    break;
                }
            }

            else if(print_related & REPORT_REL_USER)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(list_aldata->user == NULL || saved_aldata->user == NULL)
                {
                }
                else if(strcmp(list_aldata->user, saved_aldata->user) == 0)
                {
                    break;
                }
            }

            else if(print_related & REPORT_REL_SRCIP)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(list_aldata->srcip == NULL || saved_aldata->srcip == NULL)
                {
                }
                else if(strcmp(list_aldata->srcip, saved_aldata->srcip) == 0)
                {
                    break;
                }
            }

            else if(print_related & REPORT_REL_LEVEL)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(list_aldata->level == saved_aldata->level)
                {
                    break;
                }
            }
            else if(print_related & REPORT_REL_FILE)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(list_aldata->filename == NULL || saved_aldata->filename == NULL)
                {
                }
                else if(strcmp(list_aldata->filename, saved_aldata->filename) == 0)
                {
                    break;
                }
            }
            list_entry = list_entry->prev;
        }

        if(!list_entry)
        {
            if(print_related & REPORT_REL_LOCATION)
                l_print_out("   location: '%s'", saved_aldata->location);
            else if(print_related & REPORT_REL_GROUP)
                l_print_out("   group: '%s'", saved_aldata->group);
            else if(print_related & REPORT_REL_RULE)
                l_print_out("   rule: '%d'", saved_aldata->rule);
            else if((print_related & REPORT_REL_SRCIP) && saved_aldata->srcip)
                l_print_out("   srcip: '%s'", saved_aldata->srcip);
            else if((print_related & REPORT_REL_USER) && saved_aldata->user)
                l_print_out("   user: '%s'", saved_aldata->user);
            else if(print_related & REPORT_REL_LEVEL)
                l_print_out("   level: '%d'", saved_aldata->level);
            else if((print_related & REPORT_REL_FILE) && saved_aldata->filename)
                l_print_out("   filename: '%s'", saved_aldata->filename);
        }

        list_entry = OSList_GetNextNode(st_data);
    }

    return(0);
}



/* Add the entry to the hash. */
static int _os_report_add_tostore(const char *key, OSStore *top, void *data)
{
    OSList *top_list;

    /* Adding data to the hash. */
    top_list = (OSList *) OSStore_Get(top, key);
    if(top_list)
    {
        OSList_AddData(top_list, data);
    }
    else
    {
        top_list = OSList_Create();
        if(!top_list)
        {
            merror(MEM_ERROR, __local_name);
            return(0);
        }
        OSList_AddData(top_list, data);

        OSStore_Put(top, key, top_list);
    }

    return(1);
}



void os_report_printtop(void *topstore_pt, const char *hname, int print_related)
{
    int dopdout = 0;
    OSStore *topstore = (OSStore *)topstore_pt;
    OSStoreNode *next_node;

    next_node = OSStore_GetFirstNode(topstore);
    while(next_node)
    {
        OSList *st_data = (OSList *)next_node->data;
        char *lkey = (char *)next_node->key;


        /* With location we leave more space to be clearer. */
        if(!print_related)
        {
            if(strlen(lkey) > 76)
            {
                lkey[74] = '.';
                lkey[75] = '.';
                lkey[76] = '\0';
            }

            if(!dopdout)
            {
                _os_header_print(print_related, hname);
                dopdout = 1;
            }
            l_print_out("%-78s|%-8d|", (char *)next_node->key, st_data->currently_size);
        }


        /* Print each destination. */
        else
        {
            if(!dopdout)
            {
                _os_header_print(print_related, hname);
                dopdout = 1;
            }
            l_print_out("%-78s|%-8d|", (char *)next_node->key, st_data->currently_size);

            if(print_related & REPORT_REL_LOCATION)
                _os_report_print_related(REPORT_REL_LOCATION, st_data);
            if(print_related & REPORT_REL_SRCIP)
                _os_report_print_related(REPORT_REL_SRCIP, st_data);
            if(print_related & REPORT_REL_USER)
                _os_report_print_related(REPORT_REL_USER, st_data);
            if(print_related & REPORT_REL_RULE)
                _os_report_print_related(REPORT_REL_RULE, st_data);
            if(print_related & REPORT_REL_GROUP)
                _os_report_print_related(REPORT_REL_GROUP, st_data);
            if(print_related & REPORT_REL_LEVEL)
                _os_report_print_related(REPORT_REL_LEVEL, st_data);
            if(print_related & REPORT_REL_FILE)
                _os_report_print_related(REPORT_REL_FILE, st_data);

        }

        next_node = next_node->next;
    }


    if(dopdout == 1)
    {
        l_print_out(" ");
        l_print_out(" ");
    }
    return;
}



void os_ReportdStart(report_filter *r_filter)
{
    int alerts_processed = 0;
    int alerts_filtered = 0;
    char *first_alert = NULL;
    char *last_alert = NULL;
    alert_data **data_to_clean = NULL;


    time_t tm;
    struct tm *p;


    file_queue *fileq;
    alert_data *al_data;


    /* Getting current time before starting */
    tm = time(NULL);
    p = localtime(&tm);




    /* Initating file queue - to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);

    if(r_filter->report_type == REPORT_TYPE_DAILY && r_filter->filename)
    {
        fileq->fp = fopen(r_filter->filename, "r");
        if(!fileq->fp)
        {
            merror("%s: ERROR: Unable to open alerts file to generate report.", __local_name);
            return;
        }
        if(r_filter->fp)
        {
            __g_rtype = r_filter->fp;
        }
    }
    else
    {
        fileq->fp = stdin;
    }


    /* Creating top hashes. */
    r_filter->top_user = OSStore_Create();
    r_filter->top_srcip = OSStore_Create();
    r_filter->top_level = OSStore_Create();
    r_filter->top_rule = OSStore_Create();
    r_filter->top_group = OSStore_Create();
    r_filter->top_location = OSStore_Create();
    r_filter->top_files = OSStore_Create();

    Init_FileQueue(fileq, p, CRALERT_READ_ALL|CRALERT_FP_SET);



    /* Reading the alerts. */
    while(1)
    {
        /* Get message if available */
        al_data = Read_FileMon(fileq, p, 1);
        if(!al_data)
        {
            break;
        }

        alerts_processed++;


        /* Checking the filters. */
        if(!_os_report_check_filters(al_data, r_filter))
        {
            FreeAlertData(al_data);
            continue;
        }


        alerts_filtered++;
        data_to_clean = (alert_data ** ) os_AddPtArray(al_data, (void **)data_to_clean);


        /* Setting first and last alert for summary. */
        if(!first_alert)
            first_alert = al_data->date;
        last_alert = al_data->date;


        /* Adding source ip if it is set properly. */
        if(al_data->srcip != NULL && strcmp(al_data->srcip, "(none)") != 0)
            _os_report_add_tostore(al_data->srcip, r_filter->top_srcip, al_data);


        /* Adding user if it is set properly. */
        if(al_data->user != NULL && strcmp(al_data->user, "(none)") != 0)
            _os_report_add_tostore(al_data->user, r_filter->top_user, al_data);


        /* Adding level and severity. */
        {
            char mlevel[16];
            char mrule[76 +1];
            mrule[76] = '\0';
            snprintf(mlevel, 16, "Severity %d" , al_data->level);
            snprintf(mrule, 76, "%d - %s" , al_data->rule, al_data->comment);

            _os_report_add_tostore(mlevel, r_filter->top_level,
                                   al_data);
            _os_report_add_tostore(mrule, r_filter->top_rule,
                                   al_data);
        }

        /* Dealing with the group. */
        {
            char *tmp_str;
            char **mgroup;

            mgroup = OS_StrBreak(',', al_data->group, 32);
            if(mgroup)
            {
                while(*mgroup)
                {
                    tmp_str = *mgroup;
                    while(*tmp_str == ' ')
                        tmp_str++;
                    if(*tmp_str == '\0')
                    {
                        free(*mgroup);
                        mgroup++;
                        continue;
                    }

                    _os_report_add_tostore(tmp_str, r_filter->top_group,
                                           al_data);

                    free(*mgroup);
                    mgroup++;
                }

                free(mgroup);
            }
            else
            {
                tmp_str = al_data->group;
                while(*tmp_str == ' ')
                    tmp_str++;
                if(*tmp_str != '\0')
                {
                    _os_report_add_tostore(tmp_str, r_filter->top_group,
                                           al_data);
                }
            }
        }


        /* Adding to the location top filter. */
        _os_report_add_tostore(al_data->location, r_filter->top_location,
                               al_data);


        if(al_data->filename != NULL)
        {
            _os_report_add_tostore(al_data->filename, r_filter->top_files,
                                   al_data);
        }
    }

    /* No report available */
    if(alerts_filtered == 0)
    {
        if(!r_filter->report_name)
            merror("%s: INFO: Report completed and zero alerts post-filter.", __local_name);
        else
            merror("%s: INFO: Report '%s' completed and zero alerts post-filter.", __local_name, r_filter->report_name);
        return;
    }


    if(r_filter->report_name)
        verbose("%s: INFO: Report '%s' completed. Creating output...", __local_name, r_filter->report_name);
    else
        verbose("%s: INFO: Report completed. Creating output...", __local_name);


    l_print_out(" ");
    if(r_filter->report_name)
        l_print_out("Report '%s' completed.", r_filter->report_name);
    else
        l_print_out("Report completed. ==");
    l_print_out("------------------------------------------------");

    l_print_out("->Processed alerts: %d", alerts_processed);
    l_print_out("->Post-filtering alerts: %d", alerts_filtered);
    l_print_out("->First alert: %s", first_alert);
    l_print_out("->Last alert: %s", last_alert);
    l_print_out(" ");
    l_print_out(" ");

    OSStore_Sort(r_filter->top_srcip, _os_report_sort_compare);
    OSStore_Sort(r_filter->top_user,  _os_report_sort_compare);
    OSStore_Sort(r_filter->top_level, _os_report_sort_compare);
    OSStore_Sort(r_filter->top_group, _os_report_sort_compare);
    OSStore_Sort(r_filter->top_location, _os_report_sort_compare);
    OSStore_Sort(r_filter->top_rule, _os_report_sort_compare);
    OSStore_Sort(r_filter->top_files, _os_report_sort_compare);

    if(r_filter->top_srcip)
        os_report_printtop(r_filter->top_srcip, "Source ip", 0);

    if(r_filter->top_user)
        os_report_printtop(r_filter->top_user, "Username", 0);

    if(r_filter->top_level)
        os_report_printtop(r_filter->top_level, "Level", 0);

    if(r_filter->top_group)
        os_report_printtop(r_filter->top_group, "Group", 0);

    if(r_filter->top_location)
        os_report_printtop(r_filter->top_location, "Location", 0);

    if(r_filter->top_rule)
        os_report_printtop(r_filter->top_rule, "Rule", 0);

    if(r_filter->top_files)
        os_report_printtop(r_filter->top_files, "Filenames", 0);


    /* Print related events. */
    if(r_filter->related_srcip)
        os_report_printtop(r_filter->top_srcip, "Source ip",
                           r_filter->related_srcip);

    if(r_filter->related_user)
        os_report_printtop(r_filter->top_user, "Username",
                           r_filter->related_user);

    if(r_filter->related_level)
        os_report_printtop(r_filter->top_level, "Level",
                           r_filter->related_level);

    if(r_filter->related_group)
        os_report_printtop(r_filter->top_group, "Group",
                           r_filter->related_group);

    if(r_filter->related_location)
        os_report_printtop(r_filter->top_location, "Location",
                           r_filter->related_location);

    if(r_filter->related_rule)
        os_report_printtop(r_filter->top_rule, "Rule",
                           r_filter->related_rule);

    if(r_filter->related_file)
        os_report_printtop(r_filter->top_files, "Filename",
                           r_filter->related_file);


    /* If we have to dump the alerts. */
    if(data_to_clean)
    {
        int i = 0;

        if(r_filter->show_alerts)
        {
            l_print_out("Log dump:");
            l_print_out("------------------------------------------------");
        }
        while(data_to_clean[i])
        {
            alert_data *md = data_to_clean[i];
            if(r_filter->show_alerts)
                l_print_out("%s %s\nRule: %d (level %d) -> '%s'\n%s\n\n", md->date, md->location, md->rule, md->level, md->comment, md->log[0]);
            FreeAlertData(md);
            i++;
        }
        free(data_to_clean);
        data_to_clean = NULL;
    }
}





/** int os_report_check_filters(char *filter_by, char *filter_value,
 *                              report_filter *r_filter)
 * Checks the configuration filters.
 */
int os_report_configfilter(const char *filter_by, const char *filter_value,
                           report_filter *r_filter, int arg_type)
{
    if(!filter_by || !filter_value)
    {
        return(-1);
    }

    if(arg_type == REPORT_FILTER)
    {
        if(strcmp(filter_by, "group") == 0)
        {
            r_filter->group = filter_value;
        }
        else if(strcmp(filter_by, "rule") == 0)
        {
            r_filter->rule = filter_value;
        }
        else if(strcmp(filter_by, "level") == 0)
        {
            r_filter->level = filter_value;
        }
        else if(strcmp(filter_by, "location") == 0)
        {
            r_filter->location = filter_value;
        }
        else if(strcmp(filter_by, "user") == 0)
        {
            r_filter->user = filter_value;
        }
        else if(strcmp(filter_by, "srcip") == 0)
        {
            r_filter->srcip = filter_value;
        }
        else if(strcmp(filter_by, "filename") == 0)
        {
            r_filter->files = filter_value;
        }
        else
        {
            merror("%s: ERROR: Invalid filter '%s'.", __local_name, filter_by);
            return(-1);
        }
    }
    else
    {
        if(strcmp(filter_by, "group") == 0)
        {
            r_filter->related_group =
            _report_filter_value(filter_value, r_filter->related_group);

            if(r_filter->related_group == -1)
                return(-1);
        }
        else if(strcmp(filter_by, "rule") == 0)
        {
            r_filter->related_rule =
            _report_filter_value(filter_value, r_filter->related_rule);

            if(r_filter->related_rule == -1)
                return(-1);
        }
        else if(strcmp(filter_by, "level") == 0)
        {
            r_filter->related_level =
            _report_filter_value(filter_value, r_filter->related_level);

            if(r_filter->related_level == -1)
                return(-1);
        }
        else if(strcmp(filter_by, "location") == 0)
        {
            r_filter->related_location =
            _report_filter_value(filter_value, r_filter->related_location);

            if(r_filter->related_location == -1)
                return(-1);
        }
        else if(strcmp(filter_by, "srcip") == 0)
        {
            r_filter->related_srcip =
            _report_filter_value(filter_value, r_filter->related_srcip);

            if(r_filter->related_srcip == -1)
                return(-1);
        }
        else if(strcmp(filter_by, "user") == 0)
        {
            r_filter->related_user =
            _report_filter_value(filter_value, r_filter->related_user);

            if(r_filter->related_user == -1)
                return(-1);
        }
        else if(strcmp(filter_by, "filename") == 0)
        {
            r_filter->related_file =
            _report_filter_value(filter_value, r_filter->related_file);

            if(r_filter->related_file == -1)
                return(-1);
        }
        else
        {
            merror("%s: ERROR: Invalid related entry '%s'.", __local_name, filter_by);
            return(-1);
        }
    }

    return(0);
}



/* EOF */
