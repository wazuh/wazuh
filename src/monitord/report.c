/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"


typedef struct _report_filter
{
    char *group;
    char *rule;
    char *level;
    char *location;

    OSStore *top_user;
    OSStore *top_srcip;
    OSStore *top_level;
    OSStore *top_rule;
    OSStore *top_group;
    OSStore *top_location;
     
}report_filter;


report_filter r_filter;


/* Returns if d1 > d2. */
void *sort_compare(void *d1, void *d2)
{
   OSList *d1l = (OSList *)d1;
   OSList *d2l = (OSList *)d2; 

   if(d1l->currently_size > d2l->currently_size)
   {
       return(d1l);
   }

   return(NULL);
}



int str_int_compare(char *str, int id)
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



/* Add the entry to the hash. */
int os_add_tostore(char *key, OSStore *top, void *data)
{
    OSList *top_list;

    /* Adding data to the hash. */
    top_list = OSStore_Get(top, key);
    if(top_list)
    {
        OSList_AddData(top_list, data);
    }
    else
    {
        top_list = OSList_Create();
        if(!top_list)
        {
            merror(MEM_ERROR, ARGV0);
            return(0);
        }
        OSList_AddData(top_list, data);

        OSStore_Put(top, key, top_list);
    }

    return(1);
}


void os_printtop(OSStore *topstore, char *hname)
{
    OSStoreNode *next_node;
    
    print_out("Top entries for '%s':", hname);
    

    next_node = OSStore_GetFirstNode(topstore);
    while(next_node)
    {
        OSList *st_data = (OSList *)next_node->data;
        OSListNode *list_entry;
        alert_data *list_aldata;
        char *location;
        char *lkey = (char *)next_node->key;


        /* With location we leave more space to be clearer. */
        if((strcmp(hname, "Location") == 0) || (strcmp(hname, "Rule") == 0))
        {
            if(strlen(lkey) > 46)
            {
                lkey[44] = '.';
                lkey[45] = '.';
                lkey[46] = '\0';
            }

            print_out("%-48s|%-8d|", (char *)next_node->key, st_data->currently_size);
        }
        else
        {
            if(strlen(lkey) > 30)
            {
                lkey[28] = '.';
                lkey[29] = '.';
                lkey[30] = '\0';
            }
            print_out("%-32s|%-8d|", (char *)next_node->key, st_data->currently_size);
        }


        /* Print each destination. */
        list_entry = OSList_GetFirstNode(st_data);
        while(list_entry)
        {
            list_aldata = (alert_data *)list_entry->data;
            location = list_aldata->location;

            /* Removing duplicates. */
            list_entry = list_entry->prev;
            while(list_entry)
            {
                list_aldata = (alert_data *)list_entry->data;
                if(strcmp(list_aldata->location, location) == 0)
                {
                    break;
                }
                list_entry = list_entry->prev;
            }

            //if(!list_entry)
            //    print_out("   to: '%s'", location);

            list_entry = OSList_GetNextNode(st_data);
        }

        next_node = next_node->next;
    }


    print_out(" ");
    print_out(" ");
    return; 
}


int check_filters(alert_data *al_data)
{
    /* Checking for the filters. */
    if(r_filter.group)
    {
        if(!strstr(al_data->group, r_filter.group))
        {
            return(0);
        }
    }
    if(r_filter.rule)
    {
        if(str_int_compare(r_filter.rule, al_data->rule) != 1)
        {
            return(0);
        }
    }
    if(r_filter.location)
    {
        if(!OS_Match2(r_filter.location, al_data->location))
        {
            return(0);
        }
    }
    if(r_filter.level)
    {
        if(al_data->level < atoi(r_filter.level))
        {
            return(0);
        }
    }

    return(1);
}



void os_Reportd()
{
    int alerts_processed = 0;
    int alerts_filtered = 0;
    char *first_alert = NULL;
    char *last_alert = NULL;
    
    
    time_t tm;     
    struct tm *p;       

    file_queue *fileq;
    alert_data *al_data;


    /* Getting current time before starting */
    tm = time(NULL);
    p = localtime(&tm);	



    /* Creating top hashes. */
    r_filter.top_user = OSStore_Create();
    r_filter.top_srcip = OSStore_Create();
    r_filter.top_level = OSStore_Create();
    r_filter.top_rule = OSStore_Create();
    r_filter.top_group = OSStore_Create();
    r_filter.top_location = OSStore_Create();

    

    /* Initating file queue - to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    fileq->fp = stdin;
    Init_FileQueue(fileq, p, CRALERT_READ_ALL|CRALERT_FP_SET);


    /* Reading the alerts. */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);


        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, p, 1);
        if(!al_data)
        {
            verbose("%s: Report completed.", ARGV0);
            break;
        }

        alerts_processed++;
        

        if(!check_filters(al_data))
        {
            continue;
        }
        
        
        alerts_filtered++;
        if(!first_alert)
            first_alert = al_data->date;
        last_alert = al_data->date;
        
        
        if(strcmp(al_data->srcip, "(none)") != 0)
            os_add_tostore(al_data->srcip, r_filter.top_srcip, al_data);
        
        if(strcmp(al_data->user, "(none)") != 0)
            os_add_tostore(al_data->user, r_filter.top_user, al_data);

        {
            char mlevel[16];
            char mrule[76 +1];
            mrule[76] = '\0';
            snprintf(mlevel, 16, "Severity %d" , al_data->level);
            snprintf(mrule, 76, "%d - %s" , al_data->rule, al_data->comment);
            
            os_add_tostore(strdup(mlevel), r_filter.top_level, al_data);
            os_add_tostore(strdup(mrule), r_filter.top_rule, al_data);
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
                        mgroup++;
                        continue;
                    }
                    
                    os_add_tostore(tmp_str, r_filter.top_group, al_data);
                    mgroup++;
                }
            }
            else
            {
                tmp_str = al_data->group;
                while(*tmp_str == ' ')
                    tmp_str++;
                if(*tmp_str != '\0')
                {
                    os_add_tostore(tmp_str, r_filter.top_group, al_data);
                }
            }
        }
        
        os_add_tostore(al_data->location, r_filter.top_location, al_data);

        
        /* Clearing the memory */
        //FreeAlertData(al_data);
    }



    print_out("== Report completed. ==");
    print_out(" ");
    print_out("->Processed alerts: %d", alerts_processed);
    print_out("->Post-filtering alerts: %d", alerts_filtered);
    print_out("->First alert: %s", first_alert);
    print_out("->Last alert: %s", last_alert);
    print_out(" ");
    
    OSStore_Sort(r_filter.top_srcip, sort_compare);
    OSStore_Sort(r_filter.top_user, sort_compare);
    OSStore_Sort(r_filter.top_level, sort_compare);
    OSStore_Sort(r_filter.top_group, sort_compare);
    OSStore_Sort(r_filter.top_location, sort_compare);
    OSStore_Sort(r_filter.top_rule, sort_compare);
    
    os_printtop(r_filter.top_srcip, "Source ip");
    os_printtop(r_filter.top_user, "Username");
    os_printtop(r_filter.top_level, "Level");
    os_printtop(r_filter.top_group, "Group");
    os_printtop(r_filter.top_location, "Location");
    os_printtop(r_filter.top_rule, "Rule");
}


int os_Report_config(char *filter_by, char *filter_value)
{
    if(!filter_by || !filter_value)
    {
        return(0);
    }
    
    if(strcmp(filter_by, "group") == 0)
    {
        r_filter.group = filter_value;    
    }
    else if(strcmp(filter_by, "rule") == 0)
    {
        r_filter.rule = filter_value;    
    }
    else if(strcmp(filter_by, "level") == 0)
    {
        r_filter.level = filter_value;    
    }
    else if(strcmp(filter_by, "location") == 0)
    {
        r_filter.location = filter_value;    
    }
    else
    {
        return(-1);
    }

    return(0);
}



int main(int argc, char **argv)
{
    int c, test_config = 0;
    int uid=0,gid=0;
    char *dir  = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;

    char *filter_by = NULL;
    char *filter_value = NULL;


    /* Setting the name */
    OS_SetName(ARGV0);
        
    r_filter.group = NULL;
    r_filter.rule = NULL;
    r_filter.level = NULL;
    r_filter.location = NULL;

    while((c = getopt(argc, argv, "Vdhtu:g:D:c:f:v:")) != -1)
    {
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                if(!optarg)
                    ErrorExit("%s: -f needs an argument",ARGV0);
                filter_by = optarg;
                filter_value = argv[optind];

                if(os_Report_config(filter_by, filter_value) < 0)
                {
                    ErrorExit(CONFIG_ERROR, ARGV0, "user argument");
                }
                optind++;
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user=optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir=optarg;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;    
                break;
            default:
                if(filter_by)
                    filter_value = optarg;
                
                printf("value: %s\n",argv[c]);    
                help(ARGV0);
                break;
        }

    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);

    

    /* Exit here if test config is set */
    if(test_config)
        exit(0);

        
    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);

    
    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    nowChroot();


    
    /* Changing user */        
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    debug1(PRIVSEP_MSG,ARGV0,dir,user);



    /* Signal manipulation */
    StartSIG(ARGV0);

    

    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);

    
    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());
    

    /* the real stuff now */	
    os_Reportd();
    exit(0);
}


/* EOF */
