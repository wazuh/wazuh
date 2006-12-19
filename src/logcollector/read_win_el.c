/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

       
#include "shared.h"
#include "logcollector.h"       


/* This is only for windows */
#ifdef WIN32

#define BUFFER_SIZE 2048*64



/* Event logging local structure */
typedef struct _os_el
{
    int time_of_last;	
    char *name;

    EVENTLOGRECORD *er;
    HANDLE h;

    DWORD record;
}os_el;
os_el el[3];
int el_last = 0;


/** int startEL(char *app, os_el *el)
 * Starts the event logging for each el 
 */
int startEL(char *app, os_el *el)
{
    /* Opening the event log */
    el->h = OpenEventLog(NULL, app);
    if(!el->h)
    {
        return(0);	    
    }

    el->name = app;
    GetOldestEventLogRecord(el->h, &el->record);

    return(1);
}



/** char *el_getCategory(int category_id) 
 * Returns a string related to the category id of the log.
 */
char *el_getCategory(int category_id)
{
    char *cat;
    switch(category_id)
    {
        case EVENTLOG_ERROR_TYPE:
            cat = "ERROR";
            break;
        case EVENTLOG_WARNING_TYPE:
            cat = "WARNING";
            break;
        case EVENTLOG_INFORMATION_TYPE:
            cat = "INFORMATION";
            break;
        case EVENTLOG_AUDIT_SUCCESS:
            cat = "AUDIT_SUCCESS";
            break;
        case EVENTLOG_AUDIT_FAILURE:
            cat = "AUDIT_FAILURE";
            break;
        default:
            cat = "Unknown";
            break;
    }
    return(cat);
}


/** int el_getEventDLL(char *evt_name, char *source, char *event)
 * Returns the event.
 */
int el_getEventDLL(char *evt_name, char *source, char *event) 
{
    HKEY key;
    DWORD ret;
    char keyname[512];


    keyname[511] = '\0';

    snprintf(keyname, 510, 
            "System\\CurrentControlSet\\Services\\EventLog\\%s\\%s", 
            evt_name, 
            source);

    /* Opening registry */	    
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0, KEY_ALL_ACCESS, &key)
            != ERROR_SUCCESS)
    {
        return(0);    
    }


    ret = MAX_PATH -1;	
    if (RegQueryValueEx(key, "EventMessageFile", NULL, 
                NULL, (LPBYTE)event, &ret) != ERROR_SUCCESS)
    {
        event[0] = '\0';	
        return(0);
    }

    RegCloseKey(key);
    return(1);
}



/** char *el_getmessage() 
 * Returns a descriptive message of the event.
 */
char *el_getMessage(EVENTLOGRECORD *er,  char *name, 
		    char * source, LPTSTR *el_sstring) 
{
    DWORD fm_flags = 0;
    char tmp_str[257];
    char event[MAX_PATH +1];
    char *curr_str;
    char *next_str;
    LPSTR message = NULL;

    HMODULE hevt;

    /* Initializing variables */
    event[MAX_PATH] = '\0';
    tmp_str[256] = '\0';

    /* Flags for format event */
    fm_flags |= FORMAT_MESSAGE_FROM_HMODULE;
    fm_flags |= FORMAT_MESSAGE_ALLOCATE_BUFFER;
    fm_flags |= FORMAT_MESSAGE_ARGUMENT_ARRAY;

    /* Get the file name from the registry (stored on event) */
    if(!el_getEventDLL(name, source, event))
    {
        return(NULL);	    
    }	    

    curr_str = event;

    /* If our event has multiple libraries, try each one of them */ 
    while((next_str = strchr(curr_str, ';')))
    {
        *next_str = '\0';
        next_str++;

        ExpandEnvironmentStrings(curr_str, tmp_str, 255);
        hevt = LoadLibraryEx(tmp_str, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if(hevt)
        {
            if(!FormatMessage(fm_flags, hevt, er->EventID, 
                        0,
                        (LPTSTR) &message, 0, el_sstring))
            {
                message = NULL;		  
            }
            FreeLibrary(hevt);

            /* If we have a message, we can return it */
            if(message)
                return(message);
        }

        curr_str = next_str;		
    }

    ExpandEnvironmentStrings(curr_str, tmp_str, 255);
    hevt = LoadLibraryEx(tmp_str, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if(hevt)
    {
        int hr;    
        if(!(hr = FormatMessage(fm_flags, hevt, er->EventID, 
                        0,
                        (LPTSTR) &message, 0, el_sstring)))
        {
            message = NULL;		  
        }
        FreeLibrary(hevt);

        /* If we have a message, we can return it */
        if(message)
            return(message);
    }

    return(NULL);
}



/** void readel(os_el *el)
 * Reads the event log.
 */ 
void readel(os_el *el, int printit)
{
    DWORD nstr;
    DWORD user_size;
    DWORD domain_size;
    DWORD read, needed;
    int size_left;
    int str_size;

    char mbuffer[BUFFER_SIZE];
    LPSTR sstr = NULL;

    char *tmp_str = NULL;
    char *category;
    char *source;
    char *computer_name;
    char *descriptive_msg;

    char el_user[OS_FLSIZE +1];
    char el_domain[OS_FLSIZE +1];
    char el_string[OS_MAXSTR +1];
    char final_msg[OS_MAXSTR +1];
    LPSTR el_sstring[OS_FLSIZE +1];

    /* Er must point to the mbuffer */
    el->er = (EVENTLOGRECORD *) &mbuffer; 

    /* Zeroing the last values */
    el_string[OS_MAXSTR] = '\0';
    el_user[OS_FLSIZE] = '\0';
    el_domain[OS_FLSIZE] = '\0';
    final_msg[OS_MAXSTR] = '\0';
    el_sstring[OS_FLSIZE] = NULL;

    /* Reading the event log */	    
    while(ReadEventLog(el->h, 
                EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
                0,
                el->er, BUFFER_SIZE -1, &read, &needed))
    {
        while(read > 0)
        {

            /* We need to initialize every variable before the loop */
            category = el_getCategory(el->er->EventType);
            source = (LPSTR) ((LPBYTE) el->er + sizeof(EVENTLOGRECORD));
            computer_name = source + strlen(source) + 1;
            descriptive_msg = NULL;


            /* Initialing domain/user size */
            user_size = 255; domain_size = 255;
            el_domain[0] = '\0';
            el_user[0] = '\0';


            /* We must have some description */
            if(el->er->NumStrings)
            {	
                size_left = OS_MAXSTR - OS_SIZE_1024;	

                sstr = (LPSTR)((LPBYTE)el->er + el->er->StringOffset);
                el_string[0] = '\0';

                for (nstr = 0;nstr < el->er->NumStrings;nstr++)
                {
                    /* Depending on the event, we may need to
                     * get the username, because the one in the
                     * structure is not accurate.
                     * We may also get the source IP address 
                     * if available. XXX todo.
                     */
                    str_size = strlen(sstr);
                    strncat(el_string, sstr, size_left);

                    tmp_str = strchr(el_string, '\0');
                    if(tmp_str)
                    {
                        *tmp_str = ' ';		
                        tmp_str++; *tmp_str = '\0';
                    }
                    size_left-=str_size + 1;

                    if(nstr <= 54)
                        el_sstring[nstr] = (LPSTR)sstr;

                    sstr = strchr( (LPSTR)sstr, '\0');
                    if(sstr)
                        sstr++;
                    else
                        break;     
                }

                /* Get a more descriptive message (if available) */
                descriptive_msg = el_getMessage(el->er, 
                                                el->name, 
                                                source, 
                                                el_sstring);
                if(descriptive_msg != NULL)
                {
                    /* Remove any \n or \r */
                    tmp_str = descriptive_msg;    
                    while((tmp_str = strchr(tmp_str, '\n')))
                    {
                        *tmp_str = ' ';
                        tmp_str++;		    
                    }			

                    tmp_str = descriptive_msg;    
                    while((tmp_str = strchr(tmp_str, '\r')))
                    {
                        *tmp_str = ' ';
                        tmp_str++;		    
                    }			
                }
            }
            else
            {
                strncpy(el_string, "(no message)", 128);	
            }


            /* Getting username */
            if (el->er->UserSidLength)
            {
                SID_NAME_USE account_type;
                if(!LookupAccountSid(NULL, 
                                    (SID *)((LPSTR)el->er + 
                                    el->er->UserSidOffset),
                                    el_user, 
                                    &user_size, 
                                    el_domain, 
                                    &domain_size, 
                                    &account_type))		
                {
                    strncpy(el_user, "(no user)", 255);
                    strncpy(el_domain, "no domain", 255);
                }

            }

            else
            {
                strncpy(el_user, "(no user)", 255);	
                strncpy(el_domain, "no domain", 255);	
            }


            if(printit)
            {
                DWORD _evtid = 65535;
                int id = (int)el->er->EventID & _evtid; 
               
                final_msg[OS_MAXSTR - OS_LOG_HEADER] = '\0'; 
                final_msg[OS_MAXSTR - OS_LOG_HEADER -1] = '\0'; 
                
                snprintf(final_msg, OS_MAXSTR - OS_LOG_HEADER -1, 
                        "WinEvtLog: %s: %s(%d): %s: %s: %s: %s: %s", 
                        el->name,
                        category, 
                        id,
                        source,
                        el_user,
                        el_domain,
                        computer_name,
                        descriptive_msg != NULL?descriptive_msg:el_string);	
                
                if(SendMSG(logr_queue, final_msg, "WinEvtLog",
                            LOCALFILE_MQ) < 0)
                {
                    merror(QUEUE_SEND, ARGV0);
                }
            }

            if(descriptive_msg != NULL)
                LocalFree(descriptive_msg);

            /* Changing the point to the er */
            read -= el->er->Length;
            el->er = (EVENTLOGRECORD *)((LPBYTE) el->er + el->er->Length);
        }		

        /* Setting er to the beginning of the buffer */	
        el->er = (EVENTLOGRECORD *)&mbuffer;
    }
}


/** void win_startel()
 * Starts the event logging for windows
 */
void win_startel(char *evt_log)
{
    startEL(evt_log, &el[el_last]);
    readel(&el[el_last],0);
    el_last++;
}


/** void win_readel() 
 * Reads the event logging for windows
 */
void win_readel()
{
    int i = 0;
    
    /* Sleep plus 2 seconds before reading again */
    Sleep(2000);
    
    for(;i<el_last;i++)
        readel(&el[i],1);
}


#endif

/* EOF */
