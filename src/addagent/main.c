/* @(#) $Id: ./src/addagent/main.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "manage_agents.h"
#include <stdlib.h>

static void helpmsg(void) __attribute__((noreturn));
static void print_banner(void);
static void manage_shutdown(int sig) __attribute__((noreturn));

#if defined(__MINGW32__)
static int setenv(const char * name, const char * val, int overwrite) {
    int len = strlen(name) + strlen(val) + 2;
    char * str = (char *)malloc(len);
    snprintf(str, len, "%s=%s", name, val);
    putenv(str);
    return 0;
}
#endif

/* print help statement */
static void helpmsg()
{
    print_header();
    print_out("  %s: -[Vhl] [-e id] [-r id] [-i id] [-f file]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -l          List available agents.");
    print_out("    -e <id>     Extracts key for an agent (Manager only)");
    print_out("    -r <id>     Remove an agent (Manager only)");
    print_out("    -i <id>     Import authentication key (Agent only)");
    print_out("    -f <file>   Bulk generate client keys from file (Manager only)");
    print_out("                <file> contains lines in IP,NAME format");
    exit(1);
}


/* print banner */
static void print_banner()
{
    printf("\n");
    printf(BANNER, __ossec_name, __version);

    #ifdef CLIENT
    printf(BANNER_CLIENT);
    #else
    printf(BANNER_OPT);
    #endif

    return;
}


/* Clean shutdown on kill */
static void manage_shutdown(__attribute__((unused)) int sig)
{
    /* Checking if restart message is necessary */
    if(restart_necessary)
    {
        printf(MUST_RESTART);
    }
    else
    {
        printf("\n");
    }
    printf(EXIT);

    exit(0);
}


/** main **/
int main(int argc, char **argv)
{
    char *user_msg;

    int c = 0, cmdlist = 0;
    const char *cmdexport = NULL;
    const char *cmdimport = NULL;
    const char *cmdbulk = NULL;

    #ifndef WIN32
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    int gid;
    #else
    FILE *fp;
    TCHAR path[2048];
    DWORD last_error;
    int ret;
    #endif


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "Vhle:r:i:f:")) != -1){
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                helpmsg();
                break;
            case 'e':
                #ifdef CLIENT
                ErrorExit("%s: Key export only available on a master.", ARGV0);
                #endif
                if(!optarg)
                    ErrorExit("%s: -e needs an argument.", ARGV0);
                cmdexport = optarg;
                break;
            case 'r':
                #ifdef CLIENT
                ErrorExit("%s: Key removal only available on a master.", ARGV0);
                #endif
                if(!optarg)
                    ErrorExit("%s: -r needs an argument.", ARGV0);

                /* Use environment variables already available to remove_agent() */
                setenv("OSSEC_ACTION", "r", 1);
                setenv("OSSEC_AGENT_ID", optarg, 1);
                setenv("OSSEC_ACTION_CONFIRMED", "y", 1);
                break;
            case 'i':
                #ifndef CLIENT
                ErrorExit("%s: Key import only available on an agent.", ARGV0);
                #endif
                if(!optarg)
                    ErrorExit("%s: -i needs an argument.", ARGV0);
                cmdimport = optarg;
                break;
            case 'f':
                #ifdef CLIENT
                ErrorExit("%s: Bulk generate keys only available on a master.", ARGV0);
                #endif
                if(!optarg)
                    ErrorExit("%s: -f needs an argument.", ARGV0);
                cmdbulk = optarg;
                printf("Bulk load file: %s\n", cmdbulk);
                break;
            case 'l':
                cmdlist = 1;
                break;
            default:
                helpmsg();
                break;
        }

    }



    /* Get current time */
    time1 = time(0);
    restart_necessary = 0;


    #ifndef WIN32
    /* Getting the group name */
    gid = Privsep_GetGroup(group);
    if(gid < 0)
    {
        ErrorExit(USER_ERROR, ARGV0, "", group);
    }


    /* Setting the group */
    if(Privsep_SetGroup(gid) < 0)
    {
        ErrorExit(SETGID_ERROR, ARGV0, group);
    }


    /* Chrooting to the default directory */
    if(Privsep_Chroot(dir) < 0)
    {
        ErrorExit(CHROOT_ERROR, ARGV0, dir);
    }


    /* Inside chroot now */
    nowChroot();


    /* Starting signal handler */
    StartSIG2(ARGV0, manage_shutdown);

    #else

    /* Get full path to the directory this
     * executable lives in
     */
    ret = GetModuleFileName(NULL, path, sizeof(path));

    /* check for errors */
    if(!ret)
    {
        ErrorExit(GMF_ERROR);
    }

    /* Get last error */
    last_error = GetLastError();

    /* Look for errors */
    if(last_error != ERROR_SUCCESS)
    {
        if(last_error == ERROR_INSUFFICIENT_BUFFER)
        {
            ErrorExit(GMF_BUFF_ERROR, ret, sizeof(path));
        }
        else
        {
            ErrorExit(GMF_UNKN_ERROR, last_error);
        }
    }

    /* Remove file name from path */
    PathRemoveFileSpec(path);

    /* Move to correct directory */
    if(chdir(path))
    {
        ErrorExit(CHDIR_ERROR_2, path);
    }

    /* Check permissions */
    fp = fopen(OSSECCONF, "r");
    if(fp)
    {
        fclose(fp);
    }
    else
    {
        ErrorExit(CONF_ERROR, OSSECCONF);
    }

    #endif

    if(cmdlist == 1)
    {
        list_agents(cmdlist);
        exit(0);
    }
    else if(cmdimport)
    {
        k_import(cmdimport);
        exit(0);
    }
    else if(cmdexport)
    {
        k_extract(cmdexport);
        exit(0);
    }
    else if(cmdbulk)
    {
        k_bulkload(cmdbulk);
        exit(0);
    }



    /* Little shell */
    while(1)
    {
        int leave_s = 0;
        print_banner();

        /* Get ACTION from the environment. If ACTION is specified,
         * we must set leave_s = 1 to ensure that the loop will end */
        user_msg = getenv("OSSEC_ACTION");
        if (user_msg == NULL) {
          user_msg = read_from_user();
        }
        else{
          leave_s = 1;
        }

        /* All the allowed actions */
        switch(user_msg[0])
        {
            case 'A':
            case 'a':
                add_agent();
                break;
            case 'e':
            case 'E':
                k_extract(NULL);
                break;
            case 'i':
            case 'I':
                k_import(NULL);
                break;
            case 'l':
            case 'L':
                list_agents(0);
                break;
            case 'r':
            case 'R':
                remove_agent();
                break;
            case 'q':
            case 'Q':
                leave_s = 1;
                break;
	        case 'V':
		        print_version();
		        break;
            default:
                printf("\n ** Invalid Action ** \n\n");
                break;
        }

        if(leave_s)
        {
            break;
        }

        continue;

    }

    /* Checking if restart message is necessary */
    if(restart_necessary)
    {
        printf(MUST_RESTART);
    }
    else
    {
        printf("\n");
    }
    printf(EXIT);

    return(0);
}


/* EOF */
