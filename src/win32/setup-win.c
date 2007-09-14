/* @(#) $Id$ */

/* Copyright (C) 2006,2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
       

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <windows.h>
#include "os_regex/os_regex.h"

#define OSSECCONF   "ossec.conf"
#define OSSECDEF    "default-ossec.conf"
#define CLIENTKEYS  "client.keys"
#define OS_MAXSTR   1024

int fileexist(char *file)
{
    FILE *fp;

    /* Opening file */
    fp = fopen(file, "r");
    if(!fp)
        return(0);

    fclose(fp);
    return(1);
}

int dogrep(char *file, char *str)
{
    char line[OS_MAXSTR +1];
    FILE *fp;

    /* Opening file */
    fp = fopen(file, "r");
    if(!fp)
        return(0);

    /* Clearing memory */
    memset(line, '\0', OS_MAXSTR +1);

    /* Reading file and looking for str */ 
    while(fgets(line, OS_MAXSTR, fp) != NULL)
    {
        if(OS_Match(str, line))
        {
            fclose(fp);
            return(1);
        }
    }

    fclose(fp);
    return(0);
}


/* Check if dir exists */
int direxist(char *dir)
{
    DIR *dp;

    /* Opening dir */
    dp = opendir(dir);
    if(dp == NULL)
        return(0);

    closedir(dp);
    return(1);
}



/* Getting Windows directory */
char *get_win_dir()
{
    /* Ok, I should be getting %WINDIR% .. no reason to do that in here.
     */
    char *win_dir = "C:\\WINDOWS";
    if(direxist(win_dir))
    {
        return(win_dir);
    }
    
    win_dir = "C:\\WINNT";
    if(direxist(win_dir))
    {
        return(win_dir);
    }

    win_dir = "D:\\WINDOWS";
    if(direxist(win_dir))
    {
        return(win_dir);
    }

    /* Default is WINDOWS */
    return("C:\\WINDOWS");
    
}


int add_syscheck()
{
    char *win_dir;
    FILE *fp;

    win_dir = get_win_dir();

    /* Add syscheck config */
    fp = fopen(OSSECCONF, "a");
    if(!fp)
        return(0);

    fprintf(fp, 
            "\r\n"
            "<!-- Default syscheck config -->\r\n"
            "<ossec_config>\r\n"
            "  <syscheck>\r\n"
            "    <frequency>64800</frequency>\r\n"
            "    <directories check_all=\"yes\">"
            "%s/system32</directories>\r\n"
            "  </syscheck>\r\n"
            "</ossec_config>\r\n", win_dir);
    fclose(fp);

    return(0);

}


/* Adds the registry checking entries */
int config_registry()
{
    int add_reg_ig = 1;
    int add_reg_entries = 1;
    FILE *fp;


    /* We add here the last entry */
    if(dogrep(OSSECCONF, "MediaCategories</registry_ignore>"))
    {
        add_reg_ig = 0;
    }

    /* Registry entries already added */
    if(dogrep(OSSECCONF, "<windows_registry>"))
    {
        add_reg_entries = 0;
    }

    /* Nothing to add */
    if((add_reg_ig == 0) && (add_reg_entries == 0))
    {
        return(0);
    }

    /* Add syscheck config */
    fp = fopen(OSSECCONF, "a");
    if(!fp)
        return(0); 

    /* Adding registry */
    if(add_reg_entries)
    {
        fprintf(fp, 
                "\r\n\r\n"    
                "<!-- Syscheck registry config -->\r\n"
                "<ossec_config>\r\n"
                "  <syscheck>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "    <windows_registry>%s</windows_registry>\r\n"
                "  </syscheck>\r\n"
                "</ossec_config>\r\n",
                "HKEY_LOCAL_MACHINE\\Software\\Classes",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Internet Explorer",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion",
                "HKEY_LOCAL_MACHINE\\Software\\Policies",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services",
                "HKEY_LOCAL_MACHINE\\Security"
                );
    }

    /* Adding ignore entries */
    if(add_reg_ig)
    {
        fprintf(fp,
                "\r\n\r\n"
                "<!-- Syscheck registry ignored entries (too big or change too often) -->\r\n"
                "<ossec_config>\r\n"
                "  <syscheck>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore>%s</registry_ignore>\r\n"
                "    <registry_ignore type=\"sregex\">\\Enum$</registry_ignore>\r\n"
                "  </syscheck>\r\n"
                "</ossec_config>\r\n\r\n",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Prefetcher",
                "HKEY_LOCAL_MACHINE\\Software\\Classes\\Interface",
                "HKEY_LOCAL_MACHINE\\Software\\Classes\\TypeLib",
                "HKEY_LOCAL_MACHINE\\Software\\Classes\\MIME",
                "HKEY_LOCAL_MACHINE\\Software\\Classes\\Software",
                "HKEY_LOCAL_MACHINE\\Software\\Classes\\CLSID",
                "HKEY_LOCAL_MACHINE\\Security\\Policy\\Secrets",
                "HKEY_LOCAL_MACHINE\\Security\\SAM\\Domains\\Account\\Users",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\DeviceClasses",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Watchdog",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\MediaCategories",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Windows",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\hivelist",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\ServiceCurrent",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Print",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Eventlog",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\RemoteAccess\\Performance",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient"
               );

        /*
        HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\splitter\Enum 190
        HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8A7A3521-B100-4315-BD39-C56990BB5C3F} mobile
        */
    }
    
    fclose(fp);

    return(0);

}


/* Check is syscheck is present in the config */
int config_syscheck()
{
    char *win_dir;
    FILE *fp;


    /* Add syscheck config */
    fp = fopen(OSSECCONF, "a");
    if(!fp)
        return(0); 

    /* We will also add rootcheck stuff if not present */
    if(!dogrep(OSSECCONF, "<rootcheck>") && !dogrep(OSSECCONF,"windows_audit"))
    {
        fprintf(fp,
                "\r\n"
                "<!-- Rootcheck config -->\r\n"
                "<ossec_config>\r\n"
                "  <rootcheck>\r\n"
                "    <windows_audit>./shared/win_audit_rcl.txt</windows_audit>\r\n"
                "    <windows_apps>./shared/win_applications_rcl.txt</windows_apps>\r\n"
                "    <windows_malware>./shared/win_malware_rcl.txt</windows_malware>\r\n"
                "  </rootcheck>\r\n"
                "</ossec_config>\r\n"
               );

    }
    

    /* We add here the last entry */
    if(dogrep(OSSECCONF, "dllcache</ignore>"))
    {
        fclose(fp);
        return(0);
    }

    /* Syscheck not configured, return */
    if(!dogrep(OSSECCONF, "<syscheck>"))
    {
        fclose(fp);
        return(0);
    }


    win_dir = get_win_dir();

    fprintf(fp, 
            "\r\n"    
            "<!-- Updated syscheck config -->\r\n"
            "<ossec_config>\r\n"
            "  <syscheck>\r\n"
            "    <frequency>64800</frequency>\r\n"
            "    <ignore>%s/System32/LogFiles</ignore>\r\n"
            "    <ignore>%s/system32/wbem/Logs</ignore>\r\n"
            "    <ignore>%s/Prefetch</ignore>\r\n"
            "    <ignore>%s/Debug</ignore>\r\n"
            "    <ignore>%s/PCHEALTH/HELPCTR/DataColl</ignore>\r\n"
            "    <ignore>%s/SoftwareDistribution</ignore>\r\n"
            "    <ignore>%s/Temp</ignore>\r\n"
            "    <ignore>%s/SchedLgU.Txt</ignore>\r\n"
            "    <ignore>%s/system32/config</ignore>\r\n"
            "    <ignore>%s/system32/CatRoot</ignore>\r\n"
            "    <ignore>%s/system32/wbem/Repository</ignore>\r\n"
            "    <ignore>%s/LastGood.Tmp</ignore>\r\n"
            "    <ignore>%s/LastGood</ignore>\r\n"
            "    <ignore>%s/Help</ignore>\r\n"
            "    <ignore>%s/Fonts</ignore>\r\n"
            "    <ignore>%s/PCHEALTH</ignore>\r\n"
            "    <ignore>%s/system32/dllcache</ignore>\r\n"
            "    <ignore>%s/system32/spool</ignore>\r\n"
            "    <ignore type=\"sregex\">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$</ignore>\r\n"
            "  </syscheck>\r\n"
            "</ossec_config>\r\n",
            win_dir, win_dir, win_dir, win_dir, win_dir,
            win_dir, win_dir, win_dir, win_dir, win_dir,
            win_dir, win_dir, win_dir, win_dir, win_dir,
            win_dir, win_dir, win_dir);

    fclose(fp);

    return(0);

}

/* Setup windows after install */
int main(int argc, char **argv)
{
    if(argc < 2)
    {
        printf("%s: Invalid syntax.\n", argv[0]);
        printf("Try: '%s directory'\n\n", argv[0]);
        return(0);
    }
    
    if(chdir(argv[1]) != 0)
    {
        printf("%s: Invalid directory: '%s'.\n", argv[0], argv[1]);
        return(0);
    }
    
    /* Checking if ossec was installed already */
    if(!fileexist(OSSECCONF))
    {
        char cmd[OS_MAXSTR +1];
        
        /* Copy default config to ossec.conf */
        snprintf(cmd, OS_MAXSTR, "copy %s %s", OSSECDEF, OSSECCONF);
        system(cmd);


        /* Adding syscheck */
        add_syscheck();
        config_syscheck();
        config_registry();
        

        /* Run iis-logs */
        snprintf(cmd, OS_MAXSTR, "setup-iis.exe .");
        system(cmd);

    }

    /* If it is present, we need to do the upgrade */
    else
    {
        char cmd[OS_MAXSTR +1];

        
        /* Look if syscheck is configured, if it is, update it */
        config_registry();
        config_syscheck();


        /* Run iis-logs here too */
        snprintf(cmd, OS_MAXSTR, "setup-iis.exe .");
        system(cmd);
    }


    /* Setting up local files */
    system("add-localfile.exe \"C:\\Windows\\pfirewall.log\" --quiet");
    system("add-localfile.exe \"C:\\Documents and Settings\\All Users\\Application Data\\Symantec\\Symantec AntiVirus Corporate Edition\\7.5\\Logs\\\%m\%d20\%y.log\" --quiet");
    

    /* Configure ossec for automatic startup */
    system("sc config OssecSvc start= auto");
    return(0);
}
