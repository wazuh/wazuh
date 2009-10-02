/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"


/* flags for read_dir and read_file */
#define CREATE_DB   1
#define CHECK_DB    2    
int __counter = 0;


/** Prototypes **/
int read_dir(char *dir_name, int opts, int flag);


/* int check_file(char *file_name)
 * Checks if the file is already in the database.
 */
int check_file(char *file_name)
{
    char buf[MAX_LINE +2];
    buf[MAX_LINE +1] = '\0';
    
    while(fgets(buf, MAX_LINE, syscheck.fp) != NULL)
    {
        if((buf[0] != '#') && (buf[0] != ' ') && (buf[0] != '\n'))
        {
            char *n_buf;

            /* Removing the new line */
            n_buf = strchr(buf,'\n');
            if(n_buf == NULL)
                continue;

            *n_buf = '\0';


            /* First 6 characters are for internal use */
            n_buf = buf;
            n_buf+=6;

            n_buf = strchr(n_buf, ' ');
            if(n_buf)
            {
                n_buf++;

                /* Checking if name matches */
                if(strcmp(n_buf, file_name) == 0)
                    return(1);
            }
        }
    }

    /* New file */
    sleep(1);
    
    debug2("%s: DEBUG: new file '%s'.", ARGV0, file_name);
    return(0);
}



/* int read_file(char *file_name, int opts, int flag)
 * Reads and generates the integrity data of a file.
 */
int read_file(char *file_name, int opts, int flag)
{
    int check_file_new = 0;
    struct stat statbuf;
    
    /* Checking if file is to be ignored */
    if(syscheck.ignore)
    {
        int i = 0;
        while(syscheck.ignore[i] != NULL)
        {
            if(strncasecmp(syscheck.ignore[i], file_name, 
                           strlen(syscheck.ignore[i])) == 0)
            {
                return(0);            
            }

            i++;
        }
    }

    /* Checking in the regex entry */
    if(syscheck.ignore_regex)
    {
        int i = 0;
        while(syscheck.ignore_regex[i] != NULL)
        {
            if(OSMatch_Execute(file_name, strlen(file_name), 
                                          syscheck.ignore_regex[i]))
            {
                return(0);
            }
            i++;
        }
    }


    /* Win32 does not have lstat */
    #ifdef WIN32
    if(stat(file_name, &statbuf) < 0)
    #else
    if(lstat(file_name, &statbuf) < 0)
    #endif
    {
        merror("%s: Error accessing '%s'.",ARGV0, file_name);
        return(-1);
    }
    
    if(S_ISDIR(statbuf.st_mode))
    {
        #ifdef DEBUG
        verbose("%s: Reading dir: %s\n",ARGV0, file_name);
        #endif

        return(read_dir(file_name, opts, flag));
    }
    
    
    /* No S_ISLNK on windows */
    #ifdef WIN32
    else if(S_ISREG(statbuf.st_mode))
    #else
    else if(S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
    #endif    
    {
        os_md5 mf_sum;
        os_sha1 sf_sum;


        /* If check_db, we just need to verify that the file is
         * already present. If not, we add it.
         */
        if(flag == CHECK_DB)
        {
            /* File in the database already */
            fseek(syscheck.fp, 0, SEEK_SET);
            if(check_file(file_name))
            {
                /* Sleeping in here too */
                #ifndef WIN32
                if(__counter >= (3 * syscheck.sleep_after))
                #else
                if(__counter >= (syscheck.sleep_after))
                #endif
                {
                    sleep(syscheck.tsleep);
                    __counter = 0;
                }
                __counter++;

                return(0);
            }
            fseek(syscheck.fp, 0, SEEK_END);
            check_file_new = 1;
        }


        /* Cleaning sums */
        strncpy(mf_sum, "xxx", 4);
        strncpy(sf_sum, "xxx", 4);


        /* Generating checksums. */
        if((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM))
        {
            /* If it is a link, we need to check if dest is valid. */
            #ifndef WIN32
            if(S_ISLNK(statbuf.st_mode))
            {
                struct stat statbuf_lnk;
                if(stat(file_name, &statbuf_lnk) == 0)
                {
                    if(S_ISREG(statbuf_lnk.st_mode))
                    {
                        if(OS_MD5_SHA1_File(file_name, mf_sum, sf_sum) < 0)
                        {
                            strncpy(mf_sum, "xxx", 4);
                            strncpy(sf_sum, "xxx", 4);
                        }
                    }
                }
            }
            else if(OS_MD5_SHA1_File(file_name, mf_sum, sf_sum) < 0)

            #else
            if(OS_MD5_SHA1_File(file_name, mf_sum, sf_sum) < 0)
            #endif
            
            {
                strncpy(mf_sum, "xxx", 4);
                strncpy(sf_sum, "xxx", 4);
            }
        }
        
        
        /* Adding file */
        fprintf(syscheck.fp,"%c%c%c%c%c%c%d:%d:%d:%d:%s:%s %s\n",
                opts & CHECK_SIZE?'+':'-',
                opts & CHECK_PERM?'+':'-',
                opts & CHECK_OWNER?'+':'-',
                opts & CHECK_GROUP?'+':'-',
                opts & CHECK_MD5SUM?'+':'-',
                opts & CHECK_SHA1SUM?'+':'-',
                opts & CHECK_SIZE?(int)statbuf.st_size:0,
                opts & CHECK_PERM?(int)statbuf.st_mode:0,
                opts & CHECK_OWNER?(int)statbuf.st_uid:0,
                opts & CHECK_GROUP?(int)statbuf.st_gid:0,
                opts & CHECK_MD5SUM?mf_sum:"xxx",
                opts & CHECK_SHA1SUM?sf_sum:"xxx",
                file_name);


        /* Send new file */
        if(check_file_new)
        {
            char alert_msg[912 +2];

            /* Sending the new checksum to the analysis server */
            alert_msg[912 +1] = '\0';
            snprintf(alert_msg, 912, "%d:%d:%d:%d:%s:%s %s", 
                     opts & CHECK_SIZE?(int)statbuf.st_size:0,
                     opts & CHECK_PERM?(int)statbuf.st_mode:0,
                     opts & CHECK_OWNER?(int)statbuf.st_uid:0,
                     opts & CHECK_GROUP?(int)statbuf.st_gid:0,
                     opts & CHECK_MD5SUM?mf_sum:"xxx",
                     opts & CHECK_SHA1SUM?sf_sum:"xxx",
                     file_name);
            send_syscheck_msg(alert_msg);
        }
        
        
        /* Sleeping in here too */
        #ifndef WIN32
        if(__counter >= (3 * syscheck.sleep_after))
        #else
        if(__counter >= (2 * syscheck.sleep_after))
        #endif    
        {
            sleep(syscheck.tsleep);
            __counter = 0;
        }
        __counter++;


        #ifdef DEBUG 
        verbose("%s: file '%s %s'",ARGV0, file_name, mf_sum);
        #endif
    }
    else
    {
        #ifdef DEBUG
        verbose("%s: *** IRREG file: '%s'\n",ARGV0,file_name);
        #endif
    }

    return(0);
}


/* read_dir v0.1
 *
 */
int read_dir(char *dir_name, int opts, int flag)
{
    int dir_size;
   
    char f_name[PATH_MAX +2]; 
    DIR *dp;
    
	struct dirent *entry;

    f_name[PATH_MAX +1] = '\0';
	

    /* Directory should be valid */
    if((dir_name == NULL)||((dir_size = strlen(dir_name)) > PATH_MAX))
    {
        if(flag == CREATE_DB)
            merror(NULL_ERROR, ARGV0);
        
        return(-1);
    }
    
    
    /* Opening the directory given */
    dp = opendir(dir_name);
	if(!dp)
    {
        if(errno == ENOTDIR)
        {
            if(read_file(dir_name, opts, flag) == 0)
                return(0);
        }
        
        if(flag == CREATE_DB)
        {
            #ifdef WIN32
            int di = 0;
            char *(defaultfilesn[])= {
                                     "C:\\autoexec.bat",
                                     "C:\\config.sys",
                                     "C:\\WINDOWS/System32/eventcreate.exe",
                                     "C:\\WINDOWS/System32/eventtriggers.exe",
                                     "C:\\WINDOWS/System32/tlntsvr.exe",
                                     "C:\\WINDOWS/System32/Tasks",
                                     NULL
                                     };
            while(defaultfilesn[di] != NULL)
            {
                if(strcmp(defaultfilesn[di], dir_name) == 0)
                {
                    break;
                }
                di++;
            }

            if(defaultfilesn[di] == NULL)
            {
                merror("%s: WARN: Error opening directory: '%s': %s ",
                        ARGV0, dir_name, strerror(errno)); 
            }
            
            #else
            
            merror("%s: WARN: Error opening directory: '%s': %s ",
                                              ARGV0,
                                              dir_name,
                                              strerror(errno));
            #endif
        }
        
        return(-1);
    }
    

    /* Checking for real time flag. */
    if(opts & CHECK_REALTIME)
    {
        #ifdef USEINOTIFY
        realtime_adddir(dir_name);
        #endif
    }


    while((entry = readdir(dp)) != NULL)
    {
        char *s_name;
        
        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
           (strcmp(entry->d_name,"..") == 0))  
            continue;
            
        strncpy(f_name, dir_name, PATH_MAX);
       
        s_name = f_name;
        
        s_name += dir_size;


        /* checking if the file name is already null terminated */
        if(*(s_name-1) != '/')
            *s_name++ = '/';
            
        *s_name = '\0';
        
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size -2);
        read_file(f_name, opts, flag);
    }

    closedir(dp);
    return(0);
}


/* int check_db()
 * Checks database for new files.
 */
int check_db()
{
    int i = 0;

    /* Read all available directories */
    __counter = 0;
    do
    {
        read_dir(syscheck.dir[i], syscheck.opts[i], CHECK_DB);
        i++;
    }while(syscheck.dir[i] != NULL);

    return(0);
}



/* int create_db
 * Creates the file database.
 */
int create_db(int delete_db)
{
    int i = 0;
    
    syscheck.fp = fopen(syscheck.db, "w+"); /* Read and write */
    if(!syscheck.fp)
    {
        ErrorExit("%s: Unable to create syscheck database "
                  "at '%s'. Exiting.",ARGV0,syscheck.db);
        return(0);    
    }


    /* Creating a local fp only */
    if(delete_db)
    {
        unlink(syscheck.db);
    }

    
    /* dir_name can't be null */
    if((syscheck.dir == NULL) || (syscheck.dir[0] == NULL))
    {
        merror("%s: No directories to check.",ARGV0);
        return(-1);
    }
    

    merror("%s: INFO: Starting syscheck database (pre-scan).", ARGV0);


    /* Read all available directories */
    __counter = 0;
    do
    {
        if(read_dir(syscheck.dir[i], syscheck.opts[i], CREATE_DB) == 0)
        {
            #ifdef WIN32
            if(syscheck.opts[i] & CHECK_REALTIME)
            {
                realtime_adddir(syscheck.dir[i]);
            }
            #endif
        }
        i++;
    }while(syscheck.dir[i] != NULL);

    
    merror("%s: INFO: Finished creating syscheck database (pre-scan "
           "completed).", ARGV0);
    return(0);

}

/* EOF */
