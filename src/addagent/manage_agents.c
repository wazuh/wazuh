/*   $OSSEC, addagent.c, v0.2, 2006/01/27, Daniel B. Cid$   */

/* Copyright (C) 2005,2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Manage agents tool
 * Add/extract and remove agents from a server.
 */


#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"



/* Global internal variables */



/* chomp: remove spaces, new lines, etc from a string */
char *chomp(char *str)
{
    char *tmp_str;
    int size = 0;

    /* Removing spaces from the beginning */
    while(*str == ' ' || *str == '\t')
        str++;
    
    
    /* Removing any trailing new lines or \r */
    do
    {
        tmp_str = strchr(str, '\n');
        if(tmp_str)
        {
            *tmp_str = '\0';
            continue;
        }

        tmp_str = strchr(str, '\r');
        if(tmp_str)
        {
            *tmp_str = '\0';
        }
    }while(tmp_str != NULL);

    
    /* Removing spaces at the end of the string */
    tmp_str = str;
    size = strlen(str)-1;
    
    while((size >= 0) && (tmp_str[size] == ' ' || tmp_str[size] == '\t'))
    {
        tmp_str[size] = '\0';
        size--;
    }
    
    return(str);
}



/* Add an agent */
int add_agent()
{
    int i = 1;
    FILE *fp;
    char str1[STR_SIZE];
    char str2[STR_SIZE];
    
    os_md5 md1;
    os_md5 md2;
    
    char *user_input;
    char *_name;
    char *_id;
    char *_ip;

    char name[FILE_SIZE +1];
    char id[FILE_SIZE +1];
    char ip[FILE_SIZE +1];

    
    /* Checking if we can open the auth_file */
    fp = fopen(AUTH_FILE,"a");
    if(!fp)
    {
        ErrorExit(FOPEN_ERROR, ARGV0, AUTH_FILE);
    }
    fclose(fp);

    
    /* Setting time 2 */
    time2 = time(0);

    
    /* Source is time1+ time2 +pid + ppid */
    #ifndef WIN32
    srand(time2 + time1 + getpid() + getppid());
    #else
    srand(time2 + time1 + getpid());
    #endif
    rand1 = rand();

    
    /* Zeroing strings */
    memset(str1,'\0', STR_SIZE);
    memset(str2,'\0', STR_SIZE);


    printf(ADD_NEW);

    
    /* Getting the name */
    memset(name, '\0', STR_SIZE);
    do
    {
      printf(ADD_NAME);
      fflush(stdout);

      _name = read_from_user();
      strncpy(name, _name, FILE_SIZE -1);

      /* Search for ID KEY  -- no duplicates */
      if(NameExist(name))
         printf(ADD_ERROR_NAME, name);

    } while(NameExist(name));

    
    /* Getting IP */
    memset(ip, '\0', STR_SIZE);

    do
    {
      printf(ADD_IP);
      fflush(stdout);
    
      _ip = read_from_user();
      strncpy(ip, _ip, FILE_SIZE -1);
      
      if(!OS_IsValidIP(ip) || OS_HasNetmask(ip))
          printf(IP_ERROR, ip);

    } while(!OS_IsValidIP(ip) || OS_HasNetmask(ip));
   
    
    /* Default ID */
    snprintf(id, 8, "00%d", i);
    while(IDExist(id))
    {
        i++;
        snprintf(id, 8, "00%d", i);

        if(i >= 249)
        {
            printf(ERROR_KEYS);
        }
    }
   
    
    /* Getting ID */
    do
    {
      printf(ADD_ID, id);
      fflush(stdout);
    
      _id = read_from_user();
      if(_id[0] != '\0')
      {
          strncpy(id, _id, FILE_SIZE -1);
      }
      /* Search for ID KEY  -- no duplicates */
      if(IDExist(id))
      {
        printf(ADD_ERROR_ID, id);
      }
    } while(IDExist(id));
    
    

    printf(AGENT_INFO, id, name, ip);
    fflush(stdout);

    do
    {
      printf(ADD_CONFIRM);
      user_input = read_from_user();
   
      /* If user accepts to add */ 
      if(user_input[0] == 'y' || user_input[0] == 'Y')
      {
        time3 = time(0);
        rand2 = rand();

        fp = fopen(AUTH_FILE,"a");
        if(!fp)
        {
            ErrorExit(FOPEN_ERROR, ARGV0, KEYS_FILE);
        }
        
        /* Random 1: Time took to write the agent information.
         * Random 2: Time took to choose the action.
         * Random 3: All of this + time + pid
         * Random 4: Md5 all of this + the name, key and ip
         * Random 5: Final key
         */
        
        snprintf(str1, 64, "%d%s%d",time3-time2, name, rand1);
        snprintf(str2, 64, "%d%s%s%d", time2-time1, ip, id, rand2);

        OS_MD5_Str(str1, md1);
        OS_MD5_Str(str2, md2);

        snprintf(str1, 64, "%s%d%d%d",md1,(int)getpid(),rand(), time3);
        OS_MD5_Str(str1, md1);

        fprintf(fp,"%s %s %s %s%s\n",id, name, ip, md1,md2);

        fclose(fp);

        printf(AGENT_ADD);
      }
      else if(user_input[0] == 'n' || user_input[0] == 'N')
      {
        printf(ADD_NOT);
      }

    } while(!(user_input[0] == 'y' || user_input[0] == 'Y' || user_input[0] == 'n' || user_input[0] == 'N'));

    return(0);
}


/* remove an agent */
int remove_agent()
{
    FILE *fp;
    char *user_input;
    char u_id[FILE_SIZE +1];
    

    if(!print_agents())
    {
        printf(NO_AGENT);
        return(0);
    }

    do
    {
      printf(REMOVE_ID);
      fflush(stdout);

      user_input = read_from_user();
      strcpy(u_id, user_input);

      if(!IDExist(user_input))
      {
        printf(NO_ID, user_input);
      }
    } while(!IDExist(user_input));
    
    do
    {
      printf(REMOVE_CONFIRM);
      fflush(stdout);
    
      user_input = read_from_user();
    
      /* If user confirm */
      if(user_input[0] == 'y' || user_input[0] == 'Y')
      {
        fp = fopen(AUTH_FILE, "r+");
        if(!fp)
        {
            ErrorExit(FOPEN_ERROR, ARGV0, AUTH_FILE);
        }
        
        fsetpos(fp, &fp_pos);
        fprintf(fp, "# # # # # # # #");
        fclose(fp);
        printf(REMOVE_DONE, u_id);
      }
      else if(user_input[0] == 'n' || user_input[0] == 'N')
      {
        printf(REMOVE_NOT);
      }

    } while(!(user_input[0] == 'y' || user_input[0] == 'Y' || user_input[0] == 'n' || user_input[0] == 'N'));

    return(0);
}


int list_agents()
{
  if(!print_agents())
    printf(NO_AGENT);


  printf(PRESS_ENTER);
  read_from_user();

  return(0);

}

/* EOF */
