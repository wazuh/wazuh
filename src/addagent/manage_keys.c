/* @(#) $Id: ./src/addagent/manage_keys.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"
#include <stdlib.h>

static char *trimwhitespace(char *str);

static char *trimwhitespace(char *str)
{
  char *end;

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}

/* Import a key */
int k_import(const char *cmdimport)
{
    FILE *fp;
    const char *user_input;
    char *b64_dec;

    char *name; char *ip; char *tmp_key;

    char line_read[FILE_SIZE +1];

    char auth_file_tmp[] = AUTH_FILE;
    char *keys_file = basename_ex(auth_file_tmp);

    char tmp_path[strlen(TMP_DIR) + 1 + strlen(keys_file) + 6 + 1];

    snprintf(tmp_path, sizeof(tmp_path), "%s/%sXXXXXX", TMP_DIR, keys_file);

    /* Parsing user argument. */
    if(cmdimport)
    {
        user_input = cmdimport;
    }
    else
    {
        printf(IMPORT_KEY);

        user_input = getenv("OSSEC_AGENT_KEY");
        if (user_input == NULL) {
          user_input = read_from_user();
        }
    }


    /* quit */
    if(strcmp(user_input, QUIT) == 0)
        return(0);

    b64_dec = decode_base64(user_input);
    if(b64_dec == NULL)
    {
        printf(NO_KEY);
        printf(PRESS_ENTER);
        read_from_user();
        return(0);
    }


    memset(line_read, '\0', FILE_SIZE +1);
    strncpy(line_read, b64_dec, FILE_SIZE);


    name = strchr(b64_dec, ' ');
    if(name && strlen(line_read) < FILE_SIZE)
    {
        *name = '\0';
        name++;
        ip = strchr(name, ' ');
        if(ip)
        {
            *ip = '\0';
            ip++;

            tmp_key = strchr(ip, ' ');
            if(!tmp_key)
            {
                printf(NO_KEY);
                return(0);
            }
            *tmp_key = '\0';

            printf("\n");
            printf(AGENT_INFO, b64_dec, name, ip);

            while(1)
            {
                printf(ADD_CONFIRM);
                fflush(stdout);

                user_input = getenv("OSSEC_ACTION_CONFIRMED");
                if (user_input == NULL) {
                  user_input = read_from_user();
                }

                if(user_input[0] == 'y' || user_input[0] == 'Y')
                {
                    if (mkstemp_ex(tmp_path))
                    {
                        ErrorExit(MKSTEMP_ERROR, ARGV0, tmp_path);
                    }

                    #ifndef WIN32
                    if (chmod(tmp_path, 0440))
                    {
                        if (unlink(tmp_path))
                        {
                            verbose(DELETE_ERROR, ARGV0, tmp_path, errno, strerror(errno));
                        }

                        ErrorExit(CHMOD_ERROR, ARGV0, tmp_path, errno, strerror(errno));
                    }
                    #endif

                    fp = fopen(tmp_path,"w");
                    if(!fp)
                    {
                        if (unlink(tmp_path))
                        {
                            verbose(DELETE_ERROR, ARGV0, tmp_path, errno, strerror(errno));
                        }

                        ErrorExit(FOPEN_ERROR, ARGV0, tmp_path);
                    }
                    fprintf(fp,"%s\n",line_read);
                    fclose(fp);

                    if (rename_ex(tmp_path, KEYS_FILE))
                    {
                        if (unlink(tmp_path))
                        {
                            verbose(DELETE_ERROR, ARGV0, tmp_path, errno, strerror(errno));
                        }

                        ErrorExit(RENAME_ERROR, ARGV0, tmp_path);
                    }

                    /* Removing sender counter. */
                    OS_RemoveCounter("sender");

                    printf(ADDED);
                    printf(PRESS_ENTER);
                    read_from_user();
                    restart_necessary = 1;

                    free(b64_dec);
                    return(1);
                }
                else /* if(user_input[0] == 'n' || user_input[0] == 'N') */
                {
                    printf("%s", ADD_NOT);

                    free(b64_dec);
                    return(0);
                }
            }
        }
    }

    printf(NO_KEY);
    printf(PRESS_ENTER);
    read_from_user();

    free(b64_dec);
    return(0);

}


/* extract base64 for a specific agent */
int k_extract(const char *cmdextract)
{
    FILE *fp;
    const char *user_input;
    char *b64_enc;
    char line_read[FILE_SIZE +1];
    char n_id[USER_SIZE +1];


    if(cmdextract)
    {
        user_input = cmdextract;

        if(!IDExist(user_input))
        {
            printf(NO_ID, user_input);
            exit(1);
        }
    }

    else
    {
        if(!print_agents(0, 0, 0))
        {
            printf(NO_AGENT);
            printf(PRESS_ENTER);
            read_from_user();
            return(0);
        }

        do
        {
            printf(EXTRACT_KEY);
            fflush(stdout);
            user_input = read_from_user();

            /* quit */
            if(strcmp(user_input, QUIT) == 0)
                return(0);

            if(!IDExist(user_input))
                printf(NO_ID, user_input);

        } while(!IDExist(user_input));
    }


    /* Trying to open the auth file */
    fp = fopen(AUTH_FILE, "r");
    if(!fp)
    {
        ErrorExit(FOPEN_ERROR, ARGV0, AUTH_FILE);
    }

    if(fsetpos(fp, &fp_pos))
    {
        merror("%s: Can not set fileposition.", ARGV0);
        exit(1);
    }

    memset(n_id, '\0', USER_SIZE +1);
    strncpy(n_id, user_input, USER_SIZE -1);


    if(fgets(line_read, FILE_SIZE, fp) == NULL)
    {
        printf(ERROR_KEYS);
        fclose(fp);
        exit(1);
    }
    chomp(line_read);


    b64_enc = encode_base64(strlen(line_read),line_read);
    if(b64_enc == NULL)
    {
        printf(EXTRACT_ERROR);
        fclose(fp);
        exit(1);
    }

    printf(EXTRACT_MSG, n_id, b64_enc);
    if(!cmdextract)
    {
        printf("\n" PRESS_ENTER);
        read_from_user();
    }

    free(b64_enc);
    fclose(fp);

    return(0);
}

/* Bulk generate client keys from file */
int k_bulkload(const char *cmdbulk)
{
    int i = 1;
    FILE *fp, *infp;
    char str1[STR_SIZE +1];
    char str2[STR_SIZE +1];

    os_md5 md1;
    os_md5 md2;
    char line[FILE_SIZE+1];
    char name[FILE_SIZE +1];
    char id[FILE_SIZE +1];
    char ip[FILE_SIZE+1];
    char delims[] = ",";
    char * token = NULL;

    /* Checking if we can open the input file */
    printf("Opening: [%s]\n", cmdbulk);
    infp = fopen(cmdbulk,"r");
    if(!infp)
    {
        perror("Failed.");
        ErrorExit(FOPEN_ERROR, ARGV0, cmdbulk);
    }


    /* Checking if we can open the auth_file */
    fp = fopen(AUTH_FILE,"a");
    if(!fp)
    {
        ErrorExit(FOPEN_ERROR, ARGV0, AUTH_FILE);
    }
    fclose(fp);

    while(fgets(line, FILE_SIZE - 1, infp) != NULL)
	{
        os_ip c_ip;
        c_ip.ip = NULL;

		if (1 >= strlen(trimwhitespace(line)))
			continue;

		memset(ip, '\0', FILE_SIZE +1);
		token = strtok(line, delims);
		strncpy(ip, trimwhitespace(token),FILE_SIZE -1);

		memset(name, '\0', FILE_SIZE +1);
		token = strtok(NULL, delims);
		strncpy(name, trimwhitespace(token),FILE_SIZE -1);

        #ifndef WIN32
        chmod(AUTH_FILE, 0440);
        #endif

        /* Setting time 2 */
        time2 = time(0);


        /* Source is time1+ time2 +pid + ppid */
        #ifndef WIN32
        #ifdef __OpenBSD__
        srandomdev();
        #else
        srandom((unsigned)(time2 + time1 + getpid() + getppid()));
        #endif
        #else
        srandom(time2 + time1 + getpid());
        #endif

        rand1 = random();


        /* Zeroing strings */
        memset(str1,'\0', STR_SIZE +1);
        memset(str2,'\0', STR_SIZE +1);


        /* check the name */
        if(!OS_IsValidName(name))
        {
            printf(INVALID_NAME,name);
            continue;
        }

        /* Search for name  -- no duplicates */
        if(NameExist(name))
        {
            printf(ADD_ERROR_NAME, name);
            continue;
        }


        if(!OS_IsValidIP(ip, &c_ip))
        {
            printf(IP_ERROR, ip);
            continue;
        }

		/* Default ID */
		i = MAX_AGENTS + 32512;
		snprintf(id, 8, "%03d", i);
		while(!IDExist(id))
		{
		    i--;
		    snprintf(id, 8, "%03d", i);

            /* No key present, use id 0 */
            if(i <= 0)
            {
                i = 0;
                break;
            }
		}
		snprintf(id, 8, "%03d", i+1);

		if(!OS_IsValidID(id))
		{
		    printf(INVALID_ID, id);
		    goto cleanup;
		}

		/* Search for ID KEY  -- no duplicates */
		if(IDExist(id))
		{
		    printf(NO_DEFAULT, i+1);
		    goto cleanup;
		}

        printf(AGENT_INFO, id, name, ip);
        fflush(stdout);


        time3 = time(0);
        rand2 = random();

        fp = fopen(AUTH_FILE,"a");
        if(!fp)
        {
            ErrorExit(FOPEN_ERROR, ARGV0, KEYS_FILE);
        }
        #ifndef WIN32
        if(chmod(AUTH_FILE, 0440) == -1)
        {
            ErrorExit(CHMOD_ERROR, ARGV0, AUTH_FILE);
        }
        #endif


        /* Random 1: Time took to write the agent information.
        * Random 2: Time took to choose the action.
        * Random 3: All of this + time + pid
        * Random 4: Md5 all of this + the name, key and ip
        * Random 5: Final key
        */

        snprintf(str1, STR_SIZE, "%d%s%d",(int)(time3-time2), name, (int)rand1);
        snprintf(str2, STR_SIZE, "%d%s%s%d", (int)(time2-time1), ip, id, (int)rand2);

        OS_MD5_Str(str1, md1);
        OS_MD5_Str(str2, md2);

        snprintf(str1, STR_SIZE, "%s%d%d%d",md1,(int)getpid(), (int)random(),
                (int)time3);
        OS_MD5_Str(str1, md1);

        //fprintf(fp,"%s %s %s %s%s\n",id, name, ip, md1,md2);
        fprintf(fp,"%s %s %s %s%s\n",id, name, c_ip.ip, md1,md2);

        fclose(fp);

        printf(AGENT_ADD);
        restart_necessary = 1;

        cleanup:
        free(c_ip.ip);
	};

	fclose(infp);
	return(0);
}


/* EOF */
