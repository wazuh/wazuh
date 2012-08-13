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
#include <stdlib.h>

/* b64 function prototypes */
char *decode_base64(const char *src);
char *encode_base64(int size, char *src);


/* Import a key */
int k_import(char *cmdimport)
{
    FILE *fp;
    char *user_input;
    char *b64_dec;

    char *name; char *ip; char *tmp_key;

    char line_read[FILE_SIZE +1];


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
                    fp = fopen(KEYS_FILE,"w");
                    if(!fp)
                    {
                        ErrorExit(FOPEN_ERROR, ARGV0, KEYS_FILE);
                    }
                    fprintf(fp,"%s\n",line_read);
                    fclose(fp);
                    #ifndef WIN32
                    chmod(KEYS_FILE, 0440);
                    #endif

                    /* Removing sender counter. */
                    OS_RemoveCounter("sender");

                    printf(ADDED);
                    printf(PRESS_ENTER);
                    read_from_user();
                    restart_necessary = 1;
                    return(1);
                }
                else /* if(user_input[0] == 'n' || user_input[0] == 'N') */
                {
                    printf("%s", ADD_NOT);
                    return(0);
                }
            }
        }
    }

    printf(NO_KEY);
    printf(PRESS_ENTER);
    read_from_user();
    return(0);

}


/* extract base64 for a specific agent */
int k_extract(char *cmdextract)
{
    FILE *fp;
    char *user_input;
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

    fsetpos(fp, &fp_pos);

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


/* EOF */
