/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Manage agents tool
 * Add/extract and remove agents from a server
 */

#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"
#include <stdlib.h>

/* Global variables */
int restart_necessary;
time_t time1;
time_t time2;
time_t time3;
long int rand1;
long int rand2;


/* Remove spaces, newlines, etc from a string */
char *chomp(char *str)
{
    char *tmp_str;
    ssize_t size;

    /* Remove spaces from the beginning */
    while (*str == ' ' || *str == '\t') {
        str++;
    }

    /* Remove any trailing newlines or \r */
    do {
        tmp_str = strchr(str, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
            continue;
        }

        tmp_str = strchr(str, '\r');
        if (tmp_str) {
            *tmp_str = '\0';
        }
    } while (tmp_str != NULL);

    /* Remove spaces at the end of the string */
    tmp_str = str;
    size = (ssize_t) strlen(str) - 1;

    while ((size >= 0) && (tmp_str[size] == ' ' || tmp_str[size] == '\t')) {
        tmp_str[size] = '\0';
        size--;
    }

    return (str);
}

int add_agent()
{
    int i = 1;
    FILE *fp;
    char str1[STR_SIZE + 1];
    char str2[STR_SIZE + 1];

    os_md5 md1;
    os_md5 md2;

    char *user_input;
    char *_name;
    char *_id;
    char *_ip;

    char name[FILE_SIZE + 1];
    char id[FILE_SIZE + 1];
    char ip[FILE_SIZE + 1];
    os_ip c_ip;
    c_ip.ip = NULL;

    /* Check if we can open the auth_file */
    fp = fopen(AUTH_FILE, "a");
    if (!fp) {
        ErrorExit(FOPEN_ERROR, ARGV0, AUTH_FILE, errno, strerror(errno));
    }
    fclose(fp);


#ifndef WIN32
    if (chmod(AUTH_FILE, 0440) == -1) {
        ErrorExit(CHMOD_ERROR, ARGV0, AUTH_FILE, errno, strerror(errno));
    }
#endif

    /* Set time 2 */
    time2 = time(0);

    rand1 = random();

    /* Zero strings */
    memset(str1, '\0', STR_SIZE + 1);
    memset(str2, '\0', STR_SIZE + 1);

    printf(ADD_NEW);

    /* Get the name */
    memset(name, '\0', FILE_SIZE + 1);

    do {
        printf(ADD_NAME);
        fflush(stdout);
        /* Read the agent's name from user environment. If it is invalid
         * we should force user to provide a name from input device.
         */
        _name = getenv("OSSEC_AGENT_NAME");
        if (_name == NULL || NameExist(_name) || !OS_IsValidName(_name)) {
            _name = read_from_user();
        }

        if (strcmp(_name, QUIT) == 0) {
            goto cleanup;
        }

        strncpy(name, _name, FILE_SIZE - 1);

        /* Check the name */
        if (!OS_IsValidName(name)) {
            printf(INVALID_NAME, name);
        }

        /* Search for name  -- no duplicates */
        if (NameExist(name)) {
            printf(ADD_ERROR_NAME, name);
        }
    } while (NameExist(name) || !OS_IsValidName(name));

    /* Get IP */
    memset(ip, '\0', FILE_SIZE + 1);

    do {
        printf(ADD_IP);
        fflush(stdout);

        /* Read IP address from user's environment. If that IP is invalid,
         * force user to provide IP from input device */
        _ip = getenv("OSSEC_AGENT_IP");
        if (_ip == NULL || !OS_IsValidIP(_ip, &c_ip)) {
            _ip = read_from_user();
        }

        /* Quit */
        if (strcmp(_ip, QUIT) == 0) {
            goto cleanup;
        }

        strncpy(ip, _ip, FILE_SIZE - 1);

        if (!OS_IsValidIP(ip, &c_ip)) {
            printf(IP_ERROR, ip);
            _ip = NULL;
        }

    } while (!_ip);

    do {
        /* Default ID */
        i = MAX_AGENTS + 32512;
        snprintf(id, 8, "%03d", i);
        while (!IDExist(id)) {
            i--;
            snprintf(id, 8, "%03d", i);

            /* No key present, use id 0 */
            if (i <= 0) {
                i = 0;
                break;
            }
        }
        snprintf(id, 8, "%03d", i + 1);

        /* Get ID */
        printf(ADD_ID, id);
        fflush(stdout);

        /* Get Agent ID from environment. If 0, use default ID. If null,
         * get from user input. If value from environment is invalid,
         * we force user to specify an ID from the terminal. Otherwise,
         * our program goes to infinite loop.
         */
        _id = getenv("OSSEC_AGENT_ID");
        if (_id == NULL || IDExist(_id) || !OS_IsValidID(_id)) {
            _id = read_from_user();
        }

        /* If user specified 0 as Agent ID, he meant use default value.
         * NOTE: a bad condition can cause infinite loop.
         */
        if (strcmp(_id, "0") == 0) {
            strncpy(_id, id, FILE_SIZE - 1);
        }

        /* Quit */
        if (strcmp(_id, QUIT) == 0) {
            goto cleanup;
        }

        if (_id[0] != '\0') {
            strncpy(id, _id, FILE_SIZE - 1);
        }

        if (!OS_IsValidID(id)) {
            printf(INVALID_ID, id);
        }

        /* Search for ID KEY  -- no duplicates */
        if (IDExist(id)) {
            printf(ADD_ERROR_ID, id);
        }

    } while (IDExist(id) || !OS_IsValidID(id));

    printf(AGENT_INFO, id, name, ip);
    fflush(stdout);

    do {
        printf(ADD_CONFIRM);
        /* Confirmation by an environment variable. The valid value is y/Y.
         * If the user provides anything other string, it is considered as
         * n/N; please note that the old code only accepts y/Y/n/N. So if
         * the variable OSSEC_ACTION_CONFIRMED is 'foobar', the program will
         * go into an infinite loop.
         */
        user_input = getenv("OSSEC_ACTION_CONFIRMED");
        if (user_input == NULL) {
            user_input = read_from_user();
        }

        /* If user accepts to add */
        if (user_input[0] == 'y' || user_input[0] == 'Y') {
            time3 = time(0);
            rand2 = random();

            fp = fopen(AUTH_FILE, "a");
            if (!fp) {
                ErrorExit(FOPEN_ERROR, ARGV0, KEYS_FILE, errno, strerror(errno));
            }
#ifndef WIN32
            chmod(AUTH_FILE, 0440);
#endif

            /* Random 1: Time took to write the agent information
             * Random 2: Time took to choose the action
             * Random 3: All of this + time + pid
             * Random 4: Md5 all of this + the name, key and IP
             * Random 5: Final key
             */

            snprintf(str1, STR_SIZE, "%d%s%d", (int)(time3 - time2), name, (int)rand1);
            snprintf(str2, STR_SIZE, "%d%s%s%d", (int)(time2 - time1), ip, id, (int)rand2);

            OS_MD5_Str(str1, md1);
            OS_MD5_Str(str2, md2);

            snprintf(str1, STR_SIZE, "%s%d%d%d", md1, (int)getpid(), (int)random(),
                     (int)time3);
            OS_MD5_Str(str1, md1);

            fprintf(fp, "%s %s %s %s%s\n", id, name, c_ip.ip, md1, md2);

            fclose(fp);

            printf(AGENT_ADD);
            restart_necessary = 1;
            break;
        } else { /* if(user_input[0] == 'n' || user_input[0] == 'N') */
            printf(ADD_NOT);
            break;
        }
    } while (1);

    cleanup:
    free(c_ip.ip);

    return (0);
}

int remove_agent()
{
    FILE *fp;
    char *user_input;
    char u_id[FILE_SIZE + 1];
    int id_exist;

    u_id[FILE_SIZE] = '\0';

    if (!print_agents(0, 0, 0)) {
        printf(NO_AGENT);
        return (0);
    }

    do {
        printf(REMOVE_ID);
        fflush(stdout);

        user_input = getenv("OSSEC_AGENT_ID");
        if (user_input == NULL) {
            user_input = read_from_user();
        } else {
            printf("%s\n", user_input);
        }

        if (strcmp(user_input, QUIT) == 0) {
            return (0);
        }

        strncpy(u_id, user_input, FILE_SIZE);

        id_exist = IDExist(user_input);

        if (!id_exist) {
            printf(NO_ID, user_input);

            /* Exit here if we are using environment variables
             * and our ID does not exist
             */
            if (getenv("OSSEC_AGENT_ID")) {
                return (1);
            }
        }
    } while (!id_exist);

    do {
        printf(REMOVE_CONFIRM);
        fflush(stdout);

        user_input = getenv("OSSEC_ACTION_CONFIRMED");
        if (user_input == NULL) {
            user_input = read_from_user();
        } else {
            printf("%s\n", user_input);
        }

        /* If user confirms */
        if (user_input[0] == 'y' || user_input[0] == 'Y') {
            /* Get full agent name */
            char *full_name = getFullnameById(u_id);
            if (!full_name) {
                printf(NO_ID, u_id);
                return (1);
            }

            fp = fopen(AUTH_FILE, "r+");
            if (!fp) {
                free(full_name);
                ErrorExit(FOPEN_ERROR, ARGV0, AUTH_FILE, errno, strerror(errno));
            }
#ifndef WIN32
            chmod(AUTH_FILE, 0440);
#endif

            /* Remove the agent, but keep the id */
            fsetpos(fp, &fp_pos);
            fprintf(fp, "%s #*#*#*#*#*#*#*#*#*#*#", u_id);

            fclose(fp);

            /* Remove counter for ID */
            delete_agentinfo(full_name);
            OS_RemoveCounter(u_id);
            free(full_name);
            full_name = NULL;

            printf(REMOVE_DONE, u_id);
            restart_necessary = 1;
            break;
        } else { /* if(user_input[0] == 'n' || user_input[0] == 'N') */
            printf(REMOVE_NOT);
            break;
        }
    } while (1);

    return (0);
}

int list_agents(int cmdlist)
{
    if (!print_agents(0, 0, 0)) {
        printf(NO_AGENT);
    }

    printf("\n");
    if (!cmdlist) {
        printf(PRESS_ENTER);
        read_from_user();
    }

    return (0);
}

