/*   $OSSEC, manage_agents.h, v0.1, 2006/01/27, Daniel B. Cid$   */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"


/** Prototypes **/

/* Read any input from the user (stdin) */
char *read_from_user();

/* Add or remove an agent */
int add_agent();
int remove_agent();

/* Extract or import a key */
int k_extract();
int k_import();

/* Validation functions */
int IDExist(char *id);
int NameExist(char *u_name);

/* Print available agents */
int print_agents();
    
/* clear a line */
char *chomp(char *str);


/* Shared variables */
int time1;
int time2;
int time3;
int rand1;
int rand2;
fpos_t fp_pos;


/* Internal defines */
#define USER_SIZE       514
#define FILE_SIZE       257
#define STR_SIZE        66



/* Print agents */
#define PRINT_AVAILABLE     "\nAvailable agents: \n"
#define PRINT_AGENT         "   ID: %s, Name: %s, IP: %s\n"

/* Add new agent */
#define ADD_NEW         "\nAdding a new agent. Please provide the following:\n"
#define ADD_NAME        "   * A name for the new agent: "
#define ADD_IP          "   * The IP Address for the new agent: "
#define ADD_ID          "   * An ID for the new agent[%s]: "
#define AGENT_INFO      "Agent information:\n   ID:%s\n   Name:%s\n   " \
                        "IP Address:%s\n\nConfirm adding it?(y/n): "
#define AGENT_ADD       "Added.\n"
#define ADD_NOT         "Not Adding..\n"
#define PRESS_ENTER     "** Press ENTER to continue.\n"

/* Add errors */
#define ADD_ERROR_ID    "\n** ID '%s' already present. Starting over again.\n"
#define ADD_ERROR_NAME  "\n** Name '%s' already present. Starting over again.\n"
#define IP_ERROR        "\n** Invalid IP '%s'. Starting over again.\n"
#define NO_AGENT        "\n** No agent available. You need to add one first.\n"
#define NO_ID           "\n** Invalid ID '%s' given. Not present.\n"
#define NO_KEY          "\n** Invalid authentication key. Starting over again.\n"

/* Remove agent */
#define REMOVE_ID       "Provide the ID of the agent you want to remove: "
#define REMOVE_CONFIRM  "Confirm deleting it?(y/n): "
#define REMOVE_DONE     "Agent '%s' removed.\n"
#define REMOVE_NOT      "Not removing ..\n"

/* Import agent */    
#define IMPORT_KEY      "\n* Provide the Key generated from the server.\n" \
                        "* The best approach is to cut and paste it.\n" \
                        "*** OBS: Do not include spaces or new lines.\n\n" \
                        "Paste it here: "
    
/* extract key */    
#define EXTRACT_KEY     "Provide the ID of the agent you want to extract " \
                        "the key: "
#define EXTRACT_MSG     "\nAgent key information for '%s' is: \n%s\n" \
                        "\n** Press ENTER to continue\n"
   
/* Commom errors */
#define ERROR_KEYS      "Unable to handle keys file. Exiting.\n"
#define EXTRACT_ERROR   "Unable to extract agent key.\n"
#define INPUT_LARGE     ARGV0": Input too large. Not adding it.\n"
#define EXIT            "\n" ARGV0 ": Exiting ..\n"

#define BANNER          "\n****************************************" \
                        "\n* %s %s Agent manager.       *" \
                        "\n* The following options are available: *" \
                        "\n****************************************\n"
    
#define BANNER_OPT      "   (A)dd an agent (A).\n" \
                        "   (E)xtract key for an agent (E).\n" \
                        "   (R)emove an agent (R).\n" \
                        "   (Q)uit.\n" \
                        "Choose your actions: A,E,R or Q: "

#define BANNER_CLIENT   "   (I)mport key for the server (I).\n" \
                        "   (Q)uit.\n" \
                        "Choose your actions: I or Q: "
                        
/* EOF */
