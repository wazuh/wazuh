/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MONITORD_H
#define MONITORD_H

#include "hash_op.h"
#ifndef ARGV0
#define ARGV0 "wazuh-monitord"
#endif

#include "config/reports-config.h"
#include "config/global-config.h"

#define MAX_DAY_WAIT 600
#define MONITORD_MSG_HEADER "1:" ARGV0 ":"
#define AG_DISCON_MSG MONITORD_MSG_HEADER OS_AG_DISCON
#define CHECK_LOGS_SIZE TRUE

/* Prototypes */
void Monitord(void) __attribute__((noreturn));
void manage_files(int cday, int cmon, int cyear);
void generate_reports(int cday, int cmon, int cyear, const struct tm *p);
char *w_rotate_log(char *old_file, int compress, int maxage, int new_day, int rotate_json,
                   int last_counter, rotation_list *list_log, rotation_list *list_json);
int delete_old_agent(const char *agent_id);
time_t calc_next_rotation(time_t tm, const char units, int interval);

/* Time control prototypes */

/**
 * @brief Set the the current time and initialize the counters
 *
 * This function sets: all the counters in the mond_time_control to 0,
 * sets the current_time structure and saves the initial day, month and year
 *
 */
void monitor_init_time_control();

/**
 * @brief Updates the counters and updates the time. Should be called every second
 *
 * The current_time structure is updated and the counters are incremented.
 *
 */
void monitor_step_time();

/**
 * @brief Updates the day, month and year of the current_time structure
 *
 * This function should called every time the day changes.
 *
 */
void monitor_update_date();

/* Triggers prototypes */
/**
 * @brief Checks if the agents_disconnection_time has passed and resets the corresponding counter
 *
 * @retval 0 Success: The condition has not been met.
 * @retval 1 Success: The counter is greater or equal than the configurated time.
 */
int check_disconnection_trigger();

/**
 * @brief Checks if the agents_disconnection_alert_time has passed and resets the corresponding counter
 *
 * @retval 0 Success: The condition has not been met.
 * @retval 1 Success: The counter is greater or equal than the configurated time.
 */
int check_alert_trigger();

/**
 * @brief Checks if the delete_old_agents time has passed and resets the corresponding counter
 *
 * This parameter is saved in minutes.
 *
 * @retval 0 Success: The condition has not been met.
 * @retval 1 Success: The counter is greater or equal than the configurated time.
 */
int check_deletion_trigger();

/**
 * @brief Checks if the day has changed
 *
 * @retval 0 Success: The condition has not been met.
 * @retval 1 Success: The variable today and current_time.tm_mday are different.
 */
int check_logs_time_trigger();

/* Messages prototypes */
/**
 * @brief Tries to connect to the messages queue, prints an error on failure
 *
 */
void monitor_queue_connect();

/**
 * @brief Sends the OS_AG_REMOVED message, prints and error on failure
 *
 */
void monitor_send_deletion_msg(char *agent);

/**
 * @brief Sends the AG_DISCON_MSG message and calls mon_send_agent_msg()
 *
 * It also sends the OS_AG_REMOVED message if the agent wasn't found
 *
 */
void monitor_send_disconnection_msg(char *agent);

/* Actions prototypes */
/**
 * @brief Calls monitor_agents_disconnection() and saves the disconnected agents in the hash table
 *
 */
void monitor_agents_disconnection();

/**
 * @brief Iterates through the hash table, and generates the disconnection alert in case of a keepalive
 * older than the disconnection time plus the alert disconnection time.
 *
 */
void monitor_agents_alert();

/**
 * @brief Iterates through all the disconnected agents, and removes them in case of a keepalive
 * older than the disconnection time plus the delete old agent time.
 *
 */
void monitor_agents_deletion();

/* Parse read config into JSON format */
cJSON *getMonitorOptions(void);
cJSON *getMonitorGlobalOptions(void);
cJSON *getReportsOptions(void);
cJSON *getMonitorLogging(void);
size_t moncom_dispatch(char * command, char ** output);
size_t moncom_getconfig(const char * section, char ** output);
void * moncom_main(__attribute__((unused)) void * arg);

typedef struct _monitor_time_control {
    long disconnect_counter;
    long alert_counter;
    long delete_counter;
    struct tm current_time;
    int today;
    int thismonth;
    int thisyear;
} monitor_time_control;

/* Global variables */
extern monitor_config mond;
extern bool worker_node;
extern OSHash* agents_to_alert_hash;


#endif /* MONITORD_H */
