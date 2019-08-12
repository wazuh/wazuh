/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"


/**
 * @date 8 Aug 2019
 * @brief It inserts the Attack IDs and its json objetc into Attack table
 * @return It returns 0 if correct or -1 if error
 */
int wdb_mitre_attack_insert(wdb_t *wdb, char *id, char *json);

/**
 * @date 8 Aug 2019
 * @brief It inserts the Attack IDs and its attack phase(s) into has_phase table
 * @return It returns 0 if correct or -1 if error
 */
int wdb_mitre_phase_insert(wdb_t *wdb, char *id, char *phase);

/**
 * @date 8 Aug 2019
 * @brief It inserts the Attack IDs and its attack platform(s) into has_platform table
 * @return It returns 0 if correct or -1 if error
 */
int wdb_mitre_platform_insert(wdb_t *wdb, char *id, char *platform);

/**
 * @date 8 Aug 2019
 * @brief It updates the json object string of an attack ID in the Attack table
 * @return It returns 0 if correct or -1 if error
 */
int wdb_mitre_attack_update(wdb_t *wdb, char *id, char *json);

/**
 * @date 8 Aug 2019
 * @brief It gets a json object string from the Attack table
 * @return An object json string
 */
int wdb_mitre_attack_get(wdb_t *wdb, char *id, char *output);

/**
 * @date 8 Aug 2019
 * @brief It gets an array string of the phase(s) from the has_phase table
 * @return An string array of the phase(s)
 */
int wdb_mitre_phases_get(wdb_t *wdb, char *id, char *output);

/**
 * @date 8 Aug 2019
 * @brief It gets an array string of the platform(s) from the has_platform table
 * @return An string array of the platform(s)
 */
int wdb_mitre_platforms_get(wdb_t *wdb, char *id, char *output);

/**
 * @date 8 Aug 2019
 * @brief It deletes an Attack ID and its json object from Attack table
 * @return It returns 0 if correct or -1 if error
 */
int wdb_mitre_attack_delete(wdb_t *wdb, char *id);

/**
 * @date 8 Aug 2019
 * @brief It deletes an Attack ID and its attack phase(s) from has_phase table
 * @return It returns 0 if correct or -1 if error
 */
int wdb_mitre_phase_delete (wdb_t *wdb, char *id);

/**
 * @date 8 Aug 2019
 * @brief It deletes an Attack ID and its platform phase(s) from has_platform table
 * @return It returns 0 if correct or -1 if error
 */
int wdb_mitre_platform_delete(wdb_t *wdb, char *id);

/**
 * @date 8 Aug 2019
 * @brief It creates the 3 tables and filles them
 * @return Nothing
 */
void wdb_mitre_load();



