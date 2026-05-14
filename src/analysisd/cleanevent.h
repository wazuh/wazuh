/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#ifndef CLEANEVENT_H
#define CLEANEVENT_H

#include "eventinfo.h"

int OS_CleanMSG(char *msg, Eventinfo *lf);

/**
 * @brief Function to extract the module name from message
 *
 * @param msg message received
 * @return returns the name of the module from which the message is coming from
 */
char *extract_module_from_message(char *msg);

/**
 * @brief Function to extract the module name from eventinfo location field
 *
 * @param location location field from eventinfo structure
 * @return returns the name of the module from which the event is coming from
 */
const char *extract_module_from_location(const char *location);

#endif /* CLEANEVENT_H */
