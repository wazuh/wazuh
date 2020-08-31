/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef CREATE_DB_WRAPPERS_H
#define CREATE_DB_WRAPPERS_H

#include "syscheckd/syscheck.h"

void __wrap_fim_checker(char *path,
                        fim_element *item,
                        whodata_evt *w_evt,
                        int report);

int __wrap_fim_configuration_directory(const char *path,
                                       const char *entry);

cJSON *__wrap_fim_entry_json(const char * path,
                             fim_entry_data * data);

cJSON *__wrap_fim_json_event();

void __wrap_fim_realtime_event(char *file);

int __wrap_fim_registry_event(char *key, fim_entry_data *data, int pos);

int __wrap_fim_whodata_event(whodata_evt * w_evt);

#endif
