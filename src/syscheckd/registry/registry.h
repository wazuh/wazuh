/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REGISTRY_H
#define REGISTRY_H

#include "../syscheck.h"


/**
 * @brief Main scheduled algorithm for registry scan
 */
void fim_registry_scan();

/**
 * @brief Check and trigger a FIM event on a registry.
 *
 * @param new New data aquired from the actual registry entry.
 * @param saved Registry information retrieved from the FIM DB.
 * @param configuration Configuration associated with the given registry.
 * @param mode FIM event mode which caused the event.
 * @param event_type Added, modifed or deleted event.
 * @param diff A string holding the difference between the original and new value of the registry.
 * @return 0 if no event was sent, 1 if event was sent, OS_INVALID on error.
 */
int fim_registry_event(const fim_entry *new,
                       const fim_entry *saved,
                       const registry *configuration,
                       fim_event_mode mode,
                       unsigned int event_type,
                       const char *diff);

#endif
