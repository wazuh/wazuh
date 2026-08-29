/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Hook through which libwazuh reads sections of the manager configuration (etc/wazuh-manager.yml)
 * without depending on libconfig/manager_config: libconfig registers a provider at load time
 * (src/config/src/mconf-config.c) and the readers that live in libwazuh -- the cluster getters
 * (cluster_utils.c) and the logging format (debug_op.c) -- ask for their section through it.
 * Without a provider (libwazuhshared.so as loaded by the engine, the agent, unit tests) every
 * lookup returns NULL and the callers keep their "no configuration" behaviour. Manager only.
 */

#ifndef MCONF_HOOK_H
#define MCONF_HOOK_H

#ifndef CLIENT

struct cJSON;

/** @brief Returns one section of the effective document as cJSON (caller frees) or NULL. */
typedef struct cJSON *(*w_mconf_section_fn)(const char *section);

/** @brief Register (or clear, with NULL) the section provider. */
void w_mconf_hook_set(w_mconf_section_fn fn);

/** @brief The section through the registered provider; NULL without provider, section or document. */
struct cJSON *w_mconf_hook_section(const char *section);

#endif /* CLIENT */

#endif /* MCONF_HOOK_H */
