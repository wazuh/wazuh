/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef __linux__
#include "syscheck_audit.h"

#define AUDIT_LOAD_RETRIES 5 // Max retries to reload Audit rules

#ifdef ENABLE_AUDIT

/**
 * @brief Add cwd and exe of parent process
 *
 * @param ppid ID of parent process
 * @param parent_name String where save the parent name (exe)
 * @param parent_cwd String where save the parent working directory (cwd)
 */
void get_parent_process_info(int ppid, char **const parent_name, char **const parent_cwd) {
    char path[PATH_MAX + 1] = { '\0' };
    char buffer[PATH_MAX + 1] = { '\0' };
    int read_bytes = 0;

    snprintf(path, PATH_MAX, "/proc/%d/exe", ppid);

    if (read_bytes = readlink(path, buffer, OS_FLSIZE), read_bytes < 0) {
        mdebug1("Failure to obtain the name of the process: '%d'. Error: %s", ppid, strerror(errno));
        os_strdup("", *parent_name);
    } else {
        buffer[read_bytes] = '\0';
        os_strdup(buffer, *parent_name);
    }

    snprintf(path, PATH_MAX, "/proc/%d/cwd", ppid);
    if (read_bytes = readlink(path, buffer, OS_FLSIZE), read_bytes < 0) {
        mdebug1("Failure to obtain the cwd of the process: '%d'. Error: %s", ppid, strerror(errno));
        os_strdup("", *parent_cwd);
    } else {
        buffer[read_bytes] = '\0';
        os_strdup(buffer, *parent_cwd);
    }
}

void whodata_callback(auparse_state_t *state, auparse_cb_event_t cb_event_type, __attribute__((unused)) void *_unused) {
    whodata_evt *w_evt;
    bool key_found = false;
    const char *key, *success;

    if (cb_event_type != AUPARSE_CB_EVENT_READY) {
        return;
    }

    if (auparse_normalize(state, NORM_OPT_ALL)) {
        return;
    }

    if (auparse_normalize_get_results(state) != 1) {
        return;
    }

    success = auparse_get_field_str(state);

    if (success == NULL || strcmp(success, "yes") != 0) {
        return;
    }

    if (auparse_normalize_key(state) != 1) {
        // Either an error or event with no key, nothing to do here.
        return;
    }

    key = auparse_interpret_field(state);

    if (key == NULL) {
        return;
    }

    if (strcmp(key, AUDIT_KEY) == 0) {
        key_found = true;;
    }

    for (int i = 0; key_found == false && syscheck.audit_key[i]; i++) {
        if (strcmp(key, syscheck.audit_key[i]) == 0) {
            key_found = true;
        }
    }

    if (key_found == false) {
        return;
    }

    // Gather as much information as possible for the event.
    os_calloc(1, sizeof(whodata_evt), w_evt);

    if (auparse_normalize_subject_primary(state) == 1) {
        const char *auid, *auid_name;

        auid = auparse_get_field_str(state);
        auid_name = auparse_interpret_field(state);

        if (auid != NULL) {
            os_strdup(auid, w_evt->audit_uid);
        }

        if (auid_name != NULL) {
            os_strdup(auid_name, w_evt->audit_name);
        }
    }

    if (auparse_normalize_subject_secondary(state) == 1) {
        const char *uid, *user_name;

        uid = auparse_get_field_str(state);
        user_name = auparse_interpret_field(state);

        if (uid) {
            os_strdup(uid, w_evt->user_id);
        }

        if (user_name) {
            os_strdup(user_name, w_evt->user_name);
        }
    }

    if (auparse_normalize_subject_first_attribute(state) == 1) {
        do {
            const char *field = NULL, *interpreted = NULL;
            char **dst_field = NULL, **dst_interpreted = NULL;
            const char *field_name = auparse_get_field_name(state);

            if (field_name == NULL) {
                continue;
            }

            if (strcmp(field_name, "ppid") == 0) {
                w_evt->ppid = auparse_get_field_int(state);

                get_parent_process_info(w_evt->ppid, &w_evt->parent_name, &w_evt->parent_cwd);

            } else if (strcmp(field_name, "pid") == 0) {
                w_evt->process_id = auparse_get_field_int(state);
            } else if (strcmp(field_name, "gid") == 0) {
                field = auparse_get_field_str(state);
                interpreted = auparse_interpret_field(state);

                dst_field = &(w_evt->group_id);
                dst_interpreted = &(w_evt->group_name);
            } else if (strcmp(field_name, "euid") == 0) {
                field = auparse_get_field_str(state);
                interpreted = auparse_interpret_field(state);

                dst_field = &(w_evt->effective_uid);
                dst_interpreted = &(w_evt->effective_name);
            }

            if (field != NULL && dst_field != NULL) {
                os_strdup(field, *dst_field);
            }

            if (interpreted != NULL && dst_interpreted != NULL) {
                os_strdup(interpreted, *dst_interpreted);
            }
        } while (auparse_normalize_subject_next_attribute(state) == 1);
    }

    if (auparse_find_field(state, "dev")) {
        const char *dev = auparse_get_field_str(state);

        if (dev != NULL) {
            char *separator;
            os_strdup(dev, w_evt->dev);

            separator = strchr(w_evt->dev, ':');

            if (separator != NULL) {
                *separator = '\0';
            }
        }
    }

    if (auparse_normalize_object_primary(state) == 1) {
        const char *path = auparse_interpret_field(state);

        if (path != NULL) {
            os_strdup(path, w_evt->path);
        }
    }

    if (auparse_normalize_object_secondary(state) == 1) {
        const char *inode = auparse_get_field_str(state);

        if (inode != NULL) {
            os_strdup(inode, w_evt->inode);
        }
    }

    if (auparse_normalize_object_primary2(state) == 1) {

    }

    if (auparse_normalize_object_first_attribute(state) == 1) {
        do {
            const char *field_name = auparse_get_field_name(state);
            if (strcmp(field_name, "cwd") == 0) {
                const char *cwd = auparse_interpret_field(state);

                if (cwd != NULL) {
                    os_strdup(cwd, w_evt->cwd);
                }
                break;
            }
        } while (auparse_normalize_object_next_attribute(state) == 1);
    }

    fim_whodata_event(w_evt);
    free_whodata_event(w_evt);
}

#endif // ENABLE_AUDIT
#endif // __linux__
