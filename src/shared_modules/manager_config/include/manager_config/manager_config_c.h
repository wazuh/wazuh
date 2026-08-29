/*
 * Wazuh manager configuration loader — C interface for the C daemons.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#ifndef MANAGER_CONFIG_C_H
#define MANAGER_CONFIG_C_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct mconf mconf_t;

    /**
     * Load, validate (schema + semantics) and fill defaults. `home` (may be NULL) resolves relative
     * certificate paths. Returns 0 and *out on success; -1 and a message in err otherwise.
     */
    int mconf_load(const char* path, const char* home, mconf_t** out, char* err, size_t errlen);

    /**
     * Same as mconf_load with an explicit file-existence policy: check_files == 0 skips the check of the
     * certificate/key files named in the document (daemon start-up: the files are validated by `-t` and by
     * `wazuh-manager-conf validate`, not by the loader — P44).
     */
    int mconf_load_ex(const char* path, const char* home, int check_files, mconf_t** out, char* err, size_t errlen);

    /** Same as mconf_load without keeping the document (bin/<daemon> -t). 0 = valid. */
    int mconf_validate(const char* path, const char* home, char* err, size_t errlen);

    /** JSON of one section of the effective document (cJSON_Parse-able). NULL if unknown. free() it. */
    char* mconf_section_json(const mconf_t* conf, const char* section);

    /** JSON of the whole effective document. free() it. */
    char* mconf_document_json(const mconf_t* conf);

    void mconf_free(mconf_t* conf);

#ifdef __cplusplus
}
#endif

#endif /* MANAGER_CONFIG_C_H */
