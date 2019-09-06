/**
 * @file dbsync.c
 * @author Vikman Fernandez-Castro (victor@wazuh.com)
 * @brief Database synchronization decoder
 * @version 0.1
 * @date 2019-09-03
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../eventinfo.h"

void DispatchDBSync(Eventinfo * lf, int * sock) {
    cJSON * root = cJSON_Parse(lf->log);

    if (root == NULL) {
        merror(" -- Cannot parse JSON: %s", lf->log);
        return;
    }

    minfo(" -- [%s] %s", lf->location, lf->log);
    cJSON_Delete(root);
}
