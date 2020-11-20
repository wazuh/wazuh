/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "getlog.h"

char * getlog_singleline(getlog_params_t * params) { 
    return fgets(params->buffer, params->length, params->stream);
}

char * getlog_multiline(getlog_params_t * params) {
    // Handle multiline
    w_multiline_config_t * ml_cfg = (w_multiline_config_t *) params->ctxt;
    return NULL;
}
