/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 30, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #include "wazuh_modules/wmodules.h"
 #include "config.h"

int Read_WDownload(XML_NODE node, void *d1)
{
    int i = 0;

    wm_download_t *wm_download;
    wm_download = (wm_download_t *) d1;

    /* XML Definitions */
    const char *enabled = "enabled";

    if (!wm_download) {
        return (0);
    }

    if (!node)
        return 0;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, enabled) == 0) {
            SetConf(node[i]->content, (int *) &wm_download->enabled, options.wazuh_download.enabled, enabled);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        i++;
    }

    return (0);
}