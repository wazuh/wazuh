/*
 * Wazuh Container Images Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "wm_container_images.h"

static const char *XML_ENABLED       = "enabled";
static const char *XML_INTERVAL      = "interval";
static const char *XML_SCAN_ON_START = "scan_on_start";
static const char *XML_PACKAGES      = "packages";

static int parse_yes_no(const xml_node *xn, unsigned int *out)
{
    if (!xn->content || !*xn->content) {
        merror("Invalid content for tag '%s' at module '%s'.",
               xn->element, WM_CONTAINER_IMAGES_CONTEXT.name);
        return OS_INVALID;
    }
    if (!strcmp(xn->content, "yes")) {
        *out = 1;
    } else if (!strcmp(xn->content, "no")) {
        *out = 0;
    } else {
        merror("Invalid content for tag '%s' at module '%s'.",
               xn->element, WM_CONTAINER_IMAGES_CONTEXT.name);
        return OS_INVALID;
    }
    return 0;
}

int wm_container_images_read(__attribute__((unused)) const OS_XML *xml,
                             XML_NODE node, wmodule *module)
{
    wm_container_images_t *cfg;

    if (!module->data) {
        os_calloc(1, sizeof(wm_container_images_t), cfg);

        // Defaults: disabled, hourly, scan_on_start enabled, packages enabled
        cfg->flags.enabled       = 0;
        cfg->flags.scan_on_start = 1;
        cfg->flags.packages      = 1;
        cfg->interval            = WM_CONTAINER_IMAGES_DEFAULT_INTERVAL;

        module->context = &WM_CONTAINER_IMAGES_CONTEXT;
        module->tag     = strdup(module->context->name);
        module->data    = cfg;
    }

    cfg = module->data;

    if (!node) {
        return 0;
    }

    for (int i = 0; node[i]; ++i) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }

        if (!strcmp(node[i]->element, XML_ENABLED)) {
            unsigned int v;
            if (parse_yes_no(node[i], &v) < 0) return OS_INVALID;
            cfg->flags.enabled = v;
        } else if (!strcmp(node[i]->element, XML_SCAN_ON_START)) {
            unsigned int v;
            if (parse_yes_no(node[i], &v) < 0) return OS_INVALID;
            cfg->flags.scan_on_start = v;
        } else if (!strcmp(node[i]->element, XML_PACKAGES)) {
            unsigned int v;
            if (parse_yes_no(node[i], &v) < 0) return OS_INVALID;
            cfg->flags.packages = v;
        } else if (!strcmp(node[i]->element, XML_INTERVAL)) {
            if (!node[i]->content || !*node[i]->content) {
                merror("Invalid interval at module '%s'", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }
            char *endptr;
            unsigned long v = strtoul(node[i]->content, &endptr, 0);
            if (v == 0 || v == ULONG_MAX) {
                merror("Invalid interval at module '%s'", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }
            switch (*endptr) {
                case 'd': v *= W_DAY_SECONDS;    break;
                case 'h': v *= W_HOUR_SECONDS;   break;
                case 'm': v *= W_MINUTE_SECONDS; break;
                case 's':
                case '\0':                       break;
                default:
                    merror("Invalid interval at module '%s'", WM_CONTAINER_IMAGES_CONTEXT.name);
                    return OS_INVALID;
            }
            if (*endptr && endptr[1] != '\0') {
                merror("Invalid interval at module '%s'", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }
            if (v > UINT_MAX) {
                merror("Invalid interval at module '%s'", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }
            cfg->interval = (unsigned int)v;
        } else {
            merror("No such tag '%s' at module '%s'.",
                   node[i]->element, WM_CONTAINER_IMAGES_CONTEXT.name);
            return OS_INVALID;
        }
    }

    return 0;
}
