/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "wm_container_images.h"

#include <limits.h>

static const char *XML_ENABLED = "enabled";
static const char *XML_SCAN_ON_START = "scan_on_start";
static const char *XML_INTERVAL = "interval";
static const char *XML_CI_REFERENCES = "references";
static const char *XML_CI_LOCAL = "local";

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

static int parse_bool(const char *element, const char *content, unsigned int *target) {
    if (!content || !strlen(content) || (strcmp(content, "yes") && strcmp(content, "no"))) {
        merror("Invalid content for tag '%s' at module '%s'.", element, WM_CONTAINER_IMAGES_CONTEXT.name);
        return OS_INVALID;
    }

    *target = !strcmp(content, "yes");
    return 0;
}

// Append a local source path to the module configuration.
static void add_local_path(wm_container_images_t *container_images, const char *path) {
    os_realloc(container_images->local_paths, (container_images->local_paths_count + 1) * sizeof(char *), container_images->local_paths);
    container_images->local_paths[container_images->local_paths_count] = strdup(path);
    container_images->local_paths_count++;
}

// Parse the <references> block: each <local> element holds a local image path.
// Other reference types (remote registries, engine-backed local, ...) are not
// supported yet and are reported and skipped.
static int parse_references(const OS_XML *xml, xml_node *references_node, wm_container_images_t *container_images) {
    xml_node **children = OS_GetElementsbyNode(xml, references_node);
    int retval = 0;

    if (!children) {
        return 0;
    }

    for (int j = 0; children[j]; j++) {
        if (!children[j]->element) {
            merror(XML_ELEMNULL);
            retval = OS_INVALID;
            break;
        } else if (!strcmp(children[j]->element, XML_CI_LOCAL)) {
            if (!children[j]->content || !strlen(children[j]->content)) {
                merror("Empty '%s' reference at module '%s'.", XML_CI_LOCAL, WM_CONTAINER_IMAGES_CONTEXT.name);
                retval = OS_INVALID;
                break;
            }

            add_local_path(container_images, children[j]->content);
        } else {
            mwarn("Reference type '%s' is not supported yet at module '%s', ignoring it.", children[j]->element, WM_CONTAINER_IMAGES_CONTEXT.name);
        }
    }

    OS_ClearNode(children);
    return retval;
}

int wm_container_images_read(const OS_XML *xml, xml_node **nodes, wmodule *module) {
    wm_container_images_t *container_images;
    int i;

    if (!module->data) {
        os_calloc(1, sizeof(wm_container_images_t), container_images);
        container_images->enabled = 1;
        container_images->scan_on_start = 1;
        container_images->interval = WM_CONTAINER_IMAGES_DEFAULT_INTERVAL;
        container_images->local_paths = NULL;
        container_images->local_paths_count = 0;

        module->context = &WM_CONTAINER_IMAGES_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = container_images;
    }

    container_images = module->data;

    if (!nodes) {
        return 0;
    }

    for (i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            unsigned int value = 0;

            if (parse_bool(XML_ENABLED, nodes[i]->content, &value) < 0) {
                return OS_INVALID;
            }

            container_images->enabled = value;
        } else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START)) {
            unsigned int value = 0;

            if (parse_bool(XML_SCAN_ON_START, nodes[i]->content, &value) < 0) {
                return OS_INVALID;
            }

            container_images->scan_on_start = value;
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;

            if (!nodes[i]->content || !strlen(nodes[i]->content)) {
                merror("Invalid interval at module '%s'.", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }

            container_images->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (container_images->interval == 0 || container_images->interval == UINT_MAX) {
                merror("Invalid interval at module '%s'.", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                container_images->interval *= W_DAY_SECONDS;
                break;
            case 'h':
                container_images->interval *= W_HOUR_SECONDS;
                break;
            case 'm':
                container_images->interval *= W_MINUTE_SECONDS;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'.", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CI_REFERENCES)) {
            if (parse_references(xml, nodes[i], container_images) < 0) {
                return OS_INVALID;
            }
        } else {
            mwarn("No such tag '%s' at module '%s'.", nodes[i]->element, WM_CONTAINER_IMAGES_CONTEXT.name);
        }
    }

    return 0;
}
