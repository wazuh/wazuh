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

#include <errno.h>
#include <limits.h>

static const char *XML_ENABLED = "enabled";
static const char *XML_SCAN_ON_START = "scan_on_start";
static const char *XML_INTERVAL = "interval";
static const char *XML_CI_REFERENCES = "references";

// The three reference entry types of the module. The grammar is fixed here once, so a
// source that is implemented later adds behaviour without changing the configuration.
static const char *XML_CI_REF = "ref";           // Remote registry reference.
static const char *XML_CI_ARCHIVE = "archive";   // Saved image archive or OCI image layout on disk.
static const char *XML_CI_LOCAL = "local";       // Image in the local container engine store.

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

// Append one configured reference to the module configuration.
static void add_reference(wm_container_images_t *container_images, const char *type, const char *value) {
    os_realloc(container_images->references, (container_images->references_count + 1) * sizeof(wm_container_images_reference_t), container_images->references);
    os_strdup(type, container_images->references[container_images->references_count].type);
    os_strdup(value, container_images->references[container_images->references_count].value);
    container_images->references_count++;
}

// Parse the <references> block. Every entry type of the grammar is accepted here, and
// the module reports the ones it cannot read yet: keeping them out of the parser would
// mean changing the configuration grammar again when they are implemented.
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
        }

        if (strcmp(children[j]->element, XML_CI_REF) && strcmp(children[j]->element, XML_CI_ARCHIVE) &&
            strcmp(children[j]->element, XML_CI_LOCAL)) {
            mwarn("No such reference type '%s' at module '%s', ignoring it.", children[j]->element, WM_CONTAINER_IMAGES_CONTEXT.name);
            continue;
        }

        if (!children[j]->content || !strlen(children[j]->content)) {
            merror("Empty '%s' reference at module '%s'.", children[j]->element, WM_CONTAINER_IMAGES_CONTEXT.name);
            retval = OS_INVALID;
            break;
        }

        add_reference(container_images, children[j]->element, children[j]->content);
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
        container_images->references = NULL;
        container_images->references_count = 0;

        module->context = &WM_CONTAINER_IMAGES_CONTEXT;
        os_strdup(module->context->name, module->tag);
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
            unsigned long interval;
            unsigned long multiplier;

            if (!nodes[i]->content || !strlen(nodes[i]->content)) {
                merror("Invalid interval at module '%s'.", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }

            errno = 0;
            interval = strtoul(nodes[i]->content, &endptr, 0);

            // strtoul returns an unsigned long: a value that does not fit the unsigned int
            // field would be truncated into a small interval and the module would scan in
            // a tight loop, so it is rejected rather than wrapped.
            if (errno || interval == 0 || interval >= UINT_MAX) {
                merror("Invalid interval at module '%s'.", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                multiplier = W_DAY_SECONDS;
                break;
            case 'h':
                multiplier = W_HOUR_SECONDS;
                break;
            case 'm':
                multiplier = W_MINUTE_SECONDS;
                break;
            case 's':
            case '\0':
                multiplier = 1;
                break;
            default:
                merror("Invalid interval at module '%s'.", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }

            if (interval > (unsigned long)UINT_MAX / multiplier) {
                merror("Invalid interval at module '%s'.", WM_CONTAINER_IMAGES_CONTEXT.name);
                return OS_INVALID;
            }

            container_images->interval = (unsigned int)(interval * multiplier);
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
