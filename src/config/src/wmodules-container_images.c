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

// Registry credentials. Only key names appear here: the values live in the agent
// credential store, so no credential is ever written into ossec.conf.
static const char *XML_CI_REGISTRY_AUTH = "registry_auth";
static const char *XML_CI_REGISTRY = "registry";
static const char *XML_CI_HOST = "host";
static const char *XML_CI_USER_KEY = "user_keystore_key";
static const char *XML_CI_PASSKEY_KEY = "passkey_keystore_key";

// Certificate bundle used to verify a registry. Detected at run time when unset,
// because the bundle compiled into the HTTP library is the path that existed on the
// machine that built the package, not necessarily one that exists on this host.
static const char *XML_CI_CA_BUNDLE = "ca_bundle";

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

// Append one registry credential entry to the module configuration.
static void add_registry(wm_container_images_t *container_images, const char *host, const char *user_key, const char *passkey_key) {
    os_realloc(container_images->registries, (container_images->registries_count + 1) * sizeof(wm_container_images_registry_t), container_images->registries);
    os_strdup(host, container_images->registries[container_images->registries_count].host);
    os_strdup(user_key ? user_key : "", container_images->registries[container_images->registries_count].user_key);
    os_strdup(passkey_key ? passkey_key : "", container_images->registries[container_images->registries_count].passkey_key);
    container_images->registries_count++;
}

// Parse one <registry> entry of the <registry_auth> block.
//
// Skipped rather than rejected on anything wrong, for the same reason a reference entry
// is: rejecting invalidates the whole module configuration, which stops wazuh-modulesd
// from starting, and the control script tests every daemon before starting any of them.
static void parse_registry(const OS_XML *xml, xml_node *registry_node, wm_container_images_t *container_images) {
    xml_node **children = OS_GetElementsbyNode(xml, registry_node);
    char *host = NULL;
    char *user_key = NULL;
    char *passkey_key = NULL;

    if (!children) {
        mwarn("Empty '%s' entry at module '%s', ignoring it.", XML_CI_REGISTRY, WM_CONTAINER_IMAGES_CONTEXT.name);
        return;
    }

    for (int i = 0; children[i]; i++) {
        if (!children[i]->element) {
            continue;
        }

        if (!strcmp(children[i]->element, XML_CI_HOST)) {
            host = children[i]->content;
        } else if (!strcmp(children[i]->element, XML_CI_USER_KEY)) {
            user_key = children[i]->content;
        } else if (!strcmp(children[i]->element, XML_CI_PASSKEY_KEY)) {
            passkey_key = children[i]->content;
        } else {
            mwarn("No such tag '%s' inside '%s' at module '%s', ignoring it.", children[i]->element, XML_CI_REGISTRY, WM_CONTAINER_IMAGES_CONTEXT.name);
        }
    }

    if (!host || !strlen(host)) {
        mwarn("A '%s' entry at module '%s' names no host, ignoring it.", XML_CI_REGISTRY, WM_CONTAINER_IMAGES_CONTEXT.name);
        OS_ClearNode(children);
        return;
    }

    // A registry with no key names is the same as no entry at all: the reference would be
    // attempted anonymously either way, so it is reported rather than stored.
    if ((!user_key || !strlen(user_key)) && (!passkey_key || !strlen(passkey_key))) {
        mwarn("The '%s' entry for '%s' at module '%s' names no keystore key, ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name);
        OS_ClearNode(children);
        return;
    }

    add_registry(container_images, host, user_key, passkey_key);
    OS_ClearNode(children);
}

// Parse the <registry_auth> block.
static void parse_registry_auth(const OS_XML *xml, xml_node *auth_node, wm_container_images_t *container_images) {
    xml_node **children = OS_GetElementsbyNode(xml, auth_node);

    if (!children) {
        return;
    }

    for (int i = 0; children[i]; i++) {
        if (!children[i]->element) {
            continue;
        }

        if (strcmp(children[i]->element, XML_CI_REGISTRY)) {
            mwarn("No such tag '%s' inside '%s' at module '%s', ignoring it.", children[i]->element, XML_CI_REGISTRY_AUTH, WM_CONTAINER_IMAGES_CONTEXT.name);
            continue;
        }

        parse_registry(xml, children[i], container_images);
    }

    OS_ClearNode(children);
}

// Parse the <references> block. Every entry type of the grammar is accepted here, and
// the module reports the ones it cannot read yet: keeping them out of the parser would
// mean changing the configuration grammar again when they are implemented.
//
// An entry that cannot be used costs that entry only: an unrecognised type and an empty
// value are both reported and skipped, so the remaining references are still configured
// and the module still starts.
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

        // Skipped rather than rejected, like an unrecognised entry type above. Rejecting
        // made the whole module configuration invalid, which stops wazuh-modulesd from
        // starting, and the control script tests every daemon before starting any of them,
        // so one empty entry left the agent with no daemon running at all.
        if (!children[j]->content || !strlen(children[j]->content)) {
            mwarn("Empty '%s' reference at module '%s', ignoring it.", children[j]->element, WM_CONTAINER_IMAGES_CONTEXT.name);
            continue;
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
        container_images->registries = NULL;
        container_images->registries_count = 0;
        container_images->ca_bundle = NULL;

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
        } else if (!strcmp(nodes[i]->element, XML_CI_REGISTRY_AUTH)) {
            parse_registry_auth(xml, nodes[i], container_images);
        } else if (!strcmp(nodes[i]->element, XML_CI_CA_BUNDLE)) {
            if (!nodes[i]->content || !strlen(nodes[i]->content)) {
                mwarn("Empty '%s' at module '%s', ignoring it.", XML_CI_CA_BUNDLE, WM_CONTAINER_IMAGES_CONTEXT.name);
            } else {
                os_free(container_images->ca_bundle);
                os_strdup(nodes[i]->content, container_images->ca_bundle);
            }
        } else {
            mwarn("No such tag '%s' at module '%s'.", nodes[i]->element, WM_CONTAINER_IMAGES_CONTEXT.name);
        }
    }

    return 0;
}
