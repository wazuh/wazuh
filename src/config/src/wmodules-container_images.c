/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "wm_container_images.h"

#include <ctype.h>
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

// Amazon ECR credentials: the key names of the AWS access key id and secret access key, and
// the region they belong to. Key names only, like the tags above.
static const char *XML_CI_ACCESS_KEY_ID_KEY = "access_key_id_keystore_key";
static const char *XML_CI_SECRET_ACCESS_KEY_KEY = "secret_access_key_keystore_key";
static const char *XML_CI_REGION = "region";

// Certificate bundle used to verify a registry. Detected at run time when unset,
// because the bundle compiled into the HTTP library is the path that existed on the
// machine that built the package, not necessarily one that exists on this host.
static const char *XML_CI_CA_BUNDLE = "ca_bundle";

// Engine blocks of runtime security that <local> binds to. Read here only for the socket of the Docker
// engine: the runtime parser validates them. Both shapes are recognised, the one runtime security parses today
// (<container_instances> with <type>docker</type>) and the <docker> tag its configuration proposal moves to.
#ifdef __linux__
static const char *XML_CI_CONTAINER_INSTANCES = "container_instances";
static const char *XML_CI_TYPE = "type";
static const char *XML_CI_DOCKER = "docker";
static const char *XML_CI_KUBERNETES = "kubernetes";
static const char *XML_CI_SOCKET_PATH = "socket_path";

// Socket runtime security uses for Docker when its block names none, so both read the same one.
static const char *DOCKER_DEFAULT_SOCKET = "/var/run/docker.sock";
#endif

// Children of <container_security> that belong to runtime security, which only Linux agents run.
static const char *RUNTIME_SECURITY_TAGS[] = {"container_instances", "syscheck", "syscollector", "docker", "kubernetes", NULL};

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
static void add_registry(wm_container_images_t *container_images, const char *host, const char *user_key, const char *passkey_key, const char *region, unsigned int aws) {
    os_realloc(container_images->registries, (container_images->registries_count + 1) * sizeof(wm_container_images_registry_t), container_images->registries);
    os_strdup(host, container_images->registries[container_images->registries_count].host);
    os_strdup(user_key ? user_key : "", container_images->registries[container_images->registries_count].user_key);
    os_strdup(passkey_key ? passkey_key : "", container_images->registries[container_images->registries_count].passkey_key);
    os_strdup(region ? region : "", container_images->registries[container_images->registries_count].region);
    container_images->registries[container_images->registries_count].aws = aws;
    container_images->registries_count++;
}

// True when the host ends with the given suffix.
static bool host_ends_with(const char *host, const char *suffix) {
    size_t host_length = strlen(host);
    size_t suffix_length = strlen(suffix);

    return host_length > suffix_length && !strcmp(host + host_length - suffix_length, suffix);
}

// True when the host is under an Amazon domain, which is where a private ECR registry lives.
static bool is_amazon_host(const char *host) {
    return host_ends_with(host, ".amazonaws.com") || host_ends_with(host, ".amazonaws.com.cn");
}

// True when the region has the shape of an AWS region name, such as "eu-west-1": a two letter
// geography, one or more lower-case words and a one or two digit number. This is the same rule
// the module applies before it signs anything (isValidAwsRegion), so an entry that passes here
// cannot fail there.
static bool is_valid_aws_region(const char *region) {
    size_t length = strlen(region);
    size_t labels = 0;
    size_t label_length = 0;
    bool all_digits = true;
    bool all_letters = true;

    if (length < 5 || length > 32) {
        return false;
    }

    for (size_t i = 0; i <= length; i++) {
        char character = region[i];

        if (character == '-' || character == '\0') {
            if (label_length == 0) {
                return false;
            }

            if (character == '\0') {
                // The last label is the number.
                return labels >= 2 && all_digits && label_length <= 2;
            }

            // Every label before the number is letters only, the first of them two of them.
            if (!all_letters || (labels == 0 && label_length != 2)) {
                return false;
            }

            labels++;
            label_length = 0;
            all_digits = true;
            all_letters = true;
            continue;
        }

        if (character >= 'a' && character <= 'z') {
            all_digits = false;
        } else if (character >= '0' && character <= '9') {
            all_letters = false;
        } else {
            return false;
        }

        label_length++;
    }

    return false;
}

// True when the host has the shape of a private Amazon ECR registry, the only one the module
// reads: "<12 digits>.dkr.ecr.<region>.amazonaws.com", or ".amazonaws.com.cn" in China. The same
// rule as the C++ profile (profileForHost), so an entry that passes here can match a reference
// there. Any other Amazon host, an S3 or a FIPS one for instance, is not an ECR registry.
static bool is_ecr_private_host(const char *host) {
    const char *infix = ".dkr.ecr.";
    size_t host_length = strlen(host);
    char region[40];

    if (host_length < 12 + strlen(infix) || strncmp(host + 12, infix, strlen(infix)) != 0) {
        return false;
    }

    for (int i = 0; i < 12; i++) {
        if (host[i] < '0' || host[i] > '9') {
            return false;
        }
    }

    const char *tail = host + 12 + strlen(infix);
    const char *suffixes[] = {".amazonaws.com.cn", ".amazonaws.com"};

    for (size_t k = 0; k < sizeof(suffixes) / sizeof(suffixes[0]); k++) {
        size_t tail_length = strlen(tail);
        size_t suffix_length = strlen(suffixes[k]);

        if (tail_length > suffix_length && !strcmp(tail + tail_length - suffix_length, suffixes[k])) {
            size_t region_length = tail_length - suffix_length;

            if (region_length >= sizeof(region)) {
                return false;
            }

            memcpy(region, tail, region_length);
            region[region_length] = '\0';

            return is_valid_aws_region(region);
        }
    }

    return false;
}

// True, with a warning, when an entry for the host is already configured. The first entry for a
// host is the one the module uses, so a later one would be dropped silently, unlike every other
// repeated element, where the last wins. The rule is the same for the user and token pair and
// for the AWS key pair.
static bool registry_host_is_configured(const wm_container_images_t *container_images, const char *host) {
    for (int i = 0; i < container_images->registries_count; i++) {
        if (!strcmp(container_images->registries[i].host, host)) {
            mwarn("The '%s' entry for '%s' at module '%s' repeats a host already configured, ignoring it. The first entry is used.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name);
            return true;
        }
    }

    return false;
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
    char *access_key_id_key = NULL;
    char *secret_access_key_key = NULL;
    char *region = NULL;
    bool aws_tags = false;
    bool basic_tags = false;

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
            basic_tags = true;
        } else if (!strcmp(children[i]->element, XML_CI_PASSKEY_KEY)) {
            passkey_key = children[i]->content;
            basic_tags = true;
        } else if (!strcmp(children[i]->element, XML_CI_ACCESS_KEY_ID_KEY)) {
            access_key_id_key = children[i]->content;
            aws_tags = true;
        } else if (!strcmp(children[i]->element, XML_CI_SECRET_ACCESS_KEY_KEY)) {
            secret_access_key_key = children[i]->content;
            aws_tags = true;
        } else if (!strcmp(children[i]->element, XML_CI_REGION)) {
            region = children[i]->content;
        } else {
            mwarn("No such tag '%s' inside '%s' at module '%s', ignoring it.", children[i]->element, XML_CI_REGISTRY, WM_CONTAINER_IMAGES_CONTEXT.name);
        }
    }

    if (!host || !strlen(host)) {
        mwarn("A '%s' entry at module '%s' names no host, ignoring it.", XML_CI_REGISTRY, WM_CONTAINER_IMAGES_CONTEXT.name);
        OS_ClearNode(children);
        return;
    }

    // The host is compared with the registry each reference names, so a value that cannot
    // be a host (a URL, a path, spaces) would be accepted here and never match anything.
    // A scheme always carries a '/', so one test covers it and a path.
    bool bare_host = !strchr(host, '/');

    for (const char *c = host; bare_host && *c; c++) {
        bare_host = !isspace((unsigned char) *c);
    }

    if (!bare_host) {
        mwarn("The '%s' entry for '%s' at module '%s' must name a bare host such as 'ghcr.io', without a scheme, a path or whitespace, ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name);
        OS_ClearNode(children);
        return;
    }

    // Host names are not case sensitive, and the module compares them in lower case. Done
    // before any check below that looks at the host, the Amazon one included, so that
    // "123456789012.DKR.ECR.US-EAST-1.AMAZONAWS.COM" is the host the module will compare.
    for (char *c = host; *c; c++) {
        *c = (char) tolower((unsigned char) *c);
    }

    // Amazon ECR Public takes no credential, so no entry for it is ever used, whatever it holds.
    // Reported here, where the operator is editing it, before any check that would ask for more.
    if (!strcmp(host, "public.ecr.aws")) {
        mwarn("The '%s' entry for '%s' at module '%s' is not needed: Amazon ECR Public takes no credential, ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name);
        OS_ClearNode(children);
        return;
    }

    // A region belongs to an Amazon host. Anywhere else it is a tag that means nothing, and the
    // entry is kept as it was before the tag existed, rather than skipped for carrying it.
    if (region && !aws_tags && !is_amazon_host(host)) {
        mwarn("The '%s' tag inside '%s' for '%s' at module '%s' applies only to an Amazon ECR registry, ignoring it.", XML_CI_REGION, XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name);
        region = NULL;
    } else if (region) {
        aws_tags = true;
    }

    if (aws_tags) {
        // An Amazon ECR entry. Mixing the two families of tags would leave it unclear which
        // credential the key names stand for, so it is refused rather than guessed at.
        if (basic_tags) {
            mwarn("The '%s' entry for '%s' at module '%s' mixes '%s' and '%s' with the Amazon ECR tags, ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name, XML_CI_USER_KEY, XML_CI_PASSKEY_KEY);
            OS_ClearNode(children);
            return;
        }

        if (!is_ecr_private_host(host)) {
            mwarn("The '%s' entry for '%s' at module '%s' uses Amazon ECR tags, which apply only to a private ECR registry such as '<account>.dkr.ecr.<region>.amazonaws.com', ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name);
            OS_ClearNode(children);
            return;
        }

        // Both keys are needed to sign, so an entry with one can never work and is reported
        // here, where the operator is editing it, rather than at scan time.
        if (!access_key_id_key || !strlen(access_key_id_key) || !secret_access_key_key || !strlen(secret_access_key_key)) {
            mwarn("The '%s' entry for '%s' at module '%s' needs both '%s' and '%s', ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name, XML_CI_ACCESS_KEY_ID_KEY, XML_CI_SECRET_ACCESS_KEY_KEY);
            OS_ClearNode(children);
            return;
        }

        if (region && strlen(region) && !is_valid_aws_region(region)) {
            mwarn("The '%s' entry for '%s' at module '%s' has an invalid '%s', ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name, XML_CI_REGION);
            OS_ClearNode(children);
            return;
        }

        if (registry_host_is_configured(container_images, host)) {
            OS_ClearNode(children);
            return;
        }

        add_registry(container_images, host, access_key_id_key, secret_access_key_key, region, 1);
        OS_ClearNode(children);
        return;
    }

    // Tested before the user and passkey checks, so the first warning names what an Amazon
    // host needs rather than the user and passkey it must not use. Only a private ECR host can
    // take the AWS elements; any other Amazon host is not a registry the module reads.
    if (is_ecr_private_host(host)) {
        mwarn("The '%s' entry for '%s' at module '%s' needs '%s' and '%s' for an Amazon ECR registry, ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name, XML_CI_ACCESS_KEY_ID_KEY, XML_CI_SECRET_ACCESS_KEY_KEY);
        OS_ClearNode(children);
        return;
    }

    if (is_amazon_host(host)) {
        mwarn("The '%s' entry for '%s' at module '%s' names an Amazon host that is not a private ECR registry such as '<account>.dkr.ecr.<region>.amazonaws.com', ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name);
        OS_ClearNode(children);
        return;
    }

    // Both keys are needed to authenticate, so an entry with one can never work and is
    // reported here, where the operator is editing it, rather than at scan time as a
    // credential missing from the store.
    if (!user_key || !strlen(user_key)) {
        mwarn("The '%s' entry for '%s' at module '%s' names no '%s', ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name, XML_CI_USER_KEY);
        OS_ClearNode(children);
        return;
    }

    if (!passkey_key || !strlen(passkey_key)) {
        mwarn("The '%s' entry for '%s' at module '%s' names no '%s', ignoring it.", XML_CI_REGISTRY, host, WM_CONTAINER_IMAGES_CONTEXT.name, XML_CI_PASSKEY_KEY);
        OS_ClearNode(children);
        return;
    }

    if (registry_host_is_configured(container_images, host)) {
        OS_ClearNode(children);
        return;
    }

    add_registry(container_images, host, user_key, passkey_key, NULL, 0);
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

void wm_container_images_skip_security_tag(const char *element, bool runtime_supported) {
    if (runtime_supported) {
        return;
    }

    for (int i = 0; RUNTIME_SECURITY_TAGS[i]; i++) {
        if (!strcmp(element, RUNTIME_SECURITY_TAGS[i])) {
            mwarn("The '%s' tag inside 'container_security' is only supported on Linux agents, ignoring it.", element);
            return;
        }
    }

    mwarn("No such tag '%s' inside 'container_security', ignoring it.", element);
}

#ifdef __linux__
typedef enum {
    DOCKER_ENGINE_ABSENT,
    DOCKER_ENGINE_DISABLED,
    DOCKER_ENGINE_FOUND
} docker_engine_state_t;

// True when an <enabled> value switches its block off. Anything else is left to the runtime parser to judge.
static bool is_switched_off(const char *content) {
    return content && (!strcmp(content, "no") || !strcmp(content, "false"));
}

// Read one engine block. A <docker> block is the Docker engine; a <container_instances> block is only when its
// <type> says so, whatever order its options come in. The socket is set only for an enabled Docker block.
static docker_engine_state_t read_docker_block(const OS_XML *xml, xml_node *block, bool is_container_instances, char **socket_path) {
    xml_node **options = OS_GetElementsbyNode(xml, block);
    bool is_docker = !is_container_instances;
    bool enabled = true;
    char *block_socket = NULL;

    for (int i = 0; options && options[i]; i++) {
        if (!options[i]->element || !options[i]->content) {
            continue;
        }

        if (!strcmp(options[i]->element, XML_CI_TYPE)) {
            is_docker = !strcmp(options[i]->content, XML_CI_DOCKER);
        } else if (!strcmp(options[i]->element, XML_ENABLED)) {
            enabled = !is_switched_off(options[i]->content);
        } else if (!strcmp(options[i]->element, XML_CI_SOCKET_PATH) && strlen(options[i]->content)) {
            os_free(block_socket);
            os_strdup(options[i]->content, block_socket);
        }
    }

    OS_ClearNode(options);

    if (!is_docker) {
        os_free(block_socket);
        return DOCKER_ENGINE_ABSENT;
    }

    if (!enabled) {
        os_free(block_socket);
        return DOCKER_ENGINE_DISABLED;
    }

    *socket_path = block_socket;
    return DOCKER_ENGINE_FOUND;
}

// Find the Docker engine among the children of a <container_security> block. The whole block is searched, so the
// order of its children does not matter. An engine written without a socket gets the one runtime security uses.
// The caller frees the socket.
static docker_engine_state_t find_docker_engine(const OS_XML *xml, xml_node **security_children, char **socket_path) {
    docker_engine_state_t state = DOCKER_ENGINE_ABSENT;

    *socket_path = NULL;

    for (int i = 0; security_children[i] && state != DOCKER_ENGINE_FOUND; i++) {
        docker_engine_state_t block_state;

        if (!security_children[i]->element) {
            continue;
        }

        if (!strcmp(security_children[i]->element, XML_CI_CONTAINER_INSTANCES)) {
            block_state = read_docker_block(xml, security_children[i], true, socket_path);
        } else if (!strcmp(security_children[i]->element, XML_CI_DOCKER)) {
            block_state = read_docker_block(xml, security_children[i], false, socket_path);
        } else {
            continue;
        }

        if (block_state != DOCKER_ENGINE_ABSENT) {
            state = block_state;
        }
    }

    if (state == DOCKER_ENGINE_FOUND && !*socket_path) {
        os_strdup(DOCKER_DEFAULT_SOCKET, *socket_path);
    }

    return state;
}
#endif

void wm_container_images_bind_local(const OS_XML *xml, xml_node **security_children, wm_container_images_t *module, int first_reference) {
    int kept = first_reference;
#ifdef __linux__
    bool looked_up = false;
    docker_engine_state_t state = DOCKER_ENGINE_ABSENT;
    char *socket_path = NULL;
#else
    (void) xml;
    (void) security_children;
#endif

    for (int i = first_reference; i < module->references_count; i++) {
        wm_container_images_reference_t *reference = &module->references[i];
        bool bound = true;

        if (!strcmp(reference->type, XML_CI_LOCAL)) {
#ifdef __linux__
            if (!strcmp(reference->value, XML_CI_KUBERNETES)) {
                mwarn("The '%s' reference 'kubernetes' at module '%s' cannot be read: Kubernetes has no image export, so name the images with '<ref>'. Ignoring it.", XML_CI_LOCAL, WM_CONTAINER_IMAGES_CONTEXT.name);
                bound = false;
            } else if (strcmp(reference->value, XML_CI_DOCKER)) {
                mwarn("The '%s' reference '%s' at module '%s' names an engine that is not supported, only '%s' is. Ignoring it.", XML_CI_LOCAL, reference->value, WM_CONTAINER_IMAGES_CONTEXT.name, XML_CI_DOCKER);
                bound = false;
            } else if (module->docker_socket) {
                mwarn("The '%s' reference '%s' at module '%s' repeats one already configured, ignoring it. Its Docker socket, '%s', is used.", XML_CI_LOCAL, XML_CI_DOCKER, WM_CONTAINER_IMAGES_CONTEXT.name, module->docker_socket);
                bound = false;
            } else {
                if (!looked_up) {
                    state = find_docker_engine(xml, security_children, &socket_path);
                    looked_up = true;
                }

                if (state == DOCKER_ENGINE_FOUND) {
                    os_strdup(socket_path, module->docker_socket);
                } else {
                    mwarn("The '%s' reference '%s' at module '%s' needs the Docker engine of the same 'container_security' block, and %s. Ignoring it.", XML_CI_LOCAL, XML_CI_DOCKER, WM_CONTAINER_IMAGES_CONTEXT.name, state == DOCKER_ENGINE_DISABLED ? "it is disabled" : "none is configured");
                    bound = false;
                }
            }
#else
            mwarn("The '%s' reference '%s' at module '%s' needs a container engine, which is only supported on Linux agents, ignoring it.", XML_CI_LOCAL, reference->value, WM_CONTAINER_IMAGES_CONTEXT.name);
            bound = false;
#endif
        }

        if (bound) {
            module->references[kept++] = *reference;
        } else {
            os_free(reference->type);
            os_free(reference->value);
        }
    }

    module->references_count = kept;
#ifdef __linux__
    os_free(socket_path);
#endif
}
