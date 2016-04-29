/*
 * Wazuh Module Configuration
 * Wazuh Inc.
 * April 27, 2016
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_NAME = "name";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_INTERVAL = "interval";
static const char *XML_FILE = "file";
static const char *XML_PROFILE = "profile";
static const char *XML_SKIP_RESULT = "skip-result";
static const char *XML_SKIP_SEVERITY = "skip-severity";

static int wm_oscap_parse_skip_result(const char *content, wm_oscap_flags *flags);
static int wm_oscap_parse_skip_severity(const char *content, wm_oscap_flags *flags);

// Parse XML

int wm_oscap_read(const OS_XML *xml, xml_node **nodes, wmodule *module)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_oscap *oscap;
    wm_oscap_file *cur_file = NULL;
    wm_oscap_profile *cur_profile;

    // Create module

    os_calloc(1, sizeof(wm_oscap), oscap);
    module->context = &WM_OSCAP_CONTEXT;
    module->data = oscap;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL, __local_name);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            oscap->timeout = strtoul(nodes[i]->content, NULL, 0);

            if (oscap->timeout == 0 || oscap->timeout == UINT_MAX) {
                merror("%s: ERROR: Invalid timeout at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

        } else if (!strcmp(nodes[i]->element, XML_FILE)) {

            // Create file node

            if (cur_file) {
                os_calloc(1, sizeof(wm_oscap_file), cur_file->next);
                cur_file = cur_file->next;
            } else {
                // First file
                os_calloc(1, sizeof(wm_oscap_file), cur_file);
                oscap->files = cur_file;
            }

            // Parse file attributes

            for (j = 0; nodes[i]->attributes[j]; j++) {
                if (!strcmp(nodes[i]->attributes[j], XML_NAME))
                    cur_file->name = strdup(nodes[i]->values[j]);
                else if (!strcmp(nodes[i]->attributes[j], XML_TIMEOUT)) {
                    cur_file->timeout = strtoul(nodes[i]->values[j], NULL, 0);

                    if (cur_file->timeout == 0 || cur_file->timeout == UINT_MAX) {
                        merror("%s: ERROR: Invalid timeout at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
                        return OS_INVALID;
                    }
                }
                else {
                    merror("%s: ERROR: Invalid attribute '%s' at module '%s'.", __local_name, nodes[i]->attributes[0], WM_OSCAP_CONTEXT.name);
                    return OS_INVALID;
                }
            }

            if (!cur_file->name) {
                merror("%s: ERROR: No such attribute '%s' at module '%s'.", __local_name, XML_NAME, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

            // Expand file children (optional)

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            cur_profile = NULL;

            for (j = 0; children[j]; j++) {
                if (!children[j]->element) {
                    merror(XML_ELEMNULL, __local_name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                if (!strcmp(children[j]->element, XML_PROFILE)) {
                    if (cur_profile) {
                        os_calloc(1, sizeof(wm_oscap_profile), cur_profile->next);
                        cur_profile = cur_profile->next;

                    } else {
                        // First profile
                        os_calloc(1, sizeof(wm_oscap_profile), cur_profile);
                        cur_file->profiles = cur_profile;
                    }

                    cur_profile->name = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_SKIP_RESULT)) {
                    cur_file->flags.custom_result_flags = 1;

                    if (wm_oscap_parse_skip_result(children[j]->content, &cur_file->flags) < 0) {
                        merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_RESULT, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_SKIP_SEVERITY)) {
                    cur_file->flags.custom_severity_flags = 1;

                    if (wm_oscap_parse_skip_severity(children[j]->content, &cur_file->flags) < 0) {
                        merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_SEVERITY, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else {
                    merror("%s: ERROR: No such tag '%s' at module '%s'.", __local_name, children[j]->element, WM_OSCAP_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            oscap->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (oscap->interval == 0 || oscap->interval == UINT_MAX) {
                merror("%s: ERROR: Invalid interval at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                oscap->interval *= 86400;
                break;
            case 'h':
                oscap->interval *= 3600;
                break;
            case 'm':
                oscap->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("%s: ERROR: Invalid interval at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

        } else if (!strcmp(nodes[i]->element, XML_SKIP_RESULT)) {
            if (wm_oscap_parse_skip_result(nodes[i]->content, &oscap->flags) < 0) {
                merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_RESULT, WM_OSCAP_CONTEXT.name);
                OS_ClearNode(children);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_SKIP_SEVERITY)) {
            if (wm_oscap_parse_skip_severity(nodes[i]->content, &oscap->flags) < 0) {
                merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_SEVERITY, WM_OSCAP_CONTEXT.name);
                OS_ClearNode(children);
                return OS_INVALID;
            }
        } else {
            merror("%s: ERROR: No such tag '%s' at module '%s'.", __local_name, nodes[i]->element, WM_OSCAP_CONTEXT.name);
            return OS_INVALID;
        }
    }

    if (!oscap->interval)
        oscap->interval = WM_DEF_INTERVAL;

    return 0;
}

int wm_oscap_parse_skip_result(const char *content, wm_oscap_flags *flags)
{
    char *string = strdup(content);
    char *token = strtok(string, ",");

    // Reset related flags
    flags->skip_result = 0;

    while (token) {
        token = wm_strtrim(token);

        if (!strcmp(token, "pass"))
            flags->skip_result_pass = 1;
        else if (!strcmp(token, "fail"))
            flags->skip_result_fail = 1;
        else if (!strcmp(token, "notchecked"))
            flags->skip_result_notchecked = 1;
        else if (!strcmp(token, "notapplicable"))
            flags->skip_result_notapplicable = 1;
        else {
            free(string);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    free(string);
    return 0;
}

int wm_oscap_parse_skip_severity(const char *content, wm_oscap_flags *flags)
{
    char *string = strdup(content);
    char *token = strtok(string, ",");

    // Reset related flags
    flags->skip_severity = 0;

    while (token) {
        token = wm_strtrim(token);

        if (!strcmp(token, "low"))
            flags->skip_severity_low = 1;
        else if (!strcmp(token, "medium"))
            flags->skip_severity_medium = 1;
        else if (!strcmp(token, "high"))
            flags->skip_severity_high = 1;
        else {
            free(string);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    free(string);
    return 0;
}
