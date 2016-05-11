/*
 * Wazuh Module Manager
 * Wazuh Inc.
 * April 27, 2016
 */

#include "wmodules.h"

int wm_flag_reload = 0;     // Flag to reload configuration.
wmodule *wmodules = NULL;   // Config: linked list of all modules.


// Check general configuration

void wm_check() {
    wmodule *i;
    wmodule *j;
    wmodule *prev;

    // Check that a configuration exists

    if (!wmodules)
        ErrorExit("%s: WARN: No configuration defined. Exiting...", ARGV0);

    // Get the last module of the same type

    for (i = wmodules->next; i; i = i->next){
        prev = wmodules;
        for (j = wmodules; j != i; j = j->next){

            if (i->context->name == j->context->name){
                if(j == wmodules)
                    wmodules = j->next;
                else
                    prev->next = j->next;

                j->context->destroy(j->data);
                free(j);

                j = prev;
            }
            else
                prev = j;
        }
    }
}

// Destroy configuration data

void wm_destroy() {
    wmodule *next_module;

    while (wmodules) {
        next_module = wmodules->next;
        wmodules->context->destroy(wmodules->data);
        free(wmodules);
        wmodules = next_module;
    }
}

// Concatenate strings with optional separator

int wm_strcat(char **str1, const char *str2, char sep) {
    size_t len1;
    size_t len2;

    if (str2) {
        len2 = strlen(str2);

        if (*str1) {
            len1 = strlen(*str1);
            os_realloc(*str1, len1 + len2 + (sep ? 2 : 1), *str1);

            if (sep)
                memcpy(*str1 + (len1++), &sep, 1);
        } else {
            len1 = 0;
            os_malloc(len2 + 1, *str1);
        }

        memcpy(*str1 + len1, str2, len2 + 1);
        return 0;
    } else
        return -1;
}

// Compare two strings, trimming whitespaces of s1

char* wm_strtrim(char *string) {
    int i;

    while (*string == ' ')
        string++;

    i = strlen(string);

    if (i) {
        for (i--; string[i] == ' '; i--);
        string[i + 1] = '\0';
    }

    return string;
}

// Load or save the running state

int wm_state_io(const wm_context *context, int op, void *state, size_t size) {
    char path[PATH_MAX] = { '\0' };
    size_t nmemb;
    FILE *file;

    snprintf(path, PATH_MAX, "%s/%s", WM_STATE_DIR, context->name);

    if (!(file = fopen(path, op == WM_IO_WRITE ? "w" : "r")))
        return -1;

    nmemb = (op == WM_IO_WRITE) ? fwrite(state, size, 1, file) : fread(state, size, 1, file);
    fclose(file);

    return nmemb - 1;
}
