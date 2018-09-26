/*
 * Copyright (C) 2016 Wazuh Inc.
 * September 26, 2018
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

#undef ARGV0
#define ARGV0 "parallel-regex"

static void helpmsg(void) __attribute__((noreturn));
OSRegex regex;
int input_number = 7;
char *inputs[] = {
    "This is a test pattern for testing the parallel regex.",
    "This Is a test patrn for testing the parallel regex.",
    "This os a test pattern 4 testing the sequential regex",
    "This is a test pattern for testing the parallel regex",
    "NO",
    "This his a test patron for testing the paralel regex",
    "This IS a test PATTERN for testing the PARALLEL regex"
};

static void helpmsg()
{
    printf("\n%s %s: parallel-regex <threads>\n", __ossec_name, ARGV0);
    exit(1);
}

void *t_regex(__attribute__((unused)) void * id){
    int t_id = (intptr_t)id;
    int counter = 0;
    char msg[1024];
    char *ptr;
    int size;
    int i;

    printf("Starting thread %d\n", t_id);
    OSRegex_SetInstances(&regex, t_id);
    while (1) {
        counter = (t_id + counter) % input_number;
        if (OSRegex_Execute(inputs[counter], &regex, t_id)) {
            ptr = msg;
            size = snprintf(ptr, 1024, "+ [Thread %d] OSRegex_Execute: %s\n", t_id, inputs[counter]);
            ptr += size;
            for (i = 0; regex.matching[t_id]->sub_strings[i]; i++) {
                size = snprintf(ptr, 1024, " -Substring: %s\n", regex.matching[t_id]->sub_strings[i]);
                ptr += size;
            }
            printf("%s\n", msg);
            OSRegex_FreeSubStrings(&regex, t_id);
        }
    }
}

int main(int argc, char **argv)
{
    int i;
    int threads;
    char *pattern = "This (\\w+) a test (\\w*) for testing the (\\w+) regex";

    OS_SetName(ARGV0);

    /* User arguments */
    if (argc != 2) {
        helpmsg();
        return (-1);
    }

    /* User options */
    if (strcmp(argv[1], "-h") == 0) {
        helpmsg();
        return (-1);
    }

    threads = strtol(argv[1], NULL, 10);


    if (!OSRegex_Compile(pattern, &regex, OS_RETURN_SUBSTRING)) {
        printf("Pattern '%s' does not compile with OSRegex_Compile\n", pattern);
        return (-1);
    }

    for(i = 0; i < threads; i++){
        w_create_thread(t_regex,(void *) (intptr_t)i);
    }

    while (1) {
        sleep(10);
    }
    return (0);
}
