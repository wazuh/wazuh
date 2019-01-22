/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
OSRegex regex, second_regex, third_regex;
int input_number = 11;
char *inputs[] = {
    "This is a test pattern for testing the parallel regex.",
    "This Is a test patrn for testing the parallel regex.",
    "This os a test pattern 4 testing the sequential regex",
    "This is a test pattern for testing the parallel regex",
    "NO",
    "Without substrings.",
    "This is the 2 pattern.",
    "This his a test patron for testing the paralel regex",
    "This IS a test PATTERN for testing the PARALLEL regex",
    "pattern x. asdfgta",
    "This is the second pattern."
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
    regex_matching str_match;
    memset(&str_match, 0, sizeof(regex_matching));

    printf("Starting thread %d\n", t_id);
    while (1) {
        counter = (t_id + counter + 1) % input_number;

        if (OSRegex_Execute_ex(inputs[counter], &second_regex, &str_match)) {
            ptr = msg;
            size = snprintf(ptr, 1024, "+ [Thread %d][SECOND_PATTERN_MATCH]: %s\n", t_id, inputs[counter]);
            ptr += size;
            for (i = 0; str_match.sub_strings[i]; i++) {
                size = snprintf(ptr, 1024, " -Substring: %s\n", str_match.sub_strings[i]);
                ptr += size;
            }
            printf("%s\n", msg);
        }

        if (OSRegex_Execute_ex(inputs[counter], &regex, &str_match)) {
            ptr = msg;
            size = snprintf(ptr, 1024, "+ [Thread %d][FIRST_PATTERN_MATCH]: %s\n", t_id, inputs[counter]);
            ptr += size;
            for (i = 0; str_match.sub_strings[i]; i++) {
                size = snprintf(ptr, 1024, " -Substring: %s\n", str_match.sub_strings[i]);
                ptr += size;
            }
            printf("%s\n", msg);
        }


        if (OSRegex_Execute_ex(inputs[counter], &third_regex, &str_match)) {
            ptr = msg;
            size = snprintf(ptr, 1024, "+ [Thread %d][THIRD_PATTERN_MATCH]: %s\n", t_id, inputs[counter]);
            ptr += size;
            for (i = 0; str_match.sub_strings[i]; i++) {
                size = snprintf(ptr, 1024, " -Substring: %s\n", str_match.sub_strings[i]);
                ptr += size;
            }
            printf("%s\n", msg);
        }
    }
}

int main(int argc, char **argv)
{
    int i;
    int threads;
    char *pattern = "This (\\w+) a test (\\w*) for testing the (\\w+) regex|pattern (\\w).";
    char *second_pattern = "This is the (\\w*) pattern.";
    char *third_pattern = "Without substrings.";
    char *n_threads;

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

    n_threads = strdup((strlen(argv[1]) < 4 && strlen(argv[1]) > 0) ? argv[1] : "1");
    threads = strtol(n_threads, NULL, 10);
    threads = (threads < 1) ? 1 : ((threads > 40) ? 40 : threads);
    free(n_threads);

    if (!OSRegex_Compile(pattern, &regex, OS_RETURN_SUBSTRING)) {
        printf("Pattern '%s' does not compile with OSRegex_Compile\n", pattern);
        return (-1);
    }

    if (!OSRegex_Compile(second_pattern, &second_regex, OS_RETURN_SUBSTRING)) {
        printf("Pattern '%s' does not compile with OSRegex_Compile\n", second_pattern);
        return (-1);
    }

    if (!OSRegex_Compile(third_pattern, &third_regex, OS_RETURN_SUBSTRING)) {
        printf("Pattern '%s' does not compile with OSRegex_Compile\n", second_pattern);
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
