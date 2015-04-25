/* Copyright by Daniel B. Cid (2005, 2006)
 * Under the public domain. It is just an example.
 * Some examples of usage for the os_regex library.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_regex.h"


int main(int argc, char **argv)
{
    int r_code = 0;

    /* OSRegex structure */
    OSRegex reg;

    /* Check for arguments */
    if (argc != 3) {
        printf("%s regex string\n", argv[0]);
        exit(1);
    }

    /* If the compilation failed, we don't need to free anything.
     * We are passing the OS_RETURN_SUBSTRING because we wan't the
     * substrings back.
     */
    if (OSRegex_Compile(argv[1], &reg, OS_RETURN_SUBSTRING)) {
        const char *retv;
        /* If the execution succeeds, the substrings will be
         * at reg.sub_strings
         */
        if ((retv = OSRegex_Execute(argv[2], &reg))) {
            int sub_size = 0;
            char **ret;
            r_code = 1;

            /* Next pt */
            printf("next pt: '%s'\n", retv);
            /* Assign reg.sub_strings to ret */
            ret = reg.sub_strings;

            printf("substrings:\n");
            while (*ret) {
                printf("  %d: !%s!\n", sub_size, *ret);
                sub_size++;
                ret++;
            }

            /* We must free the substrings */
            OSRegex_FreeSubStrings(&reg);
        } else {
            printf("Error: Didn't match.\n");
        }

        OSRegex_FreePattern(&reg);
    }

    /* Compilation error */
    else {
        printf("Error: Regex Compile Error: %d\n", reg.error);
    }

    return (r_code);
}

