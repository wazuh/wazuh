#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../headers/file_op.h"
#include "../headers/defs.h"
#include "tap.h"

int test_temporary_file() {
    unsigned char test = 0;
    char template[OS_FLSIZE + 1];
    struct stat buf;

    int fd = TempFile(TIMESTAMP_FILE, template);
    w_assert_int_ge(fd, 0);

    fstat(fd, &buf);
    w_assert_mode_t_eq(buf.st_mode, 0177);

    unlink(template);
    close(fd);

    return 1;
}


int main(void) {
    printf("\n\n    STARTING TEST - TIMESTAMP FILE   \n\n");

    // Temporary file with right permissions created successfuly
    TAP_TEST_MSG(test_success_match(), "Creating temporary file with umask 0177 using TempFile test.");

    TAP_PLAN;
    TAP_SUMMARY;
    printf("\n    ENDING TEST  - TIMESTAMP FILE   \n\n");
    return 0;
}
