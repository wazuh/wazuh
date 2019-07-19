#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../headers/file_op.h"
#include "../headers/defs.h"
#include "tap.h"

int test_temporary_file() {
    char template[OS_FLSIZE + 1];
    struct stat buf;
    int ret = 1;

    int fd = TempFile("/var/ossec/queue/agents-timestamp", template);

    if (fd < 0){
        ret = 0;
        goto clean;
    }

    fstat(fd, &buf);

    if ((buf.st_mode & S_IRUSR) && (buf.st_mode & S_IWUSR)) {
        goto clean;
    } else {
        ret = 0;
    }

clean:
    unlink(template);
    close(fd);
    return ret;
}

int test_copy_file() {
    FILE *file_to_read;
    FILE *file_to_write;
    char buffer[60];
    int ret = 1;

    char str[] = "Test file";

    file_to_read = fopen("read_file.txt","w+");
    fwrite(str, 1, sizeof(str), file_to_read);

    file_to_write = fopen("write_file.txt", "w+");

    CopyFile(file_to_read, file_to_write);

    fclose(file_to_write);
    file_to_write = fopen("write_file.txt", "r");

    if (file_to_write) {
        if ((fgets(buffer, 60, file_to_write)) != NULL){
            if(strcmp(buffer, str) != 0) {
                ret = 0;
                goto clean;
            }
        }
    } else {
        ret = 0;
        goto clean;
    }



clean:
    fclose(file_to_write);
    fclose(file_to_read);
    remove("read_file.txt");
    remove("write_file.txt");

    return ret;
}


int main(void) {
    printf("\n\n    STARTING TEST - TIMESTAMP FILE   \n\n");

    // Temporary file with right permissions created successfuly
    TAP_TEST_MSG(test_temporary_file(), "Creating temporary file with umask 0177 using TempFile test.");

    // Copy a file's content to a new one
    TAP_TEST_MSG(test_copy_file(), "Copy a file's content to another file using CopyFile test.");

    TAP_PLAN;
    TAP_SUMMARY;
    printf("\n    ENDING TEST  - TIMESTAMP FILE   \n\n");
    return 0;
}
