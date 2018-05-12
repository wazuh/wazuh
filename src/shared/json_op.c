/*
 * JSON support library
 * Copyright (C) 2018 Wazuh Inc.
 * May 11, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

cJSON * json_fread(const char * path) {
    FILE * fp = NULL;
    cJSON * item = NULL;
    char * buffer = NULL;
    long size;

    // Load file

    if (fp = fopen(path, "r"), !fp) {
        mdebug1(FOPEN_ERROR, path, errno, strerror(errno));
        return NULL;
    }

    // Get file size

    if (size = get_fp_size(fp), size < 0) {
        mdebug1(FSEEK_ERROR, path, errno, strerror(errno));
        goto end;
    }

    // Check file size limit

    if (size > JSON_MAX_FSIZE) {
        mdebug1("Cannot load JSON file '%s': it exceeds %s", path, JSON_MAX_FSIZE_TEXT);
        goto end;
    }

    // Allocate memory
    os_malloc(size + 1, buffer);

    // Get file and parse into JSON

    if (fread(buffer, 1, size, fp) == 0) {
        mdebug1(FREAD_ERROR, path, errno, strerror(errno));
        goto end;
    }

    buffer[size] = '\0';

    if (item = cJSON_Parse(buffer), !item) {
        mdebug1("Couldn't parse JSON file '%s'", path);
    }

end:

    if (fp) {
        fclose(fp);
    }

    free(buffer);
    return item;
}

int json_fwrite(const char * path, const cJSON * item) {
    FILE * fp = NULL;
    char * buffer;
    size_t size;
    int retval = -1;

    if (buffer = cJSON_PrintUnformatted(item), !buffer) {
        mdebug1("Internal error dumping JSON into file '%s'", path);
        return -1;
    }

    size = strlen(buffer);

    if (fp = fopen(path, "w"), !fp) {
        mdebug1(FOPEN_ERROR, path, errno, strerror(errno));
        goto end;
    }

    if (fwrite(buffer, 1, size, fp) != size) {
        mdebug1("Couldn't write JSON into '%s': %s (%d)", path, strerror(errno), errno);
        goto end;
    }

    retval = 0;

end:
    free(buffer);

    if (fp) {
        fclose(fp);
    }

    return retval;
}
