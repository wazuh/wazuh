/*
 * Copyright (C) 2015, Wazuh Inc.
 * April, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../headers/shared.h"


int bzip2_compress(const char *file, const char *filebz2) {
    FILE* input;
    FILE* output;
    BZFILE* compressfile;
    int bzerror;

    if (!file || !filebz2) {
        return -1;
    }

    input = wfopen(file, "rb");
    if (!input) {
        mdebug2(FOPEN_ERROR, file, errno, strerror(errno));
        return -1;
    }

    output = wfopen(filebz2, "wb");
    if (!output) {
        mdebug2(FOPEN_ERROR, filebz2, errno, strerror(errno));
        fclose(input);
        return -1;
    }

    compressfile = BZ2_bzWriteOpen(&bzerror, output, 9, 0, 1);
    if (bzerror != BZ_OK) {
        mdebug2("Could not open to write bz2 file (%d)'%s': (%d)-%s",
                bzerror, filebz2, errno, strerror(errno));

        // compressfile is null at this point.
        BZ2_bzWriteClose(&bzerror, compressfile, 0, NULL, NULL);

        fclose(input);
        fclose(output);
        return -1;
    }

    char buf[BZIP2_BUFFER_SIZE];
    int readbuff;
    while (readbuff = fread(buf, sizeof(char), sizeof(buf), input), readbuff > 0) {
        BZ2_bzWrite(&bzerror, compressfile, (void*)buf, readbuff);

        if (bzerror != BZ_OK) {
            mdebug2("Could not write bz2 file (%d)'%s': (%d)-%s",
                    bzerror, filebz2, errno, strerror(errno));
            BZ2_bzWriteClose(&bzerror, compressfile, 0, NULL, NULL);
            fclose(input);
            fclose(output);
            return -1;
        }
    }

    BZ2_bzWriteClose(&bzerror, compressfile, 0, NULL, NULL);
    fclose(input);
    fclose(output);
    return 0;
}

int bzip2_uncompress(const char *filebz2, const char *file) {
    FILE* input;
    FILE* output;
    BZFILE* compressfile;
    int bzerror;
    unsigned char unused[BZ_MAX_UNUSED];
    int nUnused = 0;

    if (!file || !filebz2) {
        return -1;
    }

    input = wfopen(filebz2, "rb");
    if (!input) {
        mdebug2(FOPEN_ERROR, filebz2, errno, strerror(errno));
        return -1;
    }

     output = wfopen(file, "wb");
    if (!output) {
        mdebug2(FOPEN_ERROR, file, errno, strerror(errno));
        fclose(input);
        return -1;
    }

    compressfile = BZ2_bzReadOpen(&bzerror, input, 0, 0, unused, nUnused);
    if (compressfile == NULL || bzerror != BZ_OK) {
        mdebug2("BZ2_bzReadOpen(%d)'%s': (%d)-%s",
                bzerror, filebz2, errno, strerror(errno));

        // compressfile is null at this point.
        BZ2_bzReadClose(&bzerror, compressfile);

        fclose(input);
        fclose(output);
        return -1;
    }

    char buf[BZIP2_BUFFER_SIZE];
    int readbuff;
    do {
        readbuff = BZ2_bzRead(&bzerror, compressfile, buf, sizeof(buf));
        if (bzerror == BZ_OK || bzerror == BZ_STREAM_END) {
            fwrite(buf, sizeof(char), readbuff, output);
        } else {
            mdebug2("BZ2_bzRead(%d)'%s': (%d)-%s",
                    bzerror, filebz2, errno, strerror(errno));
            BZ2_bzReadClose(&bzerror, compressfile);
            fclose(input);
            fclose(output);
            return -1;
        }
    } while (bzerror == BZ_OK);

    BZ2_bzReadClose(&bzerror, compressfile);
    fclose(input);
    fclose(output);
    return 0;
}
