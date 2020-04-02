/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * April, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "../headers/bzip2_op.h"


int bzip2_compress(const char *file, const char *filebz2) {
    FILE* input;
    FILE* output;
    BZFILE* compressfile;
    int bzerror;

    if (!file || !filebz2) {
        return OS_INVALID;
    }

    input = fopen(file, "rb");
    if (!input) {
        merror(FOPEN_ERROR, file, errno, strerror(errno));
        return OS_INVALID;
    }

    output = fopen(filebz2, "wb" );
    if (!output) {
        merror(FOPEN_ERROR, filebz2, errno, strerror(errno));
        fclose(input);
        return OS_INVALID;
    }

    compressfile = BZ2_bzWriteOpen(&bzerror, output, 9, 0, 1);
    if (bzerror != BZ_OK) {
        merror("Could not open to write bz2 file (bz2error:%d): (%d)-%s",
                bzerror, errno, strerror(errno));
        fclose(input);
        fclose(output);
        return OS_INVALID;
    }

    char buf[2048];
    int readbuff;
    while (readbuff = fread(buf, sizeof(char), 2048, input), readbuff > 0) {
        BZ2_bzWrite(&bzerror, compressfile, (void*)buf, readbuff);

        if (bzerror != BZ_OK) {
            merror("Could not write bz2 file (bz2error:%d): (%d)-%s",
                    bzerror, errno, strerror(errno));
            fclose(input);
            fclose(output);
            BZ2_bzReadClose(&bzerror, compressfile);
            return OS_INVALID;
        }
    }

    unsigned int nbytes_in_lo32;
    unsigned int nbytes_in_hi32;
    unsigned int nbytes_out_lo32;
    unsigned int nbytes_out_hi32;
    BZ2_bzWriteClose64(&bzerror, compressfile, 0,
                       &nbytes_in_lo32, &nbytes_in_hi32,
                       &nbytes_out_lo32, &nbytes_out_hi32);

    if (bzerror != BZ_OK) {
        merror("BZ2_bzWriteClose64(%d): (%d)-%s", bzerror, errno, strerror(errno));
        fclose(input);
        fclose(output);
        BZ2_bzReadClose(&bzerror, compressfile);
        return OS_INVALID;
    }

    fclose(input);
    fclose(output);
    BZ2_bzReadClose(&bzerror, compressfile);
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
        return OS_INVALID;
    }

    input = fopen(filebz2, "rb");
    if (!input) {
        merror(FOPEN_ERROR, file, errno, strerror(errno));
        return OS_INVALID;
    }

    output = fopen(file, "wb" );
    if (!output) {
        merror(FOPEN_ERROR, filebz2, errno, strerror(errno));
        fclose(input);
        return OS_INVALID;
    }

    compressfile = BZ2_bzReadOpen(&bzerror, input, 0, 0, unused, nUnused);
    if (compressfile == NULL || bzerror != BZ_OK) {
        merror("BZ2_bzReadOpen(%d): (%d)-%s", bzerror, errno, strerror(errno));
        fclose(input);
        fclose(output);
        return OS_INVALID;
    }

    char buf[2048];
    int readbuff;
    do {
        readbuff = BZ2_bzRead(&bzerror, compressfile, buf, 2048);

        if (readbuff > 0) {
            if (bzerror == BZ_OK || bzerror == BZ_STREAM_END) {
                fwrite(buf, sizeof(char), readbuff, output);
            } else {
                merror("BZ2_bzRead(%d): (%d)-%s", bzerror, errno, strerror(errno));
                fclose(input);
                fclose(output);
                BZ2_bzReadClose(&bzerror, compressfile);
                return OS_INVALID;
            }
        }
    } while (readbuff > 0);

    fclose(input);
    fclose(output);
    BZ2_bzReadClose(&bzerror, compressfile);
    return 0;
}
