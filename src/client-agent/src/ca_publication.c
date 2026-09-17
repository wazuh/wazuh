/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "ca_publication.h"
#include "x509_op.h"

/* The first line of the block, so a reader (or an operator opening the file) can tell what the
 * comment is for. Not parsed: only the generation line carries meaning. */
#define CA_PUBLICATION_BANNER "## wazuh-ca-bundle"
#define CA_PUBLICATION_PREFIX "## generation:"

/* A bundle's own leading comment is a handful of lines. Anything longer is not a trust store
 * this agent wrote, so stop looking rather than read an arbitrary file to its end hunting for a
 * line that is not coming. */
#define CA_PUBLICATION_MAX_HEADER_LINES 32

int64_t w_ca_publication_read(const char *path) {
    FILE *fp;
    char line[OS_BUFFER_SIZE];
    int64_t generation = W_CA_PUBLICATION_UNKNOWN;
    int lines = 0;

    if (path == NULL) {
        return W_CA_PUBLICATION_UNKNOWN;
    }

    if (fp = wfopen(path, "r"), fp == NULL) {
        return W_CA_PUBLICATION_UNKNOWN;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        const char *value;
        char *end = NULL;
        long long parsed;

        /* The certificates begin here: everything this function cares about is above them, and
         * a "## generation:" inside a base64 body is not a thing that can happen. */
        if (strncmp(line, "-----BEGIN", 10) == 0) {
            break;
        }

        if (++lines > CA_PUBLICATION_MAX_HEADER_LINES) {
            break;
        }

        if (strncmp(line, CA_PUBLICATION_PREFIX, strlen(CA_PUBLICATION_PREFIX)) != 0) {
            continue;
        }

        value = line + strlen(CA_PUBLICATION_PREFIX);
        errno = 0;
        parsed = strtoll(value, &end, 10);

        /* Everything after the digits must be blank: a trailing token means this line was not
         * written by w_ca_publication_render() and reading a publication out of it would be
         * guessing. */
        if (errno != 0 || end == value || parsed <= 0 || parsed > INT64_MAX) {
            break;
        }

        while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
            end++;
        }

        if (*end != '\0') {
            break;
        }

        generation = (int64_t) parsed;
        break;
    }

    fclose(fp);

    return generation;
}

int w_ca_publication_render(int64_t generation, char *out, size_t out_size) {
    int written;

    if (out == NULL || generation <= 0) {
        return -1;
    }

    written = snprintf(out, out_size, "%s\n%s %lld\n", CA_PUBLICATION_BANNER,
                       CA_PUBLICATION_PREFIX, (long long) generation);

    if (written < 0 || (size_t) written >= out_size) {
        return -1;
    }

    return 0;
}

int w_ca_publication_install(const char *path, const char *pem, size_t pem_len, int64_t generation) {
    char block[128];
    File store = {NULL, NULL};
    X509 **certs = NULL;
    size_t count = 0;
    int ret = -1;

    if (path == NULL || pem == NULL || pem_len == 0) {
        return -1;
    }

    if (w_ca_publication_render(generation, block, sizeof(block)) != 0) {
        merror("CA bundle: refusing to record publication %lld.", (long long) generation);
        return -1;
    }

    /* The temporary file is where the body is judged, not the destination: a bundle that turns
     * out not to be certificates must never have existed at the path the agent verifies
     * against. TempFile() templates on the target, so the rename below stays within one
     * filesystem and is atomic. */
    if (TempFile(&store, path, 0) < 0) {
        merror("CA bundle: could not create a temporary file beside '%s': %s (%d).", path,
               strerror(errno), errno);
        return -1;
    }

#ifndef WIN32
    /* Same 0640 the anchor already carries: the runtime user reads the certificate authority it
     * verifies against; nothing widens beyond that. TempFile() leaves 0600 behind its umask. */
    if (chmod(store.name, 0640) == -1) {
        merror("CA bundle: could not set permissions on '%s': %s (%d).", store.name,
               strerror(errno), errno);
        goto end;
    }
#endif

    if (fwrite(block, 1, strlen(block), store.fp) != strlen(block) ||
            fwrite(pem, 1, pem_len, store.fp) != pem_len) {
        merror("CA bundle: could not write the trust store to '%s'.", store.name);
        goto end;
    }

    if (fclose(store.fp) != 0) {
        /* A write error can surface only here, when the stream is flushed; installing a store
         * whose tail never reached the disk would be installing a truncated bundle. */
        store.fp = NULL;
        merror("CA bundle: could not flush the trust store to '%s': %s (%d).", store.name,
               strerror(errno), errno);
        goto end;
    }

    store.fp = NULL;

    /* Judged only now that every byte is on disk, and judged from the file rather than the
     * buffer so what is validated is exactly what would be installed. */
    if (certs = w_x509_load_all_pem(store.name, &count), certs == NULL) {
        merror("CA bundle: the body served for publication %lld is not a certificate bundle this "
               "agent can parse; the trust store is unchanged.", (long long) generation);
        goto end;
    }

    w_x509_free_all(certs, count);

    if (OS_MoveFile(store.name, path) < 0) {
        merror("CA bundle: could not install the trust store at '%s'.", path);
        goto end;
    }

    minfo("CA bundle: trust store replaced at publication %lld (%zu certificate(s)).",
          (long long) generation, count);
    os_free(store.name);
    return 0;

end:
    if (store.fp != NULL) {
        fclose(store.fp);
    }

    unlink(store.name);
    os_free(store.name);

    return ret;
}
