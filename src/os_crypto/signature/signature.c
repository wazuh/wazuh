/* RSA-PKCS1-SHA256 signature
 * Copyright (C) 2017 Wazuh Inc.
 * June 28, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <headers/shared.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define SIGNLEN 2048 / 8
#define BUFLEN 4096
static const char MAGIC[] = "WPK256";

static RSA * w_rsa_readpem(const char * path);

// Unsign a WPK256 file, using a key path array. Returns 0 on success or -1 on error.
int w_rsa_unsign(const char * source, const char * target, const char ** keys) {
    RSA * rsa = NULL;
    SHA256_CTX hash;
    FILE * filein = NULL;
    FILE * fileout = NULL;
    unsigned long err;
    unsigned char signature[SIGNLEN];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char buffer[BUFLEN];
    int retval = -1;
    int i;
    ssize_t length;

    if (!(keys && keys[0])) {
        merror("No public keys to verify file '%s'.", source);
        goto cleanup;
    }

    // Read signed file

    if (filein = fopen(source, "rb"), !filein) {
        merror("opening input file: %s", strerror(errno));
        goto cleanup;
    }

    // Check magic number

    if (length = fread(buffer, 1, strlen(MAGIC), filein), length < (ssize_t)strlen(MAGIC)) {
        merror("Invalid input file (reading magic number).");
        goto cleanup;
    }

    if (memcmp(buffer, MAGIC, strlen(MAGIC))) {
        merror("Invalid input file (bad magic number).");
        goto cleanup;
    }

    // Read signature

    if (length = fread(signature, 1, SIGNLEN, filein), length < SIGNLEN) {
        merror("Invalid input file (reading signature).");
        goto cleanup;
    }

    // Hash of file content

    SHA256_Init(&hash);

    while (length = fread(buffer, 1, BUFLEN, filein), length > 0) {
        SHA256_Update(&hash, buffer, length);
    }

    if (length < 0) {
        merror("Invalid input file (reading content).");
        goto cleanup;
    }

    SHA256_Final(digest, &hash);

    // Verify signature (PKCS1)

    for (i = 0; keys[i]; i++) {
        if (*keys[i] && (rsa = w_rsa_readpem(keys[i]), rsa)) {
            if (RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, SIGNLEN, rsa) == 1) {
                RSA_free(rsa);
                break;
            } else {
                ERR_load_crypto_strings();

                while (err = ERR_get_error(), err) {
                    if (ERR_GET_REASON(err) != RSA_R_BAD_SIGNATURE) {
                        merror("At RSA_verify(): %s (%lu)", ERR_reason_error_string(err), err);
                    }
                }

                RSA_free(rsa);
            }
        }
    }

    if (!keys[i]) {
        merror("Bad signature.");
        goto cleanup;
    }

    // Extract file

    if (fileout = fopen(target, "wb"), !fileout) {
        merror("Opening output file: %s", strerror(errno));
        goto cleanup;
    }

    fseek(filein, strlen(MAGIC) + SIGNLEN, SEEK_SET);

    while (length = fread(buffer, 1, BUFLEN, filein), length > 0) {
        if (fwrite(buffer, 1, length, fileout) != (size_t)length) {
            merror("writing output file.");
            goto cleanup;
        }
    }

    if (length < 0) {
        merror("Invalid input file (writing output).");
        goto cleanup;
    }

    retval = 0;

cleanup:

    if (filein) fclose(filein);
    if (fileout) fclose(fileout);

    return retval;
}

RSA * w_rsa_readpem(const char * path) {
    RSA * rsa;
    FILE * filekey;

    if (filekey = fopen(path, "rb"), !filekey) {
        merror("Opening key file '%s': %s", path, strerror(errno));
        return NULL;
    }

    rsa = PEM_read_RSA_PUBKEY(filekey, &rsa, NULL, NULL);
    fclose(filekey);

    if (!rsa) {
        merror("Invalid RSA public key in file '%s'.", path);
        RSA_free(rsa);
        return NULL;
    }

    return rsa;
}
