/* RSA-PKCS1-SHA256 signature
 * Copyright (C) 2015-2019, Wazuh Inc.
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

static X509 * w_wpk_cert(FILE * fp);
static int wpk_verify_cert(X509 * cert, const char ** ca_store);

// Unsign a WPK256 file, using a key path array. Returns 0 on success or -1 on error.
int w_wpk_unsign(const char * source, const char * target, const char ** ca_store) {
    X509 * cert = NULL;
    EVP_PKEY * pkey = NULL;
    RSA * rsa = NULL;
    SHA256_CTX hash;
    FILE * filein = NULL;
    FILE * fileout = NULL;
    unsigned long err;
    unsigned char signature[SIGNLEN];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char buffer[BUFLEN];
    int retval = -1;
    long offset;
    ssize_t length;

    // Read signed file

    if (filein = fopen(source, "rb"), !filein) {
        merror("opening input file: %s", strerror(errno));
        goto cleanup;
    }

    // Check magic number

    if (length = fread(buffer, 1, sizeof(MAGIC), filein), length < (ssize_t)sizeof(MAGIC)) {
        merror("Invalid input file (reading magic number).");
        goto cleanup;
    }

    if (memcmp(buffer, MAGIC, sizeof(MAGIC))) {
        merror("Invalid input file (bad magic number).");
        goto cleanup;
    }

    // Get certificate

    if (cert = w_wpk_cert(filein), !cert) {
        merror("Couldn't extract certificate at file '%s'.", source);
        goto cleanup;
    }

    // Validate certificate

    if (ca_store) {
        if (wpk_verify_cert(cert, ca_store) < 0) {
            merror("Error verifying WPK certificate.");
            goto cleanup;
        }
    } else {
        mwarn("No root CA defined to verify file '%s'.", source);
    }

    // Read signature

    if (length = fread(signature, 1, SIGNLEN, filein), length < SIGNLEN) {
        merror("Invalid input file (reading signature).");
        goto cleanup;
    }

    // Hash of file content

    if (offset = ftell(filein), offset < 0) {
        merror(FTELL_ERROR, source, errno, strerror(errno));
        goto cleanup;
    }

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

    if (pkey = X509_get_pubkey(cert), !pkey) {
        merror("Couldn't get public key from certificate.");
        goto cleanup;
    }

    if (rsa = EVP_PKEY_get1_RSA(pkey), !rsa) {
        merror("Couldn't get public RSA key from certificate.");
        goto cleanup;
    }

    if (RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, SIGNLEN, rsa) != 1) {
        ERR_load_crypto_strings();

        while (err = ERR_get_error(), err) {
            switch (ERR_GET_REASON(err)) {
            case RSA_R_BAD_SIGNATURE:
                merror("Bad WPK signature.");
                break;

            default:
                merror("At RSA_verify(): %s (%lu)", ERR_reason_error_string(err), err);
            }
        }

        goto cleanup;
    }

    // Extract file

    if (fileout = fopen(target, "wb"), !fileout) {
        merror("Opening output file: %s", strerror(errno));
        goto cleanup;
    }

    if (fseek(filein, offset, SEEK_SET) < 0) {
        merror(FSEEK_ERROR, source, errno, strerror(errno));
        goto cleanup;
    }

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

    if (filein) {
        fclose(filein);
    }

    if (fileout) {
        fclose(fileout);
    }

    X509_free(cert);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);

    return retval;
}

// Extract certificate in PEM format from opened WPK file

X509 * w_wpk_cert(FILE * fp) {
    X509 * cert;
    BIO * bio;
    char * buffer = NULL;
    size_t i = 0;
    size_t size = 1024;

    os_calloc(1, size * sizeof(char), buffer);

    // Read until null character

    while (1) {
        if (!fread(buffer + i, sizeof(char), 1, fp)) {
            // Write anything but \0
            buffer[i] = '-';
            break;
        }

        if (!buffer[i] || feof(fp)) {
            break;
        }

        i++;

        if (i == size) {
            os_realloc(buffer, (size *= 2) * sizeof(char), buffer);
        }
    }

    if (buffer[i]) {
        merror("Couldn't get certificate from WPK file.");
        free(buffer);
        return NULL;
    }

    bio = BIO_new_mem_buf(buffer, (int)i);

    if (cert = PEM_read_bio_X509(bio, NULL, NULL, NULL), !cert) {
        merror("Invalid certificate in WPK file.");
        return NULL;
    }

    BIO_free_all(bio);
    free(buffer);
    return cert;
}

int wpk_verify_cert(X509 * cert, const char ** ca_store) {
    X509_STORE * store = NULL;
    X509_STORE_CTX * store_ctx = NULL;
    struct stat statbuf;
    unsigned long err;
    int result = -1;
    int i;

    OpenSSL_add_all_algorithms();

    store_ctx = X509_STORE_CTX_new();

    for (i = 0; ca_store[i]; i++) {

        // If empty string, ignore

        if (ca_store[i][0] == '\0') {
            continue;
        }

        if (store = X509_STORE_new(), !store) {
            merror("Couldn't create new store.");
            return -1;
        }

        int r;

        if (stat(ca_store[i], &statbuf) < 0) {
            merror(FSTAT_ERROR, ca_store[i], errno, strerror(errno));
            continue;
        }

        switch (statbuf.st_mode & S_IFMT) {
        case S_IFDIR:
            r = X509_STORE_load_locations(store, NULL, ca_store[i]);
            break;

        case S_IFREG:
            r = X509_STORE_load_locations(store, ca_store[i], NULL);
            break;

        default:
            merror("Loading CA '%s': it's neither file nor directory.", ca_store[i]);
            continue;
        }

        if (r < 0) {
            merror("Couldn't add CA '%s'", ca_store[i]);
            X509_STORE_free(store);
            continue;
        }

        X509_STORE_CTX_init(store_ctx, store, cert, NULL);

        r = X509_verify_cert(store_ctx);

        if (r == -1) {
            ERR_load_crypto_strings();

            while (err = ERR_get_error(), err) {
                mdebug1("At wpk_verify_cert(): %s (%lu)", ERR_reason_error_string(err), err);
            }

        } else if (r == 0) {
            ERR_load_crypto_strings();

            err = X509_STORE_CTX_get_error(store_ctx);
            mdebug1("Certificate couldn't be verified by CA '%s': %s (%lu)", ca_store[i], X509_verify_cert_error_string(err), err);

        } else if (r == 1) {

            result = 0;

        } else {
            mdebug1("At wpk_verify_cert(): unexpected result.");
        }

        X509_STORE_CTX_cleanup(store_ctx);
        X509_STORE_free(store);

        if (result == 0)
            break;
    }

    X509_STORE_CTX_free(store_ctx);

    return result;
}
