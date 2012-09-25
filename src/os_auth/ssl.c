/* @(#) $Id: ./src/os_auth/ssl.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */


#ifdef USE_OPENSSL

#include "shared.h"
#include "auth.h"


void *os_ssl_keys(int isclient, char *dir)
{
    SSL_METHOD *sslmeth;
    SSL_CTX *ctx;
    char certf[1024 +1];
    char keyf[1024 +1];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);


    /* Create our context */
    sslmeth = (SSL_METHOD *)SSLv23_method();
    ctx = SSL_CTX_new(sslmeth);

    if(isclient)
    {
        debug1("%s: DEBUG: Returning CTX for client.", ARGV0);
        return(ctx);
    }

    if(!dir)
    {
        return(NULL);
    }


    /* Setting final cert/key files */
    certf[1024] = '\0';
    keyf[1024] = '\0';
    snprintf(certf, 1023, "%s%s", dir, CERTFILE);
    snprintf(keyf, 1023, "%s%s", dir, KEYFILE);


    if(File_DateofChange(certf) <= 0)
    {
        merror("%s: ERROR: Unable to read certificate file (not found): %s", ARGV0, certf);
        return(NULL);
    }

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx, certf)))
    {
        merror("%s: ERROR: Unable to read certificate file: %s", ARGV0, certf);
        ERR_print_errors_fp(stderr);
        return(NULL);
    }

    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyf, SSL_FILETYPE_PEM)))
    {
        merror("%s: ERROR: Unable to read private key file: %s", ARGV0, keyf);
        return(NULL);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        merror("%s: ERROR: Unable to verify private key file", ARGV0);
        return(NULL);
    }


    #if(OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx,1);
    #endif

    return ctx;
}


#endif

/* EOF */
