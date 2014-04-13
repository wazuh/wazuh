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


/* Create an SSL context. If certificate verification is requested
 * then load the file containing the CA chain and verify the certifcate
 * sent by the peer.
 */
SSL_CTX *os_ssl_keys(int is_server, char *os_dir, char *cert, char *key, char *ca_cert)
{
    SSL_CTX *ctx = NULL;

    if(!(ctx = get_ssl_context()))
        goto SSL_ERROR;

    /* If a CA certificate has been specified then load it and verify the peer.
     */
    if(ca_cert)
    {
        debug1("%s: DEBUG: Peer verification requested.", ARGV0);

        if(!load_ca_cert(ctx, ca_cert))
            goto SSL_ERROR;

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    }

    /* Loading a certificate and key is mandatory for the server and optional for clients.
     */
    if(is_server)
    {
        char default_cert[PATH_MAX + 1];
        char default_key[PATH_MAX + 1];

        if(!cert)
        {
            snprintf(default_cert, PATH_MAX + 1, "%s%s", os_dir, CERTFILE);
            cert = default_cert;
        }

        if(!key)
        {
            snprintf(default_key, PATH_MAX + 1, "%s%s", os_dir, KEYFILE);
            key = default_key;
        }

        if(!load_cert_and_key(ctx, cert, key))
            goto SSL_ERROR;

        debug1("%s: DEBUG: Returning CTX for server.", ARGV0);
    }
    else
    {
        if(cert && key)
        {
            if(!load_cert_and_key(ctx, cert, key))
                goto SSL_ERROR;
        }

        debug1("%s: DEBUG: Returning CTX for client.", ARGV0);
    }

    return ctx;

SSL_ERROR:
    if(ctx)
        SSL_CTX_free(ctx);

    return (SSL_CTX *)NULL;
}

SSL_CTX *get_ssl_context()
{
    SSL_METHOD *sslmeth = NULL;
    SSL_CTX *ctx = NULL;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Create our context */
    sslmeth = (SSL_METHOD *)SSLv23_method();
    if(!(ctx = SSL_CTX_new(sslmeth)))
        goto CONTEXT_ERR;

    /* Explicitly set options and cipher list. */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if(!(SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH")))
        goto CONTEXT_ERR;

    return ctx;

CONTEXT_ERR:
    if(ctx)
        SSL_CTX_free(ctx);

    return (SSL_CTX *)NULL;
}

int load_cert_and_key(SSL_CTX *ctx, char *cert, char *key)
{
    if(File_DateofChange(cert) <= 0)
    {
        merror("%s: ERROR: Unable to read certificate file (not found): %s", ARGV0, cert);
        return 0;
    }

    if(!(SSL_CTX_use_certificate_chain_file(ctx, cert)))
    {
        merror("%s: ERROR: Unable to read certificate file: %s", ARGV0, cert);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(!(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)))
    {
        merror("%s: ERROR: Unable to read private key file: %s", ARGV0, key);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(!SSL_CTX_check_private_key(ctx))
    {
        merror("%s: ERROR: Unable to verify private key file", ARGV0);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    #if(OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx, 1);
    #endif

    return 1;
}

int load_ca_cert(SSL_CTX *ctx, char *ca_cert)
{
    if(!ca_cert)
    {
        merror("%s: ERROR: Verification requested but no CA certificate file specified", ARGV0);
        return 0;
    }

    if(SSL_CTX_load_verify_locations(ctx, ca_cert, NULL) != 1)
    {
        merror("%s: ERROR: Unable to read CA certificate file \"%s\"", ARGV0, ca_cert);
        return 0;
    }

    return 1;
}

/* Could be replaced with X509_check_host() in future but this is only available
 * in openssl 1.0.2.
 */
int check_x509_cert(SSL *ssl, char *manager, int is_ip)
{
    X509 *cert = NULL;
    int match_found = 0;

    if(!(cert = SSL_get_peer_certificate(ssl)))
        goto CERT_CHECK_FAILED;

    /* Check for a matching subject alt name entry in the extensions first and
     * if no match is found there then check the subject CN.
     */
    debug1("%s: DEBUG: Checking manager's subject alternative names.", ARGV0);
    if((match_found = check_subject_alt_names(cert, manager, is_ip)) < 0)
        goto CERT_CHECK_FAILED;

    if(!match_found)
    {
        debug1("%s: DEBUG: No matching subject alternative names found. Checking common name.", ARGV0);
        if((match_found = check_subject_cn(cert, manager)) < 0)
            goto CERT_CHECK_FAILED;
    }

    if(!match_found)
        debug1("%s: DEBUG: Unable to match manager's name.", ARGV0);

    X509_free(cert);
    return match_found;

CERT_CHECK_FAILED:
    if (cert)
        X509_free(cert);

    /* return X509_V_ERR_APPLICATION_VERIFICATION; */
    return 0;
}

/* Loop through all the subject_alt_name entries until we find a match or
 * an error occurs.
 */
int check_subject_alt_names(X509 *cert, char *manager, int is_ip)
{
    GENERAL_NAMES *names = NULL;
    int i = 0;
    int rv = 0;

    if(!(names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL)))
        return rv;

    for(i = 0; i < sk_GENERAL_NAME_num(names); i++)
    {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

        if(is_ip)
        {
            if(name->type == GEN_IPADD)
                rv = check_ipaddr(name->d.iPAddress, manager);
        }
        else
        {
            if(name->type == GEN_DNS)
                rv = check_hostname(name->d.dNSName, manager);
        }

        if(rv != 0)
            break;
    }

    GENERAL_NAMES_free(names);
    return rv;
}

/* Loop through all the common name entries until we find a match or
 * an error occurs.
 */
int check_subject_cn(X509 *cert, char *manager)
{
    X509_NAME *name = NULL;
    int i = 0;
    int rv = 0;

    name = X509_get_subject_name(cert);
    while((i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
    {
        X509_NAME_ENTRY *ne = X509_NAME_get_entry(name, i);

        if((rv = check_hostname(X509_NAME_ENTRY_get_data(ne), manager)) != 0)
            break;
    }

    return rv;
}

/* Determine whether a string found in a subject_alt_name or common name
 * matches the manager's name specified on the command line. The match is
 * case insensitive.
 */
int check_hostname(ASN1_STRING *cstr, char *manager)
{
    int i = 0;

    if (!cstr->data || !cstr->length)
        return 0;

    /* Check the names in the certificate for embedded NULL characters. */
    if (memchr(cstr->data, '\0', cstr->length) != NULL)
        return 0;

    if (cstr->length != strlen(manager))
        return 0;

    for(i = 0; i < cstr->length; i++)
    {
        if(tolower(cstr->data[i]) != tolower(manager[i]))
            return 0;
    }

    return 1;
}

int check_ipaddr(ASN1_STRING *cstr, char *manager)
{
    struct sockaddr_in iptest;
    struct sockaddr_in6 iptest6;
    int rv = 0;

    memset(&iptest, 0, sizeof(iptest));
    memset(&iptest6, 0, sizeof(iptest6));

    if(inet_pton(AF_INET, manager, &iptest.sin_addr) == 1)
    {
        if(cstr->length == 4 && !memcmp(cstr->data, (const void *)&iptest.sin_addr, 4))
            rv = 1;
    }
    else if(inet_pton(AF_INET6, manager, &iptest6.sin6_addr) == 1)
    {
        if(cstr->length == 16 && !memcmp(cstr->data, (const void *)&iptest6.sin6_addr, 16))
            rv = 1;
    }
    else
    {
        debug1("%s: DEBUG: Invalid IP address encountered.", ARGV0);
    }

    return rv;
}

/* No extra verification is done here. This function provides more
 * information in the case that certificate verification fails
 * for any reason.
 */
int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];

    if(!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);

        merror("%s: ERROR: Problem with certificate at depth %i", ARGV0, depth);

        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        merror("%s: ERROR: issuer =  %s", ARGV0, data);

        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        merror("%s: ERROR: subject =  %s", ARGV0, data);

        merror("%s: ERROR: %i:%s", ARGV0, err, X509_verify_cert_error_string(err));
    }

    return ok;
}

#endif

/* EOF */
