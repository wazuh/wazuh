/* @(#) $Id: ./src/os_auth/check_cert.c, 2014/04/25 mweigel Exp $
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
#include "check_cert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Could be replaced with X509_check_host() in future but this is only available
 * in openssl 1.0.2.
 */
int check_x509_cert(SSL *ssl, char *manager)
{
    X509 *cert = NULL;
    int match_found = 0;

    if(!(cert = SSL_get_peer_certificate(ssl)))
        goto CERT_CHECK_ERROR;

    /* Check for a matching subject alt name entry in the extensions first and
     * if no match is found there then check the subject CN.
     */
    debug1("%s: DEBUG: Checking certificate's subject alternative names.", ARGV0);
    if((match_found = check_subject_alt_names(cert, manager)) < 0)
        goto CERT_CHECK_ERROR;

    if(!match_found)
    {
        debug1("%s: DEBUG: No matching subject alternative names found. Checking common name.", ARGV0);
        if((match_found = check_subject_cn(cert, manager)) < 0)
            goto CERT_CHECK_ERROR;
    }

    if(!match_found)
        debug1("%s: DEBUG: Unable to match manager's name.", ARGV0);

    X509_free(cert);
    return match_found;

CERT_CHECK_ERROR:
    if (cert)
        X509_free(cert);

    return -1;
}

/* Loop through all the subject_alt_name entries until we find a match or
 * an error occurs.
 */
int check_subject_alt_names(X509 *cert, char *manager)
{
    GENERAL_NAMES *names = NULL;
    int i = 0;
    int result = 0;

    if(!(names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL)))
        return -1;

    for(i = 0; i < sk_GENERAL_NAME_num(names) && result == 0; i++)
    {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

        if(name->type == GEN_IPADD)
            result = check_ipaddr(name->d.iPAddress, manager);
        else if(name->type == GEN_DNS)
            result = check_hostname(name->d.dNSName, manager);
    }

    GENERAL_NAMES_free(names);
    return result;
}

/* Loop through all the common name entries until we find a match or
 * an error occurs.
 */
int check_subject_cn(X509 *cert, char *manager)
{
    X509_NAME *name = NULL;
    int i = 0;
    int result = 0;

    name = X509_get_subject_name(cert);
    while((i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0 && result == 0)
    {
        X509_NAME_ENTRY *ne = X509_NAME_get_entry(name, i);
        result = check_hostname(X509_NAME_ENTRY_get_data(ne), manager);
    }

    return result;
}

/* Determine whether a string found in a subject alt name or common name
 * field matches the manager's name specified on the command line. The
 * match is case insensitive.
 */
int check_hostname(ASN1_STRING *cstr, char *manager)
{
    label cert_labels[DNS_MAX_LABELS];
    label manager_labels[DNS_MAX_LABELS];
    int cert_label_count = 0;
    int manager_label_count = 0;
    char *cert = NULL;
    int i = 0;

    ASN1_STRING_to_UTF8((unsigned char **)&cert, cstr);
    if(cert && manager)
    {
        cert_label_count = get_domain_name_labels(cert, cert_labels);
        manager_label_count = get_domain_name_labels(manager, manager_labels);
        OPENSSL_free(cert);
    }
    else
    {
        return -1;
    }

    if(manager_label_count <= 0 || cert_label_count <= 0)
        return -1;

    if(manager_label_count != cert_label_count)
        return 0;

    /* Accept a wildcard label in the first position only.
     */
    if(label_valid(&manager_labels[0]) && !strcmp(cert_labels[0].text, "*"))
        i++;

    for(; i < manager_label_count; i++)
    {
        if(!label_valid(&manager_labels[i]))
            return 0;

        if(!label_match(&manager_labels[i], &cert_labels[i]))
            return 0;
    }

    return 1;
}

int check_ipaddr(ASN1_STRING *cstr, char *manager)
{
    struct sockaddr_in iptest;
    struct sockaddr_in6 iptest6;
    int result = 0;

    memset(&iptest, 0, sizeof(iptest));
    memset(&iptest6, 0, sizeof(iptest6));

    if(inet_pton(AF_INET, manager, &iptest.sin_addr) == 1)
    {
        if(cstr->length == 4 && !memcmp(cstr->data, (const void *)&iptest.sin_addr, 4))
            result = 1;
    }
    else if(inet_pton(AF_INET6, manager, &iptest6.sin6_addr) == 1)
    {
        if(cstr->length == 16 && !memcmp(cstr->data, (const void *)&iptest6.sin6_addr, 16))
            result = 1;
    }
    else
    {
        debug1("%s: DEBUG: Invalid IP address encountered.", ARGV0);
    }

    return result;
}

/* Separate a domain name into a series of labels and return the number of labels found.
 */
int get_domain_name_labels(const char *domain_name, label result[DNS_MAX_LABELS])
{
    int label_count = 0;
    const char *label_start = domain_name;
    const char *label_end = domain_name;

    do
    {
        if(label_count == DNS_MAX_LABELS)
            return -1;

        if(*label_end == '.' || *label_end == '\0')
        {
            label *c_label = &result[label_count];

            if ((c_label->len = label_end - label_start) > DNS_MAX_LABEL_LEN)
                return -1;

            strncpy(c_label->text, label_start, c_label->len);
            c_label->text[c_label->len] = '\0';

            label_start = label_end + 1;
            label_count++;
        }
    }
    while(*label_end++ != '\0');

    /* If the length of the last label is zero ignore it. This is the only
     * valid position for a label of length zero which occurs when a FQDN
     * is given.
     */
    return (result[label_count - 1].len > 0) ? label_count : label_count - 1;
}

/* Validate a label according to the guidelines in RFC 1035.
 */
int label_valid(const label *label)
{
    int i;

    if(label->len == 0 || label->len > DNS_MAX_LABEL_LEN)
        return 0;

    if(!isalpha(label->text[0]) || !isalnum(label->text[label->len - 1]))
        return 0;

    for(i = 0; i < label->len; i++)
    {
        if(!isalnum(label->text[i]) && label->text[i] != '-')
            return 0;
    }

    return 1;
}

/* Compare two labels and determine whether they match.
 */
int label_match(const label *label1, const label *label2)
{
    int i;

    if(label1->len != label2->len)
        return 0;

    for(i = 0; i < label1->len; i++)
    {
        if(tolower(label1->text[i]) != tolower(label2->text[i]))
            return 0;
    }

    return 1;
}

#endif

