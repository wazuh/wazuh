/* @(#) $Id: ./src/os_auth/auth.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef _AUTHD_H
#define _AUTHD_H

#ifndef ARGV0
   #define ARGV0 "ossec-authd"
#endif

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef USE_OPENSSL

void *os_ssl_keys(int isclient, char *dir);

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "os_net/os_net.h"
#include "addagent/manage_agents.h"

BIO *bio_err;
#define KEYFILE  "/etc/sslmanager.key"
#define CERTFILE  "/etc/sslmanager.cert"

#endif

#endif
