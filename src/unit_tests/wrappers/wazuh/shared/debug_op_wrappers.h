/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef DEBUG_OP_WRAPPERS_H
#define DEBUG_OP_WRAPPERS_H

#include "headers/defs.h"

int __wrap_isChroot();

void __wrap__mdebug1(const char * file,
                     int line,
                     const char * func,
                     const char *msg, ...);

void __wrap__mdebug2(const char * file,
                     int line,
                     const char * func,
                     const char *msg, ...);

void __wrap__merror(const char * file,
                    int line,
                    const char * func,
                    const char *msg, ...);

void __wrap__merror_exit(const char * file,
                         int line,
                         const char * func,
                         const char *msg, ...);

void __wrap__mferror(const char * file,
                    int line,
                    const char * func,
                    const char *msg, ...);

void __wrap__minfo(const char * file,
                  int line,
                  const char * func,
                  const char *msg, ...);

void __wrap__mtdebug1(const char *tag,
                      const char * file,
                      int line,
                      const char * func,
                      const char *msg, ...);

void __wrap__mtdebug2(const char *tag,
                      const char * file,
                      int line,
                      const char * func,
                      const char *msg, ...);

void __wrap__mterror(const char *tag,
                      const char * file,
                      int line,
                      const char * func,
                      const char *msg, ...);

void __wrap__mterror_exit(const char *tag,
                          const char * file,
                          int line,
                          const char * func,
                          const char *msg, ...);

void __wrap__mtinfo(const char *tag,
                          const char * file,
                          int line,
                          const char * func,
                          const char *msg, ...);

void __wrap__mtwarn(const char *tag,
                          const char * file,
                          int line,
                          const char * func,
                          const char *msg, ...);

void __wrap__mwarn(const char * file,
                   int line,
                   const char * func,
                   const char *msg, ...);

#endif
