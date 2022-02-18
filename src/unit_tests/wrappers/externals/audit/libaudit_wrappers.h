/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef LIBAUDIT_WRAPPERS_H
#define LIBAUDIT_WRAPPERS_H

#include <libaudit.h>

int __wrap_audit_add_rule_data();

int __wrap_audit_add_watch_dir(int type,
                               struct audit_rule_data **rulep,
                               const char *path);

int __wrap_audit_close();

int __wrap_audit_delete_rule_data();

char *__wrap_audit_errno_to_name();

int __wrap_audit_get_reply(int fd,
                           struct audit_reply *rep,
                           reply_t block,
                           int peek);

int __wrap_audit_open();

int __wrap_audit_rule_fieldpair_data(struct audit_rule_data **rulep,
                                     const char *pair,
                                     int flags);

int __wrap_audit_send(int fd,
                      int type,
                      const void *data,
                      unsigned int size);

int __wrap_audit_update_watch_perms(struct audit_rule_data *rule,
                                    int perms);


int __wrap_audit_request_status(int fd);

#endif
