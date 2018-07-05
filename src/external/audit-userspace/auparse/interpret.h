/* interpret.h --
 * Copyright 2007,08,2016 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#ifndef INTERPRET_HEADER
#define INTERPRET_HEADER

#include "config.h"
#include "dso.h"
#include "rnode.h"
#include <time.h>

/* Make these hidden to prevent conflicts */
AUDIT_HIDDEN_START

void init_interpretation_list(void);
int load_interpretation_list(const char *buf);
void free_interpretation_list(void);
int lookup_type(const char *name);
const char *interpret(const rnode *r, auparse_esc_t escape_mode);
void aulookup_destroy_uid_list(void);
void aulookup_destroy_gid_list(void);
char *au_unescape(char *buf);

AUDIT_HIDDEN_END

#endif

