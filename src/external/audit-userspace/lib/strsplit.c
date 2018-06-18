/* strsplit.c --
 * Copyright 2014,2016,2017 Red Hat Inc., Durham, North Carolina.
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
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include <string.h>
#include "libaudit.h"
#include "private.h"

char *audit_strsplit_r(char *s, char **savedpp)
{
	char *ptr;

	if (s)
		*savedpp = s;
	else {
		if (*savedpp == NULL)
			return NULL;
		*savedpp += 1;
	}
retry:	
	ptr = strchr(*savedpp, ' ');
	if (ptr) {
		if (ptr == *savedpp) {
			*savedpp += 1;
			goto retry;
		}
		s = *savedpp;
		*ptr = 0;
		*savedpp = ptr;
		return s;
	} else {
		s = *savedpp;
		*savedpp = NULL;
		if (*s == 0)
			return NULL;
		return s;
	}
}

char *audit_strsplit(char *s)
{
	static char *str = NULL;
	char *ptr;

	if (s)
		str = s;
	else {
		if (str == NULL)
			return NULL;
		str++;
	}
retry:
	ptr = strchr(str, ' ');
	if (ptr) {
		if (ptr == str) {
			str++;
			goto retry;
		}
		s = str;
		*ptr = 0;
		str = ptr;
		return s;
	} else {
		s = str;
		str = NULL;
		if (*s == 0)
			return NULL;
		return s;
	}
}
