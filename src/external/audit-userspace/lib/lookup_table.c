/* lookup_table.c -- 
 * Copyright 2004-2008,2012-13,2016 Red Hat Inc., Durham, North Carolina.
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
 *      Rickard E. (Rik) Faith <faith@redhat.com>
 */

#include "config.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "libaudit.h"
#include "gen_tables.h"
#include "private.h"

#ifndef NO_TABLES
#ifdef WITH_ALPHA
#include "alpha_tables.h"
#endif
#ifdef WITH_ARM
#include "arm_tables.h"
#endif
#ifdef WITH_AARCH64
#include "aarch64_tables.h"
#endif
#include "i386_tables.h"
#include "ia64_tables.h"
#include "ppc_tables.h"
#include "s390_tables.h"
#include "s390x_tables.h"
#include "x86_64_tables.h"
#include "errtabs.h"
#include "fstypetabs.h"
#include "ftypetabs.h"
#include "fieldtabs.h"
#endif
#include "msg_typetabs.h"
#include "actiontabs.h"
#include "flagtabs.h"
#include "machinetabs.h"
#include "optabs.h"

struct int_transtab {
    int        key;
    unsigned int  lvalue;
};

static const struct int_transtab elftab[] = {
    { MACH_X86,     AUDIT_ARCH_I386   },
    { MACH_86_64,   AUDIT_ARCH_X86_64 },
    { MACH_IA64,    AUDIT_ARCH_IA64   },
    { MACH_PPC64,   AUDIT_ARCH_PPC64  },
    { MACH_PPC64LE, AUDIT_ARCH_PPC64LE},
    { MACH_PPC,     AUDIT_ARCH_PPC    },
    { MACH_S390X,   AUDIT_ARCH_S390X  },
    { MACH_S390,    AUDIT_ARCH_S390   },
#ifdef WITH_ALPHA
    { MACH_ALPHA,   AUDIT_ARCH_ALPHA  },
#endif
#ifdef WITH_ARM
    { MACH_ARM,   AUDIT_ARCH_ARM  },
#endif
#ifdef WITH_AARCH64
    { MACH_AARCH64, AUDIT_ARCH_AARCH64},
#endif
};
#define AUDIT_ELF_NAMES (sizeof(elftab)/sizeof(elftab[0]))

int audit_name_to_field(const char *field)
{
#ifndef NO_TABLES
	int res;

	if (field_s2i(field, &res) != 0)
		return res;
#endif
	return -1;
}

const char *audit_field_to_name(int field)
{
#ifndef NO_TABLES
	return field_i2s(field);
#else
	return NULL;
#endif
}

int audit_name_to_syscall(const char *sc, int machine)
{
	int res, found = 0;

	switch (machine)
	{
#ifndef NO_TABLES
		case MACH_X86:
			found = i386_syscall_s2i(sc, &res);
			break;
		case MACH_86_64:
			found = x86_64_syscall_s2i(sc, &res);
			break;
		case MACH_IA64:
			found = ia64_syscall_s2i(sc, &res);
			break;
		case MACH_PPC64:
		case MACH_PPC64LE:
		case MACH_PPC:
			found = ppc_syscall_s2i(sc, &res);
			break;
		case MACH_S390X:
			found = s390x_syscall_s2i(sc, &res);
			break;
		case MACH_S390:
			found = s390_syscall_s2i(sc, &res);
			break;
#ifdef WITH_ALPHA
	        case MACH_ALPHA:
			found = alpha_syscall_s2i(sc, &res);
			break;
#endif
#ifdef WITH_ARM
	        case MACH_ARM:
			found = arm_syscall_s2i(sc, &res);
			break;
#endif
#ifdef WITH_AARCH64
	        case MACH_AARCH64:
			found = aarch64_syscall_s2i(sc, &res);
			break;
#endif
#endif
		default:
			return -1;
	}
	if (found)
		return res;
	return -1;
}

const char *audit_syscall_to_name(int sc, int machine)
{
#ifndef NO_TABLES
	switch (machine)
	{
		case MACH_X86:
			return i386_syscall_i2s(sc);
		case MACH_86_64:
			return x86_64_syscall_i2s(sc);
		case MACH_IA64:
			return ia64_syscall_i2s(sc);
		case MACH_PPC64:
		case MACH_PPC64LE:
		case MACH_PPC:
			return ppc_syscall_i2s(sc);
		case MACH_S390X:
			return s390x_syscall_i2s(sc);
		case MACH_S390:
			return s390_syscall_i2s(sc);
#ifdef WITH_ALPHA
	        case MACH_ALPHA:
			return alpha_syscall_i2s(sc);
#endif
#ifdef WITH_ARM
	        case MACH_ARM:
			return arm_syscall_i2s(sc);
#endif
#ifdef WITH_AARCH64
	        case MACH_AARCH64:
			return aarch64_syscall_i2s(sc);
#endif
	}
#endif
	return NULL;
}

int audit_name_to_flag(const char *flag)
{
	int res;

	if (flag_s2i(flag, &res) != 0)
		return res;
	return -1;
}

const char *audit_flag_to_name(int flag)
{
	return flag_i2s(flag);
}

int audit_name_to_action(const char *action)
{
	int res;

	if (action_s2i(action, &res) != 0)
		return res;
	return -1;
}

const char *audit_action_to_name(int action)
{
	return action_i2s(action);
}

// On the critical path for ausearch parser
int audit_name_to_msg_type(const char *msg_type)
{
	int rc;

	if (msg_type_s2i(msg_type, &rc) != 0)
		return rc;

	/* Take a stab at converting */
	if (strncmp(msg_type, "UNKNOWN[", 8) == 0) {
		int len;
		char buf[8];
		const char *end = strchr(msg_type + 8, ']');
		if (end == NULL)
			return -1;

		len = end - (msg_type + 8);
		if (len > 7)
			len = 7;
		memset(buf, 0, sizeof(buf));
		strncpy(buf, msg_type + 8, len);
		errno = 0;
		return strtol(buf, NULL, 10);
	} else if (isdigit(*msg_type)) {
		errno = 0;
		return strtol(msg_type, NULL, 10);
	}

	return -1;
}

const char *audit_msg_type_to_name(int msg_type)
{
	return msg_type_i2s(msg_type);
}

int audit_name_to_machine(const char *machine)
{
	int res;

	if (machine_s2i(machine, &res) != 0)
		return res;
	return -1;
}

const char *audit_machine_to_name(int machine)
{
	return machine_i2s(machine);
}

unsigned int audit_machine_to_elf(int machine)
{
	unsigned int i;
    
	for (i = 0; i < AUDIT_ELF_NAMES; i++)
		if (elftab[i].key == machine) 
			return elftab[i].lvalue;
	return 0;
}

int audit_elf_to_machine(unsigned int elf)
{
	unsigned int i;
    
	for (i = 0; i < AUDIT_ELF_NAMES; i++) 
		if (elftab[i].lvalue == elf) return elftab[i].key;
	return -1;
}

const char *audit_operator_to_symbol(int op)
{
	return op_i2s(op);
}

/* This function returns 0 on error, otherwise the converted value */
int audit_name_to_errno(const char *error)
{
#ifndef NO_TABLES
	int rc, minus = 1;

	if (*error == '-') {
		minus = -1;
		error++;
	}
	if (err_s2i(error, &rc) == 0)
		rc = 0;

	return rc*minus;
#else
	return 0;
#endif
}

/* This function does not handle negative numbers yet */
const char *audit_errno_to_name(int error)
{
#ifndef NO_TABLES
	if (error < 0)
		return NULL;

        return err_i2s(error);
#else
	return NULL;
#endif
}

int audit_name_to_ftype(const char *name)
{
	int res;

#ifndef NO_TABLES
	if (ftype_s2i(name, &res) != 0)
		return res;
#endif
	return -1;
}

const char *audit_ftype_to_name(int ftype)
{
#ifndef NO_TABLES
	return ftype_i2s(ftype);
#else
	return NULL;
#endif
}

int audit_name_to_fstype(const char *name)
{
	int res;

#ifndef NO_TABLES
	if (fstype_s2i(name, &res) != 0)
		return res;
#endif
	return -1;
}

const char *audit_fstype_to_name(int fstype)
{
#ifndef NO_TABLES
	return fstype_i2s(fstype);
#else
	return NULL;
#endif
}

