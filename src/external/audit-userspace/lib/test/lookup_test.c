/* lookup_test.c -- A test of table lookups.
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
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
 *      Miloslav Trmač <mitr@redhat.com>
 */

#include "config.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../libaudit.h"

/* Number of lookups of random strings */
#define RAND_ITERATIONS 1000

/* Maximum size of randomly generated strings, including the terminating NUL. */
#define S_LEN 8

struct entry {
	int val;
	const char *s;
};
#define _S(V, S) { (V), (S) },

/* Generate a random string into DEST[S_LEN]. */
static void
gen_id(char *dest)
{
	size_t i, len;

	assert(S_LEN >= 2);
	len = 1 + rand() % (S_LEN - 1);
	assert('A' == 0x41 && 'a' == 0x61); /* ASCII */
	for (i = 0; i < len; i++) {
		/* Don't start with a digit, audit_name_to_msg_type() interprets
		   those strings specially. */
		do {
			dest[i] = 0x21 + rand() % (0x7F - 0x21);
		} while (i == 0 && dest[i] >= '0' && dest[i] <= '9');
	}
	dest[i] = '\0';
}

#define TEST_I2S(EXCL)							\
	do {								\
		size_t i;						\
									\
		for (i = 0; i < sizeof(t) / sizeof(*t); i++) {		\
			const char *s;					\
									\
			if (EXCL)					\
				continue;				\
			s = I2S(t[i].val);				\
			if (s == NULL) {				\
				fprintf(stderr,				\
					"%d -> `%s' not found\n",	\
					t[i].val, t[i].s);		\
				abort();				\
			}						\
			if (strcmp(t[i].s, s) != 0) {			\
				fprintf(stderr,				\
					"%d -> `%s' mismatch `%s'\n",	\
					t[i].val, t[i].s, s);		\
				abort();				\
			}						\
		}							\
		for (i = 0; i < RAND_ITERATIONS; i++) {			\
			int val;					\
			size_t j;					\
			val = rand();					\
			for (j = 0; j < sizeof(t) / sizeof(*t); j++) {	\
				if (t[j].val == val)			\
					goto test_i2s_found;		\
			}						\
			assert(I2S(val) == NULL);			\
		test_i2s_found:						\
			;						\
		}							\
	} while (0)

#define TEST_S2I(ERR_VALUE)						\
	do {								\
		size_t i;						\
		char buf[S_LEN];					\
									\
		for (i = 0; i < sizeof(t) / sizeof(*t); i++)		\
			assert(S2I(t[i].s) == t[i].val);		\
		for (i = 0; i < RAND_ITERATIONS; i++) {			\
			/* Blindly assuming this will not generate a	\
			   meaningful identifier. */			\
			gen_id(buf);					\
			if (S2I(buf) != (ERR_VALUE)) {			\
				fprintf(stderr,				\
					"Unexpected match `%s'\n",	\
					buf);				\
				abort();				\
			}						\
		}							\
	} while (0)

#ifdef WITH_ALPHA
static void
test_alpha_table(void)
{
	static const struct entry t[] = {
#include "../alpha_table.h"
	};

	printf("Testing alpha_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_ALPHA)
#define S2I(S) audit_name_to_syscall((S), MACH_ALPHA)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}
#endif

#ifdef WITH_ARM
static void
test_arm_table(void)
{
	static const struct entry t[] = {
#include "../arm_table.h"
	};

	printf("Testing arm_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_ARM)
#define S2I(S) audit_name_to_syscall((S), MACH_ARM)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}
#endif

#ifdef WITH_AARCH64
static void
test_aarch64_table(void)
{
	static const struct entry t[] = {
#include "../aarch64_table.h"
	};

	printf("Testing aarch64_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_AARCH64)
#define S2I(S) audit_name_to_syscall((S), MACH_AARCH64)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}
#endif

static void
test_i386_table(void)
{
	static const struct entry t[] = {
#include "../i386_table.h"
	};

	printf("Testing i386_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_X86)
#define S2I(S) audit_name_to_syscall((S), MACH_X86)
	TEST_I2S(strcmp(t[i].s, "madvise1") == 0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_ia64_table(void)
{
	static const struct entry t[] = {
#include "../ia64_table.h"
	};

	printf("Testing ia64_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_IA64)
#define S2I(S) audit_name_to_syscall((S), MACH_IA64)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_ppc_table(void)
{
	static const struct entry t[] = {
#include "../ppc_table.h"
	};

	printf("Testing ppc_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_PPC)
#define S2I(S) audit_name_to_syscall((S), MACH_PPC)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_s390_table(void)
{
	static const struct entry t[] = {
#include "../s390_table.h"
	};

	printf("Testing s390_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_S390)
#define S2I(S) audit_name_to_syscall((S), MACH_S390)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_s390x_table(void)
{
	static const struct entry t[] = {
#include "../s390x_table.h"
	};

	printf("Testing s390x_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_S390X)
#define S2I(S) audit_name_to_syscall((S), MACH_S390X)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_x86_64_table(void)
{
	static const struct entry t[] = {
#include "../x86_64_table.h"
	};

	printf("Testing x86_64_table...\n");
#define I2S(I) audit_syscall_to_name((I), MACH_86_64)
#define S2I(S) audit_name_to_syscall((S), MACH_86_64)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_actiontab(void)
{
	static const struct entry t[] = {
#include "../actiontab.h"
	};

	printf("Testing actiontab...\n");
#define I2S(I) audit_action_to_name(I)
#define S2I(S) audit_name_to_action(S)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_errtab(void)
{
	static const struct entry t[] = {
#include "../errtab.h"
	};

	printf("Testing errtab...\n");
#define I2S(I) audit_errno_to_name(I)
#define S2I(S) audit_name_to_errno(S)
	TEST_I2S(strcmp(t[i].s, "EWOULDBLOCK") == 0
		 || strcmp(t[i].s, "EDEADLOCK") == 0);
	TEST_S2I(0);
#undef I2S
#undef S2I
}

static void
test_fieldtab(void)
{
	static const struct entry t[] = {
#include "../fieldtab.h"
	};

	printf("Testing fieldtab...\n");
#define I2S(I) audit_field_to_name(I)
#define S2I(S) audit_name_to_field(S)
	TEST_I2S(strcmp(t[i].s, "loginuid") == 0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_flagtab(void)
{
	static const struct entry t[] = {
#include "../flagtab.h"
	};

	printf("Testing flagtab...\n");
#define I2S(I) audit_flag_to_name(I)
#define S2I(S) audit_name_to_flag(S)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_fstypetab(void)
{
	static const struct entry t[] = {
#include "../fstypetab.h"
	};

	printf("Testing fstypetab...\n");
#define I2S(I) audit_fstype_to_name(I)
#define S2I(S) audit_name_to_fstype(S)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_ftypetab(void)
{
	static const struct entry t[] = {
#include "../ftypetab.h"
	};

	printf("Testing ftypetab...\n");
#define I2S(I) audit_ftype_to_name(I)
#define S2I(S) audit_name_to_ftype(S)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_machinetab(void)
{
	static const struct entry t[] = {
#include "../machinetab.h"
	};

	printf("Testing machinetab...\n");
#define I2S(I) audit_machine_to_name(I)
#define S2I(S) audit_name_to_machine(S)
	TEST_I2S((t[i].s[0] == 'i' && t[i].s[1] >= '4' && t[i].s[1] <= '6'
		 && strcmp(t[i].s + 2, "86") == 0) ||
		(strncmp(t[i].s, "arm", 3) == 0));
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_msg_typetab(void)
{
	static const struct entry t[] = {
#include "../msg_typetab.h"
	};

	printf("Testing msg_typetab...\n");
#define I2S(I) audit_msg_type_to_name(I)
#define S2I(S) audit_name_to_msg_type(S)
	TEST_I2S(0);
	TEST_S2I(-1);
#undef I2S
#undef S2I
}

static void
test_optab(void)
{
	static const struct entry t[] = {
#include "../optab.h"
	};

	printf("Testing optab...\n");
#define I2S(I) audit_operator_to_symbol(I)
	TEST_I2S(0);
#undef I2S
}

int
main(void)
{
	// This is only for preventing collisions in s2i tests.
	// If collisions are found in future, change the number. 
	srand(3);
#ifdef WITH_ALPHA
	test_alpha_table();
#endif
#ifdef WITH_ARM
	test_arm_table();
#endif
#ifdef WITH_AARCH64
	test_aarch64_table();
#endif
	test_i386_table();
	test_ia64_table();
	test_ppc_table();
	test_s390_table();
	test_s390x_table();
	test_x86_64_table();
	test_actiontab();
	test_errtab();
	test_fieldtab();
	test_flagtab();
	test_fstypetab();
	test_ftypetab();
	test_machinetab();
	test_msg_typetab();
	test_optab();
	return EXIT_SUCCESS;
}

