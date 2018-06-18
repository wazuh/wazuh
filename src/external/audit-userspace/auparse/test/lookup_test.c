/* lookup_test.c -- A test of table lookups.
 * Copyright 2017 Red Hat Inc., Durham, North Carolina.
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
 *      Miloslav Trmač <mitr@redhat.com>
 */

#include "config.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "gen_tables.h"

// To see if new tests are needed:
// $ grep 'i2s(int v)' ../*.h | wc -l
// 30
// only headers with i2s can be tested.


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

static int debug = 0;

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
			if (debug) printf("%d=%s\n", t[i].val, t[i].s); \
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

#include "../captabs.h"
static void
test_captab(void)
{
	static const struct entry t[] = {
#include "../captab.h"
	};

	printf("Testing captab...\n");
#define I2S(I) cap_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../clocktabs.h"
static void
test_clocktab(void)
{
	static const struct entry t[] = {
#include "../clocktab.h"
	};

	printf("Testing clocktab...\n");
#define I2S(I) clock_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../epoll_ctls.h"
static void
test_epoll_ctl(void)
{
	static const struct entry t[] = {
#include "../epoll_ctl.h"
	};

	printf("Testing epoll_ctl...\n");
#define I2S(I) epoll_ctl_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include <sys/socket.h>
#include "../famtabs.h"
static void
test_famtab(void)
{
	static const struct entry t[] = {
#include "../famtab.h"
	};

	printf("Testing famtab...\n");
#define I2S(I) fam_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../fcntl-cmdtabs.h"
static void
test_fcntltab(void)
{
	static const struct entry t[] = {
#include "../fcntl-cmdtab.h"
	};

	printf("Testing fcntltab...\n");
#define I2S(I) fcntl_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../icmptypetabs.h"
static void
test_icmptypetab(void)
{
	static const struct entry t[] = {
#include "../icmptypetab.h"
	};

	printf("Testing icmptypetab...\n");
#define I2S(I) icmptype_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../inethooktabs.h"
static void
test_inethooktab(void)
{
	static const struct entry t[] = {
#include "../inethooktab.h"
	};

	printf("Testing inethooktab...\n");
#define I2S(I) inethook_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../ioctlreqtabs.h"
static void
test_ioctlreqtab(void)
{
	static const struct entry t[] = {
#include "../ioctlreqtab.h"
	};

	printf("Testing ioctlreqtab...\n");
#define I2S(I) ioctlreq_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../ip6optnametabs.h"
static void
test_ip6optnametab(void)
{
	static const struct entry t[] = {
#include "../ip6optnametab.h"
	};

	printf("Testing ip6optnametab...\n");
#define I2S(I) ip6optname_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include <linux/ipc.h>
#include "../ipctabs.h"
static void
test_ipctab(void)
{
	static const struct entry t[] = {
#include "../ipctab.h"
	};

	printf("Testing ipctab...\n");
#define I2S(I) ipc_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../ipoptnametabs.h"
static void
test_ipoptnametab(void)
{
	static const struct entry t[] = {
#include "../ipoptnametab.h"
	};

	printf("Testing ipoptnametab...\n");
#define I2S(I) ipoptname_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../netactiontabs.h"
static void
test_netactiontab(void)
{
	static const struct entry t[] = {
#include "../netactiontab.h"
	};

	printf("Testing netactiontab...\n");
#define I2S(I) netaction_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../nfprototabs.h"
static void
test_nfprototab(void)
{
	static const struct entry t[] = {
#include "../nfprototab.h"
	};

	printf("Testing nfprototab...\n");
#define I2S(I) nfproto_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../normalize_evtypetabs.h"
static void
test_evtypetab(void)
{
	static const struct entry t[] = {
#include "../normalize_evtypetab.h"
	};

	printf("Testing evtypetab...\n");
#define I2S(I) evtype_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../normalize_obj_kind_maps.h"
static void
test_normalize_obj_kind_map(void)
{
	static const struct entry t[] = {
#include "../normalize_obj_kind_map.h"
	};

	printf("Testing normalize_obj_kind_map...\n");
#define I2S(I) normalize_obj_kind_map_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "libaudit.h"
#include "../normalize_record_maps.h"
static void
test_normalize_record_map(void)
{
	static const struct entry t[] = {
#include "../normalize_record_map.h"
	};

	printf("Testing normalize_record_map...\n");
#define I2S(I) normalize_record_map_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include <sys/personality.h>
#include "../persontabs.h"
static void
test_persontab(void)
{
	static const struct entry t[] = {
#include "../persontab.h"
	};

	printf("Testing persontab...\n");
#define I2S(I) person_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../pktoptnametabs.h"
static void
test_pktoptnametab(void)
{
	static const struct entry t[] = {
#include "../pktoptnametab.h"
	};

	printf("Testing pktoptnametab...\n");
#define I2S(I) pktoptname_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include <sys/prctl.h>
#include "../prctl_opttabs.h"
static void
test_prctl_opttab(void)
{
	static const struct entry t[] = {
#include "../prctl-opt-tab.h"
	};

	printf("Testing prctl_opttab...\n");
#define I2S(I) prctl_opt_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../ptracetabs.h"
static void
test_ptracetab(void)
{
	static const struct entry t[] = {
#include "../ptracetab.h"
	};

	printf("Testing ptracetab...\n");
#define I2S(I) ptrace_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../rlimittabs.h"
static void
test_rlimittab(void)
{
	static const struct entry t[] = {
#include "../rlimittab.h"
	};

	printf("Testing rlimittab...\n");
#define I2S(I) rlimit_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include <sched.h>
#include "../schedtabs.h"
static void
test_schedtab(void)
{
	static const struct entry t[] = {
#include "../schedtab.h"
	};

	printf("Testing schedtab...\n");
#define I2S(I) sched_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../seccomptabs.h"
static void
test_seccomptab(void)
{
	static const struct entry t[] = {
#include "../seccomptab.h"
	};

	printf("Testing seccomptab...\n");
#define I2S(I) seccomp_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../seektabs.h"
static void
test_seektab(void)
{
	static const struct entry t[] = {
#include "../seektab.h"
	};

	printf("Testing seektab...\n");
#define I2S(I) seek_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../signaltabs.h"
static void
test_signaltab(void)
{
	static const struct entry t[] = {
#include "../signaltab.h"
	};

	printf("Testing signaltab...\n");
#define I2S(I) signal_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../sockleveltabs.h"
static void
test_sockleveltab(void)
{
	static const struct entry t[] = {
#include "../sockleveltab.h"
	};

	printf("Testing sockleveltab...\n");
#define I2S(I) socklevel_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../sockoptnametabs.h"
static void
test_sockoptnametab(void)
{
	static const struct entry t[] = {
#include "../sockoptnametab.h"
	};

	printf("Testing sockoptnametab...\n");
#define I2S(I) sockoptname_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include <linux/net.h>
#include "../socktabs.h"
static void
test_socktab(void)
{
	static const struct entry t[] = {
#include "../socktab.h"
	};

	printf("Testing socktab...\n");
#define I2S(I) sock_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../socktypetabs.h"
static void
test_socktypetab(void)
{
	static const struct entry t[] = {
#include "../socktypetab.h"
	};

	printf("Testing socktypetab...\n");
#define I2S(I) sock_type_i2s(I)
	TEST_I2S(0);
#undef I2S
}

#include "../tcpoptnametabs.h"
static void
test_tcpoptnametab(void)
{
	static const struct entry t[] = {
#include "../tcpoptnametab.h"
	};

	printf("Testing tcpoptnametab...\n");
#define I2S(I) tcpoptname_i2s(I)
	TEST_I2S(0);
#undef I2S
}

int
main(void)
{
	// This is only for preventing collisions in s2i tests.
	// If collisions are found in future, change the number. 
	srand(3);
	test_captab();
	test_clocktab();
	test_epoll_ctl();
	test_famtab();
	test_fcntltab();
	test_icmptypetab();
	test_inethooktab();
	test_ioctlreqtab();
	test_ip6optnametab();
	test_ipctab();
	test_ipoptnametab();
	test_netactiontab();
	test_nfprototab();
	test_evtypetab();
	test_normalize_obj_kind_map();
	test_normalize_record_map();
	test_persontab();
	test_pktoptnametab();
	test_prctl_opttab();
	test_ptracetab();
	test_rlimittab();
	test_schedtab();
	test_seccomptab();
	test_seektab();
	test_signaltab();
	test_sockleveltab();
	test_sockoptnametab();
	test_socktab();
	test_socktypetab();
	test_tcpoptnametab();

	puts("===============================");
	puts("Interpretation table tests pass");
	puts("===============================");

	return EXIT_SUCCESS;
}

