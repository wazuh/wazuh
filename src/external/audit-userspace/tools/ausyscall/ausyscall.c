/*
 * ausysvcall.c - A program that lets you map syscall names and numbers 
 * Copyright (c) 2008 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "libaudit.h"

#define LAST_SYSCALL 1400	// IA64 is in the 1300's right now

void usage(void)
{
	fprintf(stderr, "usage: ausyscall [arch] name | number | --dump | --exact\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int i, rc;
	int machine=-1, syscall_num=-1, dump=0, exact=0;
	const char *name = NULL;

	if (argc > 4) {
		fputs("Too many arguments\n", stderr);
		usage();
	} else if (argc < 2)
		usage();
 
	for (i=1; i<argc; i++) {
		if (isdigit(argv[i][0])) {
			if (syscall_num != -1) {
				fputs("Two syscall numbers not allowed\n",
					stderr);
				usage();
			}
			syscall_num = strtol(argv[i], 0, 10);
		} else if ((rc = audit_name_to_machine(argv[i])) != -1) {
			if (machine != -1) {
				fputs("Two machine types not allowed\n",stderr);
				usage();
			}
			machine = rc;
		} else if (strcmp("--dump", argv[i]) == 0) {
			dump=1;
		} else if (strcmp("--exact", argv[i]) == 0) {
			exact=1;
#ifndef WITH_ALPHA
		} else if (strcmp("alpha", argv[i]) == 0) {
			fputs("Alpha processor support is not enabled\n",
					stderr);
			exit(1);
#endif
#ifndef WITH_ARM
		} else if (strcmp("arm", argv[i]) == 0) {
			fputs("Arm eabi processor support is not enabled\n",
					stderr);
			exit(1);
#endif
#ifndef WITH_AARCH64
		} else if (strcmp("aarch64", argv[i]) == 0) {
			fputs("Aarch64 processor support is not enabled\n",
					stderr);
			exit(1);
#endif
		} else {
			if (name != NULL) {
				fputs("Two syscall names not allowed\n",stderr);
				usage();
			}
			name = argv[i];
		}
	}
	if (machine == -1)
		machine = audit_detect_machine();
	if (machine == -1) {
		fprintf(stderr, "Unable to detect machine type\n");
		return 1;
	}

	if (dump) {
		printf("Using %s syscall table:\n",
			audit_machine_to_name(machine));
		for (i=0; i<8192; i++) {
			name = audit_syscall_to_name(i, machine);
			if (name) 
				printf("%d\t%s\n", i, name);
		}
		return 0;
	}

	if (name) {
		if (exact) {
			rc = audit_name_to_syscall(name, machine);
			if (rc < 0) {
				fprintf(stderr,
					"Unknown syscall %s using %s lookup table\n",
					name, audit_machine_to_name(machine));
				return 1;
			} else
				printf("%d\n", rc);
		} else {
			int found = 0;
			for (i=0; i< LAST_SYSCALL; i++) {
				const char *n = audit_syscall_to_name(i, machine);
				if (n && strcasestr(n, name)) {
					found = 1;
					printf("%-18s %d\n", n, i);
				}
			}
			if (!found) {
				fprintf(stderr,
					"Unknown syscall %s using %s lookup table\n",
					name, audit_machine_to_name(machine));
				return 1;
			}
		}
	} else if (syscall_num != -1) {
		name = audit_syscall_to_name(syscall_num, machine);
		if (name == NULL) {
			fprintf(stderr,
				"Unknown syscall %d using %s lookup table\n",
				syscall_num, audit_machine_to_name(machine));
			return 1;
		} else
			printf("%s\n", name);
	} else {
		fputs("Error - either a syscall name or number must "
			"be given with an optional arch\n", stderr);
		return 1;
	}

	return 0;
}

