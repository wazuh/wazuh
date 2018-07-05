/* gen_tables.c -- Generator of lookup tables.
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
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/net.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/personality.h>
#include <sys/mount.h>
#ifndef MS_DIRSYNC
#include <linux/fs.h>
#endif
#include "gen_tables.h"
#include "libaudit.h"
#include "auparse-defs.h"

/* This is from asm/ipc.h. Copying it for now as some platforms
 *  * have broken headers. */
#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define SEMTIMEDOP       4
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24
#define DIPC            25

/*
 * Defines EHWPOISON to the value found in uapi/asm-generic/errno.h,
 * which is correct for most (but not all architectures).
 */
#ifndef EHWPOISON
#define EHWPOISON      133
#endif


/* The ratio of table size to number of non-empty elements allowed for a
   "direct" s2i table; if the ratio would be bigger, bsearch tables are used
   instead.

   2 looks like a lot at a first glance, but the bsearch tables need twice as
   much space per element, so with the ratio equal to 2 the direct table uses
   no more memory and is faster. */
#define DIRECT_THRESHOLD 2

/* Allow more than one string defined for a single integer value */
static bool allow_duplicate_ints; /* = false; */

struct value {
	int val;
	const char *s;
	size_t s_offset;
	size_t orig_index;
};

/* The mapping to store. */
static struct value values[] = {
#define _S(VAL, S) { (VAL), (S), 0, 0 },
#include TABLE_H
#undef _S
};

#define NUM_VALUES (sizeof(values) / sizeof(*values))

/* Compare two "struct value" members by name. */
static int
cmp_value_strings(const void *xa, const void *xb)
{
	const struct value *a, *b;

	a = xa;
	b = xb;
	return strcmp(a->s, b->s);
}

/* Compare two "struct value" members by value. */
static int
cmp_value_vals(const void *xa, const void *xb)
{
	const struct value *a, *b;

	a = xa;
	b = xb;
	if (a->val > b->val)
		return 1;
	if (a->val < b->val)
		return -1;
	/* Preserve the original order if there is an ambiguity, to always use
	   the first specified value. */
	if (a->orig_index > b->orig_index)
		return 1;
	if (a->orig_index < b->orig_index)
		return -1;
	return 0;
}

/* Compare two "struct value" members by orig_index. */
static int
cmp_value_orig_index(const void *xa, const void *xb)
{
	const struct value *a, *b;

	a = xa;
	b = xb;
	if (a->orig_index > b->orig_index)
		return 1;
	if (a->orig_index < b->orig_index)
		return -1;
	return 0;
}

/* Output the string table, initialize values[*]->s_offset. */
static void
output_strings(const char *prefix)
{
	size_t i, offset;

	offset = 0;
	for (i = 0; i < NUM_VALUES; i++) {
		values[i].s_offset = offset;
		offset += strlen(values[i].s) + 1;
	}
	printf("static const char %s_strings[] = \"", prefix);
	assert(NUM_VALUES > 0);
	for (i = 0; i < NUM_VALUES; i++) {
		const char *c;

		if (i != 0 && i % 10 == 0)
			fputs("\"\n"
			      "\t\"", stdout);
		for (c = values[i].s; *c != '\0'; c++) {
			assert(*c != '"' && *c != '\\'
			       && isprint((unsigned char)*c));
			putc(*c, stdout);
		}
		if (i != NUM_VALUES - 1)
			fputs("\\0", stdout);
	}
	fputs("\";\n", stdout);
}

/* Output the string to integer mapping code.
   Assume strings are all uppsercase or all lowercase if specified by
   parameters; in that case, make the search case-insensitive.
   values must be sorted by strings. */
static void
output_s2i(const char *prefix, bool uppercase, bool lowercase)
{
	size_t i;

	for (i = 0; i < NUM_VALUES - 1; i++) {
		assert(strcmp(values[i].s, values[i + 1].s) <= 0);
		if (strcmp(values[i].s, values[i + 1].s) == 0) {
			fprintf(stderr, "Duplicate value `%s': %d, %d\n",
				values[i].s, values[i].val, values[i + 1].val);
			abort();
		}
	}
	printf("static const unsigned %s_s2i_s[] = {", prefix);
	for (i = 0; i < NUM_VALUES; i++) {
		if (i % 10 == 0)
			fputs("\n\t", stdout);
		assert(values[i].s_offset <= UINT_MAX);
		printf("%zu,", values[i].s_offset);
	}
	printf("\n"
	       "};\n"
	       "static const int %s_s2i_i[] = {", prefix);
	for (i = 0; i < NUM_VALUES; i++) {
		if (i % 10 == 0)
			fputs("\n\t", stdout);
		printf("%d,", values[i].val);
	}
	fputs("\n"
	      "};\n", stdout);
	assert(!(uppercase && lowercase));
	if (uppercase) {
		for (i = 0; i < NUM_VALUES; i++) {
			const char *c;

			for (c = values[i].s; *c != '\0'; c++)
				assert(isascii((unsigned char)*c)
				       && !GT_ISLOWER(*c));
		}
	} else if (lowercase) {
		for (i = 0; i < NUM_VALUES; i++) {
			const char *c;

			for (c = values[i].s; *c != '\0'; c++)
				assert(isascii((unsigned char)*c)
				       && !GT_ISUPPER(*c));
		}
	}
	if (uppercase || lowercase) {
		printf("static int %s_s2i(const char *s, int *value) {\n"
		       "\tsize_t len, i;\n"
		       "\t if (s == NULL || value == NULL)\n"
		       "\t\treturn 0;\n"
		       "\tlen = strlen(s);\n"
		       "\t{ char copy[len + 1];\n"
		       "\tfor (i = 0; i < len; i++) {\n"
		       "\t\tchar c = s[i];\n", prefix);
		if (uppercase)
			fputs("\t\tcopy[i] = GT_ISLOWER(c) ? c - 'a' + 'A' "
							  ": c;\n", stdout);
		else
			fputs("\t\tcopy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' "
							  ": c;\n", stdout);
		printf("\t}\n"
		       "\tcopy[i] = 0;\n"
		       "\treturn s2i__(%s_strings, %s_s2i_s, %s_s2i_i, %zu, "
				      "copy, value);\n"
		       "\t}\n"
		       "}\n", prefix, prefix, prefix, NUM_VALUES);
	} else
		printf("static int %s_s2i(const char *s, int *value) {\n"
		       "\treturn s2i__(%s_strings, %s_s2i_s, %s_s2i_i, %zu, s, "
				      "value);\n"
		       "}\n", prefix, prefix, prefix, prefix, NUM_VALUES);
}

/* Output the string to integer mapping table.
   values must be sorted by strings. */
static void
output_i2s(const char *prefix)
{
	struct value *unique_values;
	int min_val, max_val;
	size_t i, n;

	assert(NUM_VALUES > 0);
	for (i = 0; i < NUM_VALUES - 1; i++) {
		assert(values[i].val <= values[i + 1].val);
		if (!allow_duplicate_ints
		    && values[i].val == values[i + 1].val) {
			fprintf(stderr, "Duplicate value %d: `%s', `%s'\n",
				values[i].val, values[i].s, values[i + 1].s);
			abort();
		}
	}

	unique_values = malloc(NUM_VALUES * sizeof(*unique_values));
	assert(unique_values != NULL);
	n = 0;
	for (i = 0; i < NUM_VALUES; i++) {
		if (n == 0 || unique_values[n - 1].val != values[i].val) {
			unique_values[n] = values[i];
			n++;
		}
	}

	min_val = unique_values[0].val;
	max_val = unique_values[n - 1].val;
	if (((double)max_val - (double)min_val) / n <= DIRECT_THRESHOLD) {
		int next_index;

		printf("static const unsigned %s_i2s_direct[] = {", prefix);
		next_index = min_val;
		i = 0;
		for (;;) {
			if ((next_index - min_val) % 10 == 0)
				fputs("\n\t", stdout);
			while (unique_values[i].val < next_index)
				/* This can happen if (allow_duplicate_ints) */
				i++;
			if (unique_values[i].val == next_index) {
				assert(unique_values[i].s_offset <= UINT_MAX);
				printf("%zu,", unique_values[i].s_offset);
			} else
				fputs("-1u,", stdout);
			if (next_index == max_val)
				/* Done like this to avoid integer overflow */
				break;
			next_index++;
		}
		printf("\n"
		       "};\n"
		       "static const char *%s_i2s(int v) {\n"
		       "\treturn i2s_direct__(%s_strings, %s_i2s_direct, %d, "
					     "%d, v);\n"
		       "}\n", prefix, prefix, prefix, min_val, max_val);
	} else {
		printf("static const int %s_i2s_i[] = {", prefix);
		for (i = 0; i < n; i++) {
			if (i % 10 == 0)
				fputs("\n\t", stdout);
			printf("%d,", unique_values[i].val);
		}
		printf("\n"
		       "};\n"
		       "static const unsigned %s_i2s_s[] = {", prefix);
		for (i = 0; i < n; i++) {
			if (i % 10 == 0)
				fputs("\n\t", stdout);
			assert(unique_values[i].s_offset <= UINT_MAX);
			printf("%zu,", unique_values[i].s_offset);
		}
		printf("\n"
		       "};\n"
		       "static const char *%s_i2s(int v) {\n"
		       "\treturn i2s_bsearch__(%s_strings, %s_i2s_i, %s_i2s_s, "
			      "%zu, v);\n"
		       "}\n", prefix, prefix, prefix, prefix, n);
	}
	free(unique_values);
}

/* Output the string to integer mapping table as a transtab[].
   values must be sorted in the desired order. */
static void
output_i2s_transtab(const char *prefix)
{
	size_t i;
	char *uc_prefix;

	printf("static const struct transtab %s_table[] = {", prefix);
	for (i = 0; i < NUM_VALUES; i++) {
		if (i % 10 == 0)
			fputs("\n\t", stdout);
		printf("{%d,%zu},", values[i].val, values[i].s_offset);
	}
	uc_prefix = strdup(prefix);
	assert(uc_prefix != NULL);
	for (i = 0; uc_prefix[i] != '\0'; i++)
		uc_prefix[i] = toupper((unsigned char)uc_prefix[i]);
	printf("\n"
	       "};\n"
	       "#define %s_NUM_ENTRIES "
	       "(sizeof(%s_table) / sizeof(*%s_table))\n", uc_prefix, prefix,
	       prefix);
	free(uc_prefix);
}

int
main(int argc, char **argv)
{
	bool gen_i2s, gen_i2s_transtab, gen_s2i, uppercase, lowercase;
	char *prefix;
	size_t i;

	/* This is required by gen_tables.h */
	assert(NUM_VALUES <= (SSIZE_MAX / 2 + 1));

	/* To make sure GT_ISUPPER and GT_ISLOWER work. */
	assert('Z' == 'A' + 25 && 'z' == 'a' + 25);
	gen_i2s = false;
	gen_i2s_transtab = false;
	gen_s2i = false;
	uppercase = false;
	lowercase = false;
	prefix = NULL;
	assert (argc > 1);
	for (i = 1; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "--i2s") == 0)
			gen_i2s = true;
		else if (strcmp(argv[i], "--i2s-transtab") == 0)
			gen_i2s_transtab = true;
		else if (strcmp(argv[i], "--s2i") == 0)
			gen_s2i = true;
		else if (strcmp(argv[i], "--uppercase") == 0)
			uppercase = true;
		else if (strcmp(argv[i], "--lowercase") == 0)
			lowercase = true;
		else if (strcmp(argv[i], "--duplicate-ints") == 0)
			allow_duplicate_ints = true;
		else {
			assert(*argv[i] != '-');
			assert(prefix == NULL);
			prefix = argv[i];
		}
	}
	assert(prefix != NULL);
	assert(!(uppercase && lowercase));

	printf("/* This is a generated file, see Makefile.am for its "
	       "inputs. */\n");
	for (i = 0; i < NUM_VALUES; i++)
		values[i].orig_index = i;
	qsort(values, NUM_VALUES, sizeof(*values), cmp_value_strings);
	/* FIXME? if (gen_s2i), sort the strings in some other order
	   (e.g. "first 4 nodes in BFS of the bsearch tree first") to use the
	   cache better. */
	/* FIXME? If the only thing generated is a transtab, keep the strings
	   in the original order to use the cache better. */
	output_strings(prefix);
	if (gen_s2i)
		output_s2i(prefix, uppercase, lowercase);
	if (gen_i2s) {
		qsort(values, NUM_VALUES, sizeof(*values), cmp_value_vals);
		output_i2s(prefix);
	}
	if (gen_i2s_transtab) {
		qsort(values, NUM_VALUES, sizeof(*values),
		      cmp_value_orig_index);
		output_i2s_transtab(prefix);
	}
	return EXIT_SUCCESS;
}
