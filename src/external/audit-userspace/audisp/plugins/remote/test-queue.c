/* test-queue.c -- test suite for persistent-queue.c
 * Copyright 2011,2018 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Miloslav Trmač <mitr@redhat.com>
 */

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "queue.h"

#define NUM_ENTRIES 7
/* 3*4096, larger than MAX_AUDIT_MESSAGE_LENGTH.  The same value is used in the
   main audisp-remote code. */
#define ENTRY_SIZE 12288

static char filename[] = "/tmp/tqXXXXXX";
static struct queue *q;

static char *sample_entries[NUM_ENTRIES - 1];
#define NUM_SAMPLE_ENTRIES (sizeof(sample_entries) / sizeof(*sample_entries))

#define die(...) die__(__LINE__, __VA_ARGS__)
static void __attribute__((format (printf, 2, 3)))
die__(int line, const char *message, ...)
{
	va_list ap;

	fprintf(stderr, "test-queue: %d: ", line);
	va_start(ap, message);
	vfprintf(stderr, message, ap);
	va_end(ap);
	putc('\n', stderr);
	abort();
}

#define err(...) err__(__LINE__, __VA_ARGS__)
static void __attribute__((format (printf, 2, 3)))
err__(int line, const char *message, ...)
{
	char *errno_str;
	va_list ap;

	errno_str = strerror(errno);
	fprintf(stderr, "test-queue: %d: ", line);
	va_start(ap, message);
	vfprintf(stderr, message, ap);
	va_end(ap);
	fprintf(stderr, ": (%d) %s\n", errno, errno_str);
	abort();
}

static void
init_sample_entries(void)
{
	size_t i;

	for (i = 0; i < NUM_SAMPLE_ENTRIES; i++) {
		char *e;
		size_t j, len;

		len = rand() % ENTRY_SIZE;
		e = malloc(len + 1);
		if (e == NULL)
			err("malloc");
		for (j = 0; j < len; j++)
			e[j] = rand() % CHAR_MAX + 1;
		e[j] = '\0';
		sample_entries[i] = e;
	}
}

static void
free_sample_entries(void)
{
	size_t i;

	for (i = 0; i < NUM_SAMPLE_ENTRIES; i++)
		free(sample_entries[i]);
}

static void
test_q_open(void)
{
	struct queue *q2;

	/* Test that flags are honored */
	q2 = q_open(Q_IN_FILE | Q_CREAT | Q_EXCL, filename, NUM_ENTRIES,
		    ENTRY_SIZE);
	if (q2 != NULL)
		die("q_open didn't fail");
	if (errno != EEXIST)
		err("q_open");

	/* Test that locking is enforced.  Use a separate process because
	   fcntl()/lockf() locking is attached to processes, not file
	   descriptors. */
	fflush(NULL);
	switch (fork()) {
	case -1:
		err("fork");
	case 0:
		q2 = q_open(Q_IN_FILE, filename, NUM_ENTRIES, ENTRY_SIZE);
		if (q2 != NULL)
			die("q_open didn't fail");
		if (errno != EBUSY)
			err("q_open");
		_exit(0);
	default: {
		int status;

		if (wait(&status) == (pid_t)-1)
			err("wait");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			die("wait status %d", status);
	}
	}
}

static void
test_empty_q (void)
{
	char buf[ENTRY_SIZE];

	if (q_peek(q, buf, sizeof(buf)) != 0)
		die("q_peek reports non-empty");

	if (q_drop_head(q) != -1)
		die("q_drop_head didn't fail");
	if (errno != EINVAL)
		err("q_drop_head");

	if (q_queue_length(q) != 0)
		die("Unexpected q_queue_length");
}

static void
test_basic_data (void)
{
	char buf[ENTRY_SIZE + 1];
	int i;

	if (q_append(q, " ") != 0)
		die("q_append");

	memset (buf, 'A', ENTRY_SIZE);
	buf[ENTRY_SIZE] = '\0';
	if (q_append(q, buf) != -1)
		die("q_append didn't fail");
	if (errno != EINVAL)
		err("q_append");

	buf[ENTRY_SIZE - 1] = '\0';
	if (q_append(q, buf) != 0)
		die("q_append");

	if (q_queue_length(q) != 2)
		die("Unexpected q_queue_length");

	if (q_peek(q, buf, sizeof(buf)) < 1)
		err("q_peek");
	if (strcmp(buf, " ") != 0)
		die("invalid data returned");
	if (q_drop_head(q) != 0)
		err("q_drop_head");

	if (q_peek(q, buf, ENTRY_SIZE - 1) != -1)
		err("q_peek didn't fail");
	if (errno != ERANGE)
		err("q_peek");
	for (i = 0; i < 2; i++) {
		size_t j;

		if (q_peek(q, buf, sizeof(buf)) < 1)
			err("q_peek");
		for (j = 0; j < ENTRY_SIZE - 1; j++) {
			if (buf[j] != 'A')
				die("invalid data at %zu", j);
		}
		if (buf[j] != '\0')
			die("invalid data at %zu", j);
	}
	if (q_drop_head(q) != 0)
		err("q_drop_head");

	if (q_queue_length(q) != 0)
		die("Unexpected q_queue_length");
}

static void
append_sample_entries(size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (q_append(q, sample_entries[i % NUM_SAMPLE_ENTRIES]) != 0)
			die("q_append %zu", i);
	}
}

static void
verify_sample_entries(size_t count)
{
	char buf[ENTRY_SIZE + 1];
	size_t i;

	if (q_queue_length(q) != count)
		die("Unexpected q_queue_length");
	for (i = 0; i < count; i++) {
		if (q_peek(q, buf, sizeof(buf)) < 1)
			err("q_peek %zu", i);
		if (strcmp(buf, sample_entries[i % NUM_SAMPLE_ENTRIES]) != 0)
			die("invalid data %zu", i);
		if (q_drop_head(q) != 0)
			err("q_drop_head");
	}
	if (q_peek(q, buf, sizeof(buf)) != 0)
		die("q_peek reports non-empty");
}

static void
test_run(int flags)
{
	size_t j;

	q = q_open(flags | Q_CREAT | Q_EXCL, filename, NUM_ENTRIES, ENTRY_SIZE);
	if (q == NULL)
		err("q_open");

	if ((flags & Q_IN_FILE) != 0)
		test_q_open();

	/* Do this enough times to get a wraparound */
	for (j = 0; j < NUM_ENTRIES; j++) {
		test_empty_q();
		test_basic_data();
	}

	append_sample_entries(NUM_ENTRIES - 1);
	if (q_queue_length(q) != NUM_ENTRIES - 1)
		die("Unexpected q_queue_length");

	q_close(q);

	q = q_open(flags, filename, NUM_ENTRIES, ENTRY_SIZE);
	if (q == NULL)
		err("q_open");
	if ((flags & Q_IN_FILE) != 0)
		/* Test that the queue can be reopened and data has been
		   preserved. */
		verify_sample_entries(NUM_ENTRIES - 1);
	else
		/* Test that a new in-memory queue is empty. */
		verify_sample_entries(0);
	q_close(q);

	if ((flags & Q_IN_FILE) != 0 && unlink(filename) != 0)
		err("unlink");
}

static void
test_resizing(void)
{
	q = q_open(Q_IN_FILE | Q_CREAT | Q_EXCL, filename, NUM_ENTRIES,
		   ENTRY_SIZE);
	if (q == NULL)
		err("q_open");

	append_sample_entries(NUM_ENTRIES);
	if (q_queue_length(q) != NUM_ENTRIES)
		die("Unexpected q_queue_length");

	q_close(q);

	/* Verify num_entries is validated */
	q = q_open(Q_IN_FILE, filename, NUM_ENTRIES + 1, ENTRY_SIZE);
	if (q != NULL)
		die("q_open didn't fail");
	if (errno != EINVAL)
		err("q_open");
	q = q_open(Q_IN_FILE, filename, NUM_ENTRIES - 1, ENTRY_SIZE);
	if (q != NULL)
		die("q_open didn't fail");
	if (errno != EINVAL)
		err("q_open");

	/* Test increasing size */
	q = q_open(Q_IN_FILE | Q_RESIZE, filename, 2 * NUM_ENTRIES, ENTRY_SIZE);
	if (q == NULL)
		err("q_open");
	verify_sample_entries(NUM_ENTRIES);

	append_sample_entries(NUM_ENTRIES);
	q_close(q);

	/* Test decreasing size */
	q = q_open(Q_IN_FILE | Q_RESIZE, filename, NUM_ENTRIES / 2, ENTRY_SIZE);
	if (q != NULL)
		die("q_open didn't fail");
	if (errno != ENOSPC)
		err("q_open");
	q = q_open(Q_IN_FILE | Q_RESIZE, filename, NUM_ENTRIES, ENTRY_SIZE);
	if (q == NULL)
		err("q_open");
	verify_sample_entries(NUM_ENTRIES);
	q_close(q);

	if (unlink(filename) != 0)
		err("unlink");
}

int
main(void)
{
	static const int flags[] = {
		Q_IN_MEMORY,
		Q_IN_FILE,
		Q_IN_FILE | Q_SYNC,
		Q_IN_MEMORY | Q_IN_FILE
	};

	int fd;
	size_t i;

	init_sample_entries();

	/* We really want tmpnam() here (safe due to the Q_EXCL below), but
	   gcc warns on any use of tmpnam(). */
	fd = mkstemp(filename);
	if (fd == -1)
		err("tmpnam");
	if (close(fd) != 0)
		err("close");
	if (unlink(filename) != 0)
		err("unlink");

	for (i = 0; i < sizeof(flags) / sizeof(*flags); i++)
		test_run(flags[i]);

	test_resizing();

	free_sample_entries();

	return EXIT_SUCCESS;
}
