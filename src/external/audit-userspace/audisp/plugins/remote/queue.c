/* queue.c - a string queue implementation
 * Copyright 2009, 2011 Red Hat Inc., Durham, North Carolina.
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
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "queue.h"

struct queue
{
	int flags;		/* Q_* */
	int fd;			/* -1 if !Q_IN_FILE */
	/* NULL if !Q_IN_MEMORY.  [i] contains a memory copy of the queue entry
	   "i", if known - it may be NULL even if entry exists. */
	unsigned char **memory;
	size_t num_entries;
	size_t entry_size;
	size_t queue_head;
	size_t queue_length;
	unsigned char buffer[];	/* Used only locally within q_peek() */
};

/* Infrastructure */

/* Compile-time expression verification */
#define verify(E) do {				\
		char verify__[(E) ? 1 : -1];	\
		(void)verify__;			\
	} while (0)

/* Like pread(), except that it handles partial reads, and returns 0 on
   success. */
static int full_pread(int fd, void *buf, size_t size, off_t offset)
{
	while (size != 0) {
		ssize_t run, res;

		if (size > SSIZE_MAX)
			run = SSIZE_MAX;
		else
			run = size;
		res = pread(fd, buf, run, offset);
		if (res < 0)
			return -1;
		if (res == 0) {
			errno = ENXIO; /* Any better value? */
			return -1;
		}
		buf = (unsigned char *)buf + res;
		size -= res;
		offset += res;
	}
	return 0;
}

/* Like pwrite(), except that it handles partial writes, and returns 0 on
   success. */
static int full_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
	while (size != 0) {
		ssize_t run, res;

		if (size > SSIZE_MAX)
			run = SSIZE_MAX;
		else
			run = size;
		res = pwrite(fd, buf, run, offset);
		if (res < 0)
			return -1;
		if (res == 0) {
			errno = ENXIO; /* Any better value? */
			return -1;
		}
		buf = (const unsigned char *)buf + res;
		size -= res;
		offset += res;
	}
	return 0;
}

/* File format and utilities */

/* The mutable part of struct file_header */
struct fh_state {
	uint32_t queue_head;	/* 0-based index of the first non-empty entry */
	uint32_t queue_length;	/* [0, num_entries] */
};

/* All integer values are in network byte order (big endian) */
struct file_header
{
	uint8_t magic[14];	/* See fh_magic below */
	uint8_t version;	/* File format version, see FH_VERSION* below */
	uint8_t reserved;	/* Must be 0 */
	/* Total file size is (num_entries + 1) * entry_size.  This must fit
	   into SIZE_MAX because the "len" parameter of posix_fallocate has
	   a size_t type. */
	uint32_t num_entries;	/* Total number of entries allocated */
	uint32_t entry_size;
	struct fh_state s;
};

/* Contains a '\0' byte to unambiguously mark the file as a binary file. */
static const uint8_t fh_magic[14] = "\0audisp-remote";
#define FH_VERSION_0 0x00

/* Return file position for ENTRY in Q */
static size_t entry_offset (const struct queue *q, size_t entry)
{
	return (entry + 1) * q->entry_size;
}

/* Synchronize Q if required and return 0.
   On error, return -1 and set errno. */
static int q_sync(struct queue *q)
{
	if ((q->flags & Q_SYNC) == 0)
		return 0;
	return fdatasync(q->fd);
}

/* Sync file's fh_state with Q, q_sync (Q), and return 0.
   On error, return -1 and set errno. */
static int sync_fh_state (struct queue *q)
{
	struct fh_state s;

	if (q->fd == -1)
		return 0;

	s.queue_head = htonl(q->queue_head);
	s.queue_length = htonl(q->queue_length);
	if (full_pwrite(q->fd, &s, sizeof(s), offsetof(struct file_header, s))
	    != 0)
		return -1;
	return q_sync(q);
}

/* Queue implementation */

/* Open PATH for Q, update Q from it, and return 0.
   On error, return -1 and set errno; Q->fd may be set even on error. */
static int q_open_file(struct queue *q, const char *path)
{
	int open_flags, fd_flags;
	struct stat st;
	struct file_header fh;

	open_flags = O_RDWR;
	if ((q->flags & Q_CREAT) != 0)
		open_flags |= O_CREAT;
	if ((q->flags & Q_EXCL) != 0)
		open_flags |= O_EXCL;
	q->fd = open(path, open_flags, S_IRUSR | S_IWUSR);
	if (q->fd == -1)
		return -1;

	fd_flags = fcntl(q->fd, F_GETFD);
	if (fd_flags < 0)
		return -1;
	if (fcntl(q->fd, F_SETFD, fd_flags | FD_CLOEXEC) == -1)
		return -1;

	/* File locking in POSIX is pretty much broken... let's hope nobody
	   attempts to open a single file twice within the same process.
	   open() above has initialized the file offset to 0, so the lockf()
	   below affects the whole file. */
	if (lockf(q->fd, F_TLOCK, 0) != 0) {
		if (errno == EACCES || errno == EAGAIN)
			errno = EBUSY; /* This makes more sense... */
		return -1;
	}

	if (fstat(q->fd, &st) != 0)
		return -1;
	if (st.st_size == 0) {
		verify(sizeof(fh.magic) == sizeof(fh_magic));
		memcpy(fh.magic, fh_magic, sizeof(fh.magic));
		fh.version = FH_VERSION_0;
		fh.reserved = 0;
		fh.num_entries = htonl(q->num_entries);
		fh.entry_size = htonl(q->entry_size);
		fh.s.queue_head = htonl(0);
		fh.s.queue_length = htonl(0);
		if (full_pwrite(q->fd, &fh, sizeof(fh), 0) != 0)
			return -1;
		if (q_sync(q) != 0)
			return -1;
#ifdef HAVE_POSIX_FALLOCATE
		if (posix_fallocate(q->fd, 0,
				    (q->num_entries + 1) * q->entry_size) != 0)
			return -1;
#endif
	} else {
		uint32_t file_entries;
		if (full_pread(q->fd, &fh, sizeof(fh), 0) != 0)
			return -1;
		if (memcmp(fh.magic, fh_magic, sizeof(fh.magic)) != 0
		    || fh.version != FH_VERSION_0 || fh.reserved != 0
		    || fh.entry_size != htonl(q->entry_size)) {
			errno = EINVAL;
			return -1;
		}
		file_entries = ntohl(fh.num_entries);
		if (file_entries > SIZE_MAX / q->entry_size - 1
		    || ((uintmax_t)st.st_size
			!= (file_entries + 1) * q->entry_size)) {
			errno = EINVAL;
			return -1;
		}
	}
	/* Note that this may change q->num_entries! */
	q->num_entries = ntohl(fh.num_entries);
	q->queue_head = ntohl(fh.s.queue_head);
	q->queue_length = ntohl(fh.s.queue_length);
	if (q->queue_head >= q->num_entries
	    || q->queue_length > q->num_entries) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/* Like q_open(), but does not handle Q_RESIZE, and NUM_ENTRIES is only used
   when creating a new file. */
static struct queue *q_open_no_resize(int q_flags, const char *path,
				      size_t num_entries, size_t entry_size)
{
	struct queue *q;
	int saved_errno;

	if ((q_flags & (Q_IN_MEMORY | Q_IN_FILE)) == 0) {
		errno = EINVAL;
		return NULL;
	}
	if (num_entries == 0 || num_entries > UINT32_MAX
	    || entry_size < 1 /* for trailing NUL */
	    || entry_size < sizeof(struct file_header) /* for Q_IN_FILE */
	    /* to allocate "struct queue" including its buffer*/
	    || entry_size > UINT32_MAX - sizeof(struct queue)) {
		errno = EINVAL;
		return NULL;
	}
	if (entry_size > SIZE_MAX
	    || num_entries > SIZE_MAX / entry_size - 1 /* for Q_IN_FILE */
	    || num_entries > SIZE_MAX / sizeof(*q->memory)) {
		errno = EINVAL;
		return NULL;
	}

	q = malloc(sizeof(*q) + entry_size);
	if (q == NULL)
		return NULL;
	q->flags = q_flags;
	q->fd = -1;
	q->memory = NULL;
	q->num_entries = num_entries;
	q->entry_size = entry_size;
	q->queue_head = 0;
	q->queue_length = 0;

	if ((q_flags & Q_IN_MEMORY) != 0) {
		size_t sz = num_entries * sizeof(*q->memory);

		q->memory = malloc(sz);
		if (q->memory == NULL)
			goto err;
		memset(q->memory, 0, sz);
	}

	if ((q_flags & Q_IN_FILE) != 0 && q_open_file(q, path) != 0)
		goto err;

	return q;

err:
	saved_errno = errno;
	if (q->fd != -1)
		close(q->fd);
	free(q->memory);
	free(q);
	errno = saved_errno;
	return NULL;
}

void q_close(struct queue *q)
{
	if (q->fd != -1)
		close(q->fd); /* Also releases the file lock */
	if (q->memory != NULL) {
		size_t i;

		for (i = 0; i < q->num_entries; i++)
			free(q->memory[i]);
		free(q->memory);
	}
	free(q);
}

/* Internal use only: add DATA to Q, but don't update fh_state. */
static int q_append_no_sync_fh_state(struct queue *q, const char *data)
{
	size_t data_size, entry_index;
	unsigned char *copy;

	if (q->queue_length == q->num_entries) {
		errno = ENOSPC;
		return -1;
	}

	data_size = strlen(data) + 1;
	if (data_size > q->entry_size) {
		errno = EINVAL;
		return -1;
	}

	entry_index = (q->queue_head + q->queue_length) % q->num_entries;
	if (q->memory != NULL) {
		if (q->memory[entry_index] != NULL) {
			errno = EIO; /* This is _really_ unexpected. */
			return -1;
		}
		copy = malloc(data_size);
		if (copy == NULL)
			return -1;
		memcpy(copy, data, data_size);
	} else
		copy = NULL;

	if (q->fd != -1) {
		size_t offset;

		offset = entry_offset(q, entry_index);
		if (full_pwrite(q->fd, data, data_size, offset) != 0) {
			int saved_errno;

			saved_errno = errno;
			if (copy != NULL)
				free(copy);
			errno = saved_errno;
			return -1;
		}
	}

	if (copy != NULL)
		q->memory[entry_index] = copy;

	q->queue_length++;

	return 0;
}

int q_append(struct queue *q, const char *data)
{
	int r;

	r = q_append_no_sync_fh_state(q, data);
	if (r != 0)
		return r;

	return sync_fh_state(q); /* Calls q_sync() */
}

int q_peek(struct queue *q, char *buf, size_t size)
{
	const unsigned char *data;
	size_t data_size;

	if (q->queue_length == 0)
		return 0;

	if (q->memory != NULL && q->memory[q->queue_head] != NULL) {
		data = q->memory[q->queue_head];
		data_size = strlen((char *)data) + 1;
	} else if (q->fd != -1) {
		const unsigned char *end;

		if (full_pread(q->fd, q->buffer, q->entry_size,
			       entry_offset(q, q->queue_head)) != 0)
			return -1;
		data = q->buffer;
		end = memchr(q->buffer, '\0', q->entry_size);
		if (end == NULL) {
			/* FIXME: silently drop this entry? */
			errno = EBADMSG;
			return -1;
		}
		data_size = (end - data) + 1;

		if (q->memory != NULL) {
			unsigned char *copy;

			copy = malloc(data_size);
			if (copy != NULL) { /* Silently ignore failures. */
				memcpy(copy, data, data_size);
				q->memory[q->queue_head] = copy;
			}
		}
	} else {
		errno = EIO; /* This is _really_ unexpected. */
		return -1;
	}

	if (size < data_size) {
		errno = ERANGE;
		return -1;
	}
	memcpy(buf, data, data_size);
	return data_size;
}

/* Internal use only: drop head of Q, but don't write this into the file */
static int q_drop_head_memory_only(struct queue *q)
{
	if (q->queue_length == 0) {
		errno = EINVAL;
		return -1;
	}

	if (q->memory != NULL) {
		free(q->memory[q->queue_head]);
		q->memory[q->queue_head] = NULL;
	}

	q->queue_head++;
	if (q->queue_head == q->num_entries)
		q->queue_head = 0;
	q->queue_length--;
	return 0;
}

int q_drop_head(struct queue *q)
{
	int r;

	r = q_drop_head_memory_only(q);
	if (r != 0)
		return r;

	return sync_fh_state(q); /* Calls q_sync() */
}

size_t q_queue_length(const struct queue *q)
{
	return q->queue_length;
}

struct queue *q_open(int q_flags, const char *path, size_t num_entries,
		     size_t entry_size)
{
	struct queue *q, *q2;
	char *tmp_path, *buf;
	size_t path_len;
	int saved_errno, fd;

	q = q_open_no_resize(q_flags, path, num_entries, entry_size);
	if (q == NULL || q->num_entries == num_entries)
		return q;

	if ((q->flags & Q_RESIZE) == 0) {
		saved_errno = EINVAL;
		goto err_errno_q;
	}

	if (q->queue_length > num_entries) {
		saved_errno = ENOSPC;
		goto err_errno_q;
	}

	buf = malloc(entry_size);
	if (buf == NULL) {
		saved_errno = errno;
		goto err_errno_q;
	}

	path_len = strlen(path);
	tmp_path = malloc(path_len + 7);
	if (tmp_path == NULL) {
		saved_errno = errno;
		goto err_errno_buf;
	}
	memcpy(tmp_path, path, path_len);
	memcpy(tmp_path + path_len, "XXXXXX", 7);
	/* We really want tmpnam() here (safe due to the Q_EXCL below), but gcc
	   warns on any use of tmpnam(). */
	fd = mkstemp(tmp_path);
	if (fd == -1) {
		saved_errno = errno;
		goto err_errno_tmp_path;
	}
	if (close(fd) != 0 || unlink(tmp_path) != 0) {
		saved_errno = errno;
		goto err_errno_tmp_file;
	}

	q2 = q_open_no_resize(q_flags | Q_CREAT | Q_EXCL, tmp_path, num_entries,
			      entry_size);
	if (q2 == NULL) {
		saved_errno = errno;
		goto err_errno_tmp_file;
	}
	if (q2->num_entries != num_entries) {
		errno = EIO;	/* This is _really_ unexpected. */
		goto err_q2;
	}

	for (;;) {
		int r;

		r = q_peek(q, buf, entry_size);
		if (r == 0)
			break;
		if (r < 0)
			goto err_q2;

		if (q_append_no_sync_fh_state(q2, buf) != 0)
			goto err_q2;
		if (q_drop_head_memory_only(q) != 0)
			goto err_q2;
	}
	if (sync_fh_state(q2) != 0)
		goto err_q2;

	if (rename(tmp_path, path) != 0)
		goto err_q2;

	q_close(q);
	free(buf);
	free(tmp_path);
	return q2;

err_q2:
	saved_errno = errno;
	q_close(q2);
err_errno_tmp_file:
	unlink(tmp_path);
err_errno_tmp_path:
	free(tmp_path);
err_errno_buf:
	free(buf);
err_errno_q:
	q_close(q);
	errno = saved_errno;
	return NULL;
}
