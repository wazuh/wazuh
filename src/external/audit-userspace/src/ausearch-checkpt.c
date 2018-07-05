/*
 * ausearch-checkpt.c - ausearch checkpointing feature
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
 */
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "ausearch-checkpt.h"

#define	DBG	0	/* set to non-zero for debug */

/* Remember why we failed */
unsigned checkpt_failure = 0;

/*
 * Remember the file we were processing when we had incomplete events.
 * We remember this via it's dev and inode
 */
static dev_t checkpt_dev = (dev_t)NULL;
static ino_t checkpt_ino = (ino_t)NULL;

/* Remember the last event output */
static event last_event = {0, 0, 0, NULL, 0};

/* Loaded values from a given checkpoint file */
dev_t chkpt_input_dev = (dev_t)NULL;
ino_t chkpt_input_ino = (ino_t)NULL;
event chkpt_input_levent = {0, 0, 0, NULL, 0};

/*
 * Record the dev_t and ino_t of the given file
 *
 * Returns:
 * 1	Failed to get status
 * 0	OK
 */
int set_ChkPtFileDetails(const char *fn)
{
	struct stat sbuf;

	if (stat(fn, &sbuf) != 0) {
		fprintf(stderr, "Cannot stat audit file for checkpoint "
			"details - %s: %s\n", fn, strerror(errno));
		checkpt_failure |= CP_STATFAILED;
		return 1;
	}
	checkpt_dev = sbuf.st_dev;
	checkpt_ino = sbuf.st_ino;

	return 0;
}

/*
 * Save the given event in the last_event record
 * Returns:
 * 1	no memory
 * 0	OK
 */
int set_ChkPtLastEvent(const event *e)
{
	/* Set the event node if necessary */
	if (e->node) {
		if (last_event.node) {
			if (strcmp(e->node, last_event.node) != 0) {
				free((void *)last_event.node);
				last_event.node = strdup(e->node);
			}
		} else
			last_event.node = strdup(e->node);
		if (last_event.node == NULL) {
			fprintf(stderr, "No memory to allocate "
					"checkpoint last event node name\n");
			return 1;
		}
	} else {
		if (last_event.node)
			free((void *)last_event.node);
		last_event.node = NULL;
	}
	last_event.sec = e->sec;
	last_event.milli = e->milli;
	last_event.serial = e->serial;
	last_event.type = e->type;

	return 0;
}

/* Free all checkpoint memory */
void free_ChkPtMemory(void)
{
	if (last_event.node)
		(void)free((void *)last_event.node);
	last_event.node = NULL;
	if (chkpt_input_levent.node)
		(void)free((void *)chkpt_input_levent.node);
	chkpt_input_levent.node = NULL;
}

/*
 * Save the checkpoint to the given file
 * Returns:
 * 1	io error
 * 0	OK
 */
void save_ChkPt(const char *fn)
{
	FILE *fd;

	if ((fd = fopen(fn, "w")) == NULL) {
		fprintf(stderr, "Cannot open checkpoint file - %s: %s\n",
			fn, strerror(errno));
		checkpt_failure |= CP_STATUSIO;
		return;
	}
	// Write the inode in decimal to make ls -i easier to use.
	fprintf(fd, "dev=0x%X\ninode=%u\n",
		(unsigned int)checkpt_dev, (unsigned int)checkpt_ino);
	fprintf(fd, "output=%s %lu.%03u:%lu 0x%X\n",
		last_event.node ? last_event.node : "-",
		(long unsigned int)last_event.sec, last_event.milli,
		last_event.serial, last_event.type);
	fclose(fd);
}

/*
 * Parse a checkpoint file "output=" record
 * Returns
 * 1	failed to parse or no memory
 * 0	parsed OK
 */
static int parse_checkpt_event(char *lbuf, int ndix, event *e)
{
	char *rest;

	/*
 	 * Find the space after the node, then make it '\0' so
 	 * we terminate the node value. We leave 'rest' at the start
 	 * of the event time/serial element
 	 */
	rest = strchr(&lbuf[ndix], ' ');
	if (rest == NULL) {
		fprintf(stderr, "Malformed output/event checkpoint line "
				"near node - [%s]\n", lbuf);
		checkpt_failure |= CP_STATUSBAD;
		return 1;
	}
	*rest++ = '\0';
	
	if (lbuf[ndix] == '-')
		e->node = NULL;
	else {
		e->node = strdup(&lbuf[ndix]);
		if (e->node == NULL) {
			fprintf(stderr, "No memory for node when loading "
					"checkpoint line - [%s]\n", lbuf);
			checkpt_failure |= CP_NOMEM;
			return 1;
		}
	}
	if (sscanf(rest, "%lu.%03u:%lu 0x%X", &e->sec, &e->milli,
						&e->serial, &e->type) != 4) {
		fprintf(stderr, "Malformed output/event checkpoint line "
			"after node - [%s]\n", lbuf);
		checkpt_failure |= CP_STATUSBAD;
		return 1;
	}

	return 0;
}

/*
 * Load the checkpoint from the given file
 * Returns:
 *  < -1	error
 * == -1	no file present
 * == 0		loaded data
 */
int load_ChkPt(const char *fn)
{
#define	MAX_LN	1023
	FILE *fd;
	char lbuf[MAX_LN];

	if ((fd = fopen(fn, "r")) == NULL) {
		if (errno == ENOENT)
			return -1;
		fprintf(stderr, "Cannot open checkpoint file - %s: %s\n",
			fn, strerror(errno));
		return -2;
	}
	chkpt_input_levent.node = NULL;
	while (fgets(lbuf, MAX_LN, fd) != NULL) {
		size_t len = strlen(lbuf);

		if (len && lbuf[len - 1] == '\n')	/* drop the newline */
			lbuf[len - 1] = '\0';

		if (strncmp(lbuf, "dev=", 4) == 0) {
			errno = 0;
			chkpt_input_dev = strtoul(&lbuf[4], NULL, 16);
			if (errno) {
				fprintf(stderr, "Malformed dev checkpoint "
						"line - [%s]\n", lbuf);
				checkpt_failure |= CP_STATUSBAD;
				break;
			}
		} else if (strncmp(lbuf, "inode=", 6) == 0) {
			errno = 0;
			chkpt_input_ino = strtoul(&lbuf[6], NULL, 0);
			if (errno) {
				fprintf(stderr, "Malformed inode checkpoint "
						"line - [%s]\n", lbuf);
				checkpt_failure |= CP_STATUSBAD;
				break;
			}
		} else if (strncmp(lbuf, "output=", 7) == 0) {
			free((void *)chkpt_input_levent.node);
			chkpt_input_levent.node = NULL;
			if (parse_checkpt_event(lbuf, 7, &chkpt_input_levent))
				break;
		} else {
			fprintf(stderr, "Unknown checkpoint line - [%s]\n",
				lbuf);
			checkpt_failure |= CP_STATUSBAD;
			break;
		}
	}
	if (	(chkpt_input_ino == (ino_t)NULL) ||
		(chkpt_input_dev == (dev_t)NULL) ) {
		fprintf(stderr, "Missing dev/inode lines from checkpoint "
				"file %s\n", fn);
		checkpt_failure |= CP_STATUSBAD;
	}
	fclose(fd);

	if (checkpt_failure)
		return -3;

#if	DBG
	{
		fprintf(stderr, "Loaded %s - dev: 0x%X, ino: 0x%X\n",
			fn, chkpt_input_dev, chkpt_input_ino);
		fprintf(stderr, "output:%s %d.%03d:%lu 0x%X\n",
			chkpt_input_levent.node ? chkpt_input_levent.node : "-",
			chkpt_input_levent.sec, chkpt_input_levent.milli,
			chkpt_input_levent.serial, chkpt_input_levent.type);
	}
#endif	/* DBG */
	return 0;
}

