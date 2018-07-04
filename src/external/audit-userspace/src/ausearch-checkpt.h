/*
 * ausearch-checkpt.h - ausearch checkpointing feature header file 
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
#ifndef	CHECKPT_HEADER
#define	CHECKPT_HEADER

#include <sys/types.h>
#include "ausearch-llist.h"

int set_ChkPtFileDetails(const char *fn);
int set_ChkPtLastEvent(const event *e);
void free_ChkPtMemory(void);
void save_ChkPt(const char *fn);
int load_ChkPt(const char *fn);

#define	CP_NOMEM	0x0001	/* no memory when creating checkpoint list */
#define	CP_STATFAILED	0x0002	/* stat() call on last log file failed */
#define	CP_STATUSIO	0x0004	/* cannot open/read/write checkpoint file */
#define	CP_STATUSBAD	0x0008	/* malformed status checkpoint entries */
#define	CP_CORRUPTED	0x0010	/* corrupted times in checkpoint file */

extern unsigned checkpt_failure;

extern dev_t	chkpt_input_dev;
extern ino_t	chkpt_input_ino;
extern event	chkpt_input_levent;

#endif	/* CHECKPT_HEADER */
