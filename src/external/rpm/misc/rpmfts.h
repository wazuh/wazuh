/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)fts.h	8.3 (Berkeley) 8/14/94
 */

#ifndef	_FTS_H
#define	_FTS_H 1

#include <rpm/rpmutil.h>

#if defined(__GLIBC__)
#include <features.h>
#else

#   define __THROW

#if !defined(_LARGEFILE64_SOURCE)
# define	_LARGEFILE64_SOURCE
#endif

#if !defined(_D_EXACT_NAMLEN)
# define _D_EXACT_NAMLEN(d) (strlen((d)->d_name))
#endif

#if defined(hpux)
# if !defined(_INCLUDE_POSIX_SOURCE)
#  define	_INCLUDE_POSIX_SOURCE
# endif
#endif

#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <dirent.h>

typedef struct {
	struct _ftsent *fts_cur;	/*!< current node */
	struct _ftsent *fts_child;	/*!< linked list of children */
	struct _ftsent **fts_array;	/*!< sort array */
	dev_t fts_dev;			/*!< starting device # */
	char *fts_path;			/*!< path for this descent */
	int fts_rfd;			/*!< fd for root */
	int fts_pathlen;		/*!< sizeof(path) */
	int fts_nitems;			/*!< elements in the sort array */
	int (*fts_compar) (const void *, const void *);			/*!< compare fn */

	DIR * (*fts_opendir) (const char * path);
	struct dirent * (*fts_readdir) (DIR * dir);
	int (*fts_closedir) (DIR * dir);
	int (*fts_stat) (const char * path, struct stat * st);
	int (*fts_lstat) (const char * path, struct stat * st);

#define	FTS_COMFOLLOW	0x0001		/* follow command line symlinks */
#define	FTS_LOGICAL	0x0002		/* logical walk */
#define	FTS_NOCHDIR	0x0004		/* don't change directories */
#define	FTS_NOSTAT	0x0008		/* don't get stat info */
#define	FTS_PHYSICAL	0x0010		/* physical walk */
#define	FTS_SEEDOT	0x0020		/* return dot and dot-dot */
#define	FTS_XDEV	0x0040		/* don't cross devices */
#define FTS_WHITEOUT	0x0080		/* return whiteout information */
#define	FTS_OPTIONMASK	0x00ff		/* valid user option mask */

#define	FTS_NAMEONLY	0x0100		/* (private) child names only */
#define	FTS_STOP	0x0200		/* (private) unrecoverable error */
	int fts_options;		/*!< fts_open options, global flags */
} FTS;

typedef struct _ftsent {
	struct _ftsent *fts_cycle;	/*!< cycle node */
	struct _ftsent *fts_parent;	/*!< parent directory */
	struct _ftsent *fts_link;	/*!< next file in directory */
	long fts_number;	        /*!< local numeric value */
	void *fts_pointer;	        /*!< local address value */
	char *fts_accpath;		/*!< access path */
	char *fts_path;			/*!< root path */
	int fts_errno;			/*!< errno for this node */
	int fts_symfd;			/*!< fd for symlink */
	uint16_t fts_pathlen;		/*!< strlen(fts_path) */
	uint16_t fts_namelen;		/*!< strlen(fts_name) */

	ino_t fts_ino;			/*!< inode */
	dev_t fts_dev;			/*!< device */
	nlink_t fts_nlink;		/*!< link count */

#define	FTS_ROOTPARENTLEVEL	-1
#define	FTS_ROOTLEVEL		 0
	short fts_level;		/*!< depth (-1 to N) */

#define	FTS_D		 1		/* preorder directory */
#define	FTS_DC		 2		/* directory that causes cycles */
#define	FTS_DEFAULT	 3		/* none of the above */
#define	FTS_DNR		 4		/* unreadable directory */
#define	FTS_DOT		 5		/* dot or dot-dot */
#define	FTS_DP		 6		/* postorder directory */
#define	FTS_ERR		 7		/* error; errno is set */
#define	FTS_F		 8		/* regular file */
#define	FTS_INIT	 9		/* initialized only */
#define	FTS_NS		10		/* stat(2) failed */
#define	FTS_NSOK	11		/* no stat(2) requested */
#define	FTS_SL		12		/* symbolic link */
#define	FTS_SLNONE	13		/* symbolic link without target */
#define FTS_W		14		/* whiteout object */
	uint16_t fts_info;		/*!< user flags for FTSENT structure */

#define	FTS_DONTCHDIR	 0x01		/* don't chdir .. to the parent */
#define	FTS_SYMFOLLOW	 0x02		/* followed a symlink to get here */
	uint16_t fts_flags;		/*!< private flags for FTSENT structure */

#define	FTS_AGAIN	 1		/* read node again */
#define	FTS_FOLLOW	 2		/* follow symbolic link */
#define	FTS_NOINSTR	 3		/* no instructions */
#define	FTS_SKIP	 4		/* discard node */
	uint16_t fts_instr;		/*!< fts_set() instructions */

	struct stat *fts_statp;		/*!< stat(2) information */
	char fts_name[1];		/*!< file name */
} FTSENT;

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Return list of children of the current node.
 * @param sp		file hierarchy state
 * @param instr
 * @return		file set member
 */
RPM_GNUC_INTERNAL
FTSENT	*Fts_children (FTS * sp, int instr) __THROW
;

/**
 * Destroy a file hierarchy traversal handle.
 * @param sp		file hierarchy state
 * @return		0 on success, -1 on error
 */
RPM_GNUC_INTERNAL
int	 Fts_close (FTS * sp) __THROW
;

/**
 * Create a handle for file hierarchy traversal.
 * @param argv		paths that compose a logical file hierarchy
 * @param options	traversal options
 * @param compar	traversal ordering (or NULL)
 * @return 		file hierarchy state (or NULL on error)
 */
RPM_GNUC_INTERNAL
FTS	*Fts_open (char * const * argv, int options,
		   int (*compar) (const FTSENT **, const FTSENT **)) __THROW
	;

/**
 * Return next node in the file hierarchy traversal.
 * @param sp		file hierarchy state
 * @return		file set member
 */
RPM_GNUC_INTERNAL
FTSENT	*Fts_read (FTS * sp) __THROW
;

/**
 * Modify the traversal for a file set member.
 * @param sp		file hierarchy state
 * @param p		file set member
 * @param instr		new disposition for file set member
 * @return		0 on success, -1 on error
 */
RPM_GNUC_INTERNAL
int	 Fts_set (FTS * sp, FTSENT * p, int instr) __THROW
;

#ifdef  __cplusplus
}
#endif

#endif /* fts.h */
