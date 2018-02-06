#ifndef PROCPS_PROC_READPROC_H
#define PROCPS_PROC_READPROC_H

// New Interface to Process Table -- PROCTAB Stream (a la Directory streams)
// Copyright 1996 Charles L. Blake.
// Copyright 1998 Michael K. Johnson
// Copyright 1998-2003 Albert Cahalan
// May be distributed under the terms of the
// GNU Library General Public License, a copy of which is provided
// in the file COPYING


#include "procps.h"
#include "pwcache.h"

#define SIGNAL_STRING

EXTERN_C_BEGIN

// ld	cutime, cstime, priority, nice, timeout, alarm, rss,
// c	state,
// d	ppid, pgrp, session, tty, tpgid,
// s	signal, blocked, sigignore, sigcatch,
// lu	flags, min_flt, cmin_flt, maj_flt, cmaj_flt, utime, stime,
// lu	rss_rlim, start_code, end_code, start_stack, kstk_esp, kstk_eip,
// lu	start_time, vsize, wchan,

// This is to help document a transition from pid to tgid/tid caused
// by the introduction of thread support. It is used in cases where
// neither tgid nor tid seemed correct. (in other words, FIXME)
#define XXXID tid

// Basic data structure which holds all information we can get about a process.
// (unless otherwise specified, fields are read from /proc/#/stat)
//
// Most of it comes from task_struct in linux/sched.h
//
typedef struct proc_t {
// 1st 16 bytes
    int
        tid,		// (special)       task id, the POSIX thread ID (see also: tgid)
    	ppid;		// stat,status     pid of parent process
    unsigned
        pcpu;           // stat (special)  %CPU usage (is not filled in by readproc!!!)
    char
    	state,		// stat,status     single-char code for process state (S=sleeping)
    	pad_1,		// n/a             padding
    	pad_2,		// n/a             padding
    	pad_3;		// n/a             padding
// 2nd 16 bytes
    unsigned long long
	utime,		// stat            user-mode CPU time accumulated by process
	stime,		// stat            kernel-mode CPU time accumulated by process
// and so on...
	cutime,		// stat            cumulative utime of process and reaped children
	cstime,		// stat            cumulative stime of process and reaped children
	start_time;	// stat            start time of process -- seconds since 1-1-70
#ifdef SIGNAL_STRING
    char
	// Linux 2.1.7x and up have 64 signals. Allow 64, plus '\0' and padding.
	signal[18],	// status          mask of pending signals, per-task for readtask() but per-proc for readproc()
	blocked[18],	// status          mask of blocked signals
	sigignore[18],	// status          mask of ignored signals
	sigcatch[18],	// status          mask of caught  signals
	_sigpnd[18];	// status          mask of PER TASK pending signals
#else
    long long
	// Linux 2.1.7x and up have 64 signals.
	signal,		// status          mask of pending signals, per-task for readtask() but per-proc for readproc()
	blocked,	// status          mask of blocked signals
	sigignore,	// status          mask of ignored signals
	sigcatch,	// status          mask of caught  signals
	_sigpnd;	// status          mask of PER TASK pending signals
#endif
    unsigned KLONG
	start_code,	// stat            address of beginning of code segment
	end_code,	// stat            address of end of code segment
	start_stack,	// stat            address of the bottom of stack for the process
	kstk_esp,	// stat            kernel stack pointer
	kstk_eip,	// stat            kernel instruction pointer
	wchan;		// stat (special)  address of kernel wait channel proc is sleeping in
    long
	priority,	// stat            kernel scheduling priority
	nice,		// stat            standard unix nice level of process
	rss,		// stat            resident set size from /proc/#/stat (pages)
	alarm,		// stat            ?
    // the next 7 members come from /proc/#/statm
	size,		// statm           total # of pages of memory
	resident,	// statm           number of resident set (non-swapped) pages (4k)
	share,		// statm           number of pages of shared (mmap'd) memory
	trs,		// statm           text resident set size
	lrs,		// statm           shared-lib resident set size
	drs,		// statm           data resident set size
	dt;		// statm           dirty pages
    unsigned long
	vm_size,        // status          same as vsize in kb
	vm_lock,        // status          locked pages in kb
	vm_rss,         // status          same as rss in kb
	vm_data,        // status          data size
	vm_stack,       // status          stack size
	vm_exe,         // status          executable size
	vm_lib,         // status          library size (all pages, not just used ones)
	rtprio,		// stat            real-time priority
	sched,		// stat            scheduling class
	vsize,		// stat            number of pages of virtual memory ...
	rss_rlim,	// stat            resident set size limit?
	flags,		// stat            kernel flags for the process
	min_flt,	// stat            number of minor page faults since process start
	maj_flt,	// stat            number of major page faults since process start
	cmin_flt,	// stat            cumulative min_flt of process and child processes
	cmaj_flt;	// stat            cumulative maj_flt of process and child processes
    char
	**environ,	// (special)       environment string vector (/proc/#/environ)
	**cmdline;	// (special)       command line string vector (/proc/#/cmdline)
    char
	// Be compatible: Digital allows 16 and NT allows 14 ???
    	euser[P_G_SZ],	// stat(),status   effective user name
    	ruser[P_G_SZ],	// status          real user name
    	suser[P_G_SZ],	// status          saved user name
    	fuser[P_G_SZ],	// status          filesystem user name
    	rgroup[P_G_SZ],	// status          real group name
    	egroup[P_G_SZ],	// status          effective group name
    	sgroup[P_G_SZ],	// status          saved group name
    	fgroup[P_G_SZ],	// status          filesystem group name
    	cmd[16];	// stat,status     basename of executable file in call to exec(2)
    struct proc_t
	*ring,		// n/a             thread group ring
	*next;		// n/a             various library uses
    int
	pgrp,		// stat            process group id
	session,	// stat            session id
	nlwp,		// stat,status     number of threads, or 0 if no clue
	tgid,		// (special)       task group ID, the POSIX PID (see also: tid)
	tty,		// stat            full device number of controlling terminal
        euid, egid,     // stat(),status   effective
        ruid, rgid,     // status          real
        suid, sgid,     // status          saved
        fuid, fgid,     // status          fs (used for file access only)
	tpgid,		// stat            terminal process group id
	exit_signal,	// stat            might not be SIGCHLD
	processor;      // stat            current (or most recent?) CPU
} proc_t;

// PROCTAB: data structure holding the persistent information readproc needs
// from openproc().  The setup is intentionally similar to the dirent interface
// and other system table interfaces (utmp+wtmp come to mind).

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#define PROCPATHLEN 64  // must hold /proc/2000222000/task/2000222000/cmdline

typedef struct PROCTAB {
    DIR*	procfs;
//    char deBug0[64];
    DIR*	taskdir;  // for threads
//    char deBug1[64];
    pid_t	taskdir_user;  // for threads
    int         did_fake; // used when taskdir is missing
    int(*finder)(struct PROCTAB *restrict const, proc_t *restrict const);
    proc_t*(*reader)(struct PROCTAB *restrict const, proc_t *restrict const);
    int(*taskfinder)(struct PROCTAB *restrict const, const proc_t *restrict const, proc_t *restrict const, char *restrict const);
    proc_t*(*taskreader)(struct PROCTAB *restrict const, const proc_t *restrict const, proc_t *restrict const, char *restrict const);
    pid_t*	pids;	// pids of the procs
    uid_t*	uids;	// uids of procs
    int		nuid;	// cannot really sentinel-terminate unsigned short[]
    int         i;  // generic
    unsigned	flags;
    unsigned    u;  // generic
    void *      vp; // generic
    char        path[PROCPATHLEN];  // must hold /proc/2000222000/task/2000222000/cmdline
    unsigned pathlen;        // length of string in the above (w/o '\0')
} PROCTAB;

// initialize a PROCTAB structure holding needed call-to-call persistent data
extern PROCTAB* openproc(int flags, ... /* pid_t*|uid_t*|dev_t*|char* [, int n] */ );

typedef struct proc_data_t {
    proc_t **tab;
    proc_t **proc;
    proc_t **task;
    int n;
    int nproc;
    int ntask;
} proc_data_t;

extern proc_data_t *readproctab2(int(*want_proc)(proc_t *buf), int(*want_task)(proc_t *buf), PROCTAB *restrict const PT);

// Convenient wrapper around openproc and readproc to slurp in the whole process
// table subset satisfying the constraints of flags and the optional PID list.
// Free allocated memory with exit().  Access via tab[N]->member.  The pointer
// list is NULL terminated.

extern proc_t** readproctab(int flags, ... /* same as openproc */ );

// clean-up open files, etc from the openproc()
extern void closeproc(PROCTAB* PT);

// retrieve the next process matching the criteria set by the openproc()
extern proc_t* readproc(PROCTAB *restrict const PT, proc_t *restrict p);
extern proc_t* readtask(PROCTAB *restrict const PT, const proc_t *restrict const p, proc_t *restrict t);

// warning: interface may change
extern int read_cmdline(char *restrict const dst, unsigned sz, unsigned pid);

extern void look_up_our_self(proc_t *p);

// deallocate space allocated by readproc

extern void freeproc(proc_t* p);

//fill out a proc_t for a single task
extern proc_t * get_proc_stats(pid_t pid, proc_t *p);

// openproc/readproctab:
//
// Return PROCTAB* / *proc_t[] or NULL on error ((probably) "/proc" cannot be
// opened.)  By default readproc will consider all processes as valid to parse
// and return, but not actually fill in the cmdline, environ, and /proc/#/statm
// derived memory fields.
//
// `flags' (a bitwise-or of PROC_* below) modifies the default behavior.  The
// "fill" options will cause more of the proc_t to be filled in.  The "filter"
// options all use the second argument as the pointer to a list of objects:
// process status', process id's, user id's.  The third
// argument is the length of the list (currently only used for lists of user
// id's since uid_t supports no convenient termination sentinel.)

#define PROC_FILLMEM         0x0001 // read statm
#define PROC_FILLCOM         0x0002 // alloc and fill in `cmdline'
#define PROC_FILLENV         0x0004 // alloc and fill in `environ'
#define PROC_FILLUSR         0x0008 // resolve user id number -> user name
#define PROC_FILLGRP         0x0010 // resolve group id number -> group name
#define PROC_FILLSTATUS      0x0020 // read status -- currently unconditional
#define PROC_FILLSTAT        0x0040 // read stat -- currently unconditional
#define PROC_FILLWCHAN       0x0080 // look up WCHAN name
#define PROC_FILLARG         0x0100 // alloc and fill in `cmdline'

#define PROC_LOOSE_TASKS     0x0200 // threat threads as if they were processes

// Obsolete, consider only processes with one of the passed:
#define PROC_PID             0x1000  // process id numbers ( 0   terminated)
#define PROC_UID             0x4000  // user id numbers    ( length needed )

// it helps to give app code a few spare bits
#define PROC_SPARE_1     0x01000000
#define PROC_SPARE_2     0x02000000
#define PROC_SPARE_3     0x04000000
#define PROC_SPARE_4     0x08000000

EXTERN_C_END
#endif
