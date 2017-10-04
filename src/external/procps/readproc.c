/*
 * New Interface to Process Table -- PROCTAB Stream (a la Directory streams)
 * Copyright (C) 1996 Charles L. Blake.
 * Copyright (C) 1998 Michael K. Johnson
 * Copyright 1998-2003 Albert Cahalan
 * May be distributed under the conditions of the
 * GNU Library General Public License; a copy is in COPYING
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "version.h"
#include "readproc.h"
#include "alloc.h"
#include "pwcache.h"
#include "devname.h"
#include "procps.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/dir.h>
#include <sys/types.h>
#include <sys/stat.h>

// sometimes it's easier to do this manually, w/o gcc helping
#ifdef PROF
extern void __cyg_profile_func_enter(void*,void*);
#define ENTER(x) __cyg_profile_func_enter((void*)x,(void*)x)
#define LEAVE(x) __cyg_profile_func_exit((void*)x,(void*)x)
#else
#define ENTER(x)
#define LEAVE(x)
#endif

#ifndef SIGNAL_STRING
// convert hex string to unsigned long long
static unsigned long long unhex(const char *restrict cp){
    unsigned long long ull = 0;
    for(;;){
        char c = *cp++;
        if(unlikely(c<0x30)) break;
        ull = (ull<<4) | (c - (c>0x57) ? 0x57 : 0x30) ;
    }
    return ull;
}
#endif

static int task_dir_missing;

///////////////////////////////////////////////////////////////////////////

typedef struct status_table_struct {
    unsigned char name[7];        // /proc/*/status field name
    unsigned char len;            // name length
#ifdef LABEL_OFFSET
    long offset;                  // jump address offset
#else
    void *addr;
#endif
} status_table_struct;

#ifdef LABEL_OFFSET
#define F(x) {#x, sizeof(#x)-1, (long)(&&case_##x-&&base)},
#else
#define F(x) {#x, sizeof(#x)-1, &&case_##x},
#endif
#define NUL  {"", 0, 0},

// Derived from:
// gperf -7 --language=ANSI-C --key-positions=1,3,4 -C -n -c sml.gperf
//
// Suggested method:
// Grep this file for "case_", then strip those down to the name.
// (leave the colon and newline) So "Pid:\n" and "Threads:\n"
// would be lines in the file. (no quote, no escape, etc.)
//
// Watch out for name size in the status_table_struct (grrr, expanding)
// and the number of entries (we mask with 63 for now). The table
// must be padded out to 64 entries, maybe 128 in the future.

static void status2proc(char *S, proc_t *restrict P, int is_proc){
    long Threads = 0;
    long Tgid = 0;
    long Pid = 0;

  static const unsigned char asso[] =
    {
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 15, 61,
      61, 61, 61, 61, 61, 61, 30,  3,  5,  5,
      61,  5, 61,  8, 61, 61,  3, 61, 10, 61,
       6, 61, 13,  0, 30, 25,  0, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61,  3, 61, 13,
       0,  0, 61, 30, 61, 25, 61, 61, 61,  0,
      61, 61, 61, 61,  5, 61,  0, 61, 61, 61,
       0, 61, 61, 61, 61, 61, 61, 61
    };

    static const status_table_struct table[] = {
      F(VmStk)
      NUL NUL
      F(State)
      NUL
      F(VmExe)
      F(ShdPnd)
      NUL
      F(VmData)
      NUL
      F(Name)
      NUL NUL
      F(VmRSS)
      NUL NUL
      F(VmLck)
      NUL NUL NUL
      F(Gid)
      F(Pid)
      NUL NUL NUL
      F(VmSize)
      NUL NUL
      F(VmLib)
      NUL NUL
      F(PPid)
      NUL
      F(SigCgt)
      NUL
      F(Threads)
      F(SigPnd)
      NUL
      F(SigIgn)
      NUL
      F(Uid)
      NUL NUL NUL NUL NUL NUL NUL NUL NUL
      NUL NUL NUL NUL NUL
      F(Tgid)
      NUL NUL NUL NUL
      F(SigBlk)
      NUL NUL NUL
    };

#undef F
#undef NUL

ENTER(0x220);

    P->vm_size = 0;
    P->vm_lock = 0;
    P->vm_rss  = 0;
    P->vm_data = 0;
    P->vm_stack= 0;
    P->vm_exe  = 0;
    P->vm_lib  = 0;
    P->nlwp    = 0;
    P->signal[0] = '\0';  // so we can detect it as missing for very old kernels

    goto base;

    for(;;){
        char *colon;
        status_table_struct entry;

        // advance to next line
        S = strchr(S, '\n');
        if(unlikely(!S)) break;  // if no newline
        S++;

        // examine a field name (hash and compare)
    base:
        if(unlikely(!*S)) break;
        entry = table[63 & (asso[S[3]] + asso[S[2]] + asso[S[0]])];
        colon = strchr(S, ':');
        if(unlikely(!colon)) break;
        if(unlikely(colon[1]!='\t')) break;
        if(unlikely(colon-S != entry.len)) continue;
        if(unlikely(memcmp(entry.name,S,colon-S))) continue;

        S = colon+2; // past the '\t'

#ifdef LABEL_OFFSET
        goto *(&&base + entry.offset);
#else
        goto *entry.addr;
#endif

    case_Name:{
        unsigned u = 0;
        while(u < sizeof P->cmd - 1u){
            int c = *S++;
            if(unlikely(c=='\n')) break;
            if(unlikely(c=='\0')) break; // should never happen
            if(unlikely(c=='\\')){
                c = *S++;
                if(c=='\n') break; // should never happen
                if(!c)      break; // should never happen
                if(c=='n') c='\n'; // else we assume it is '\\'
            }
            P->cmd[u++] = c;
        }
        P->cmd[u] = '\0';
        S--;   // put back the '\n' or '\0'
        continue;
    }
#ifdef SIGNAL_STRING
    case_ShdPnd:
        memcpy(P->signal, S, 16);
        P->signal[16] = '\0';
        continue;
    case_SigBlk:
        memcpy(P->blocked, S, 16);
        P->blocked[16] = '\0';
        continue;
    case_SigCgt:
        memcpy(P->sigcatch, S, 16);
        P->sigcatch[16] = '\0';
        continue;
    case_SigIgn:
        memcpy(P->sigignore, S, 16);
        P->sigignore[16] = '\0';
        continue;
    case_SigPnd:
        memcpy(P->_sigpnd, S, 16);
        P->_sigpnd[16] = '\0';
        continue;
#else
    case_ShdPnd:
        P->signal = unhex(S);
        continue;
    case_SigBlk:
        P->blocked = unhex(S);
        continue;
    case_SigCgt:
        P->sigcatch = unhex(S);
        continue;
    case_SigIgn:
        P->sigignore = unhex(S);
        continue;
    case_SigPnd:
        P->_sigpnd = unhex(S);
        continue;
#endif
    case_State:
        P->state = *S;
        continue;
    case_Tgid:
        Tgid = strtol(S,&S,10);
        continue;
    case_Pid:
        Pid = strtol(S,&S,10);
        continue;
    case_PPid:
        P->ppid = strtol(S,&S,10);
        continue;
    case_Threads:
        Threads = strtol(S,&S,10);
        continue;
    case_Uid:
        P->ruid = strtol(S,&S,10);
        P->euid = strtol(S,&S,10);
        P->suid = strtol(S,&S,10);
        P->fuid = strtol(S,&S,10);
        continue;
    case_Gid:
        P->rgid = strtol(S,&S,10);
        P->egid = strtol(S,&S,10);
        P->sgid = strtol(S,&S,10);
        P->fgid = strtol(S,&S,10);
        continue;
    case_VmData:
        P->vm_data = strtol(S,&S,10);
        continue;
    case_VmExe:
        P->vm_exe = strtol(S,&S,10);
        continue;
    case_VmLck:
        P->vm_lock = strtol(S,&S,10);
        continue;
    case_VmLib:
        P->vm_lib = strtol(S,&S,10);
        continue;
    case_VmRSS:
        P->vm_rss = strtol(S,&S,10);
        continue;
    case_VmSize:
        P->vm_size = strtol(S,&S,10);
        continue;
    case_VmStk:
        P->vm_stack = strtol(S,&S,10);
        continue;
    }

#if 0
    // recent kernels supply per-tgid pending signals
    if(is_proc && *ShdPnd){
	memcpy(P->signal, ShdPnd, 16);
	P->signal[16] = '\0';
    }
#endif

    // recent kernels supply per-tgid pending signals
#ifdef SIGNAL_STRING
    if(!is_proc || !P->signal[0]){
	memcpy(P->signal, P->_sigpnd, 16);
	P->signal[16] = '\0';
    }
#else
    if(!is_proc || !have_process_pending){
	P->signal = P->_sigpnd;
    }
#endif

    // Linux 2.4.13-pre1 to max 2.4.xx have a useless "Tgid"
    // that is not initialized for built-in kernel tasks.
    // Only 2.6.0 and above have "Threads" (nlwp) info.

    if(Threads){
       P->nlwp = Threads;
       P->tgid = Tgid;     // the POSIX PID value
       P->tid  = Pid;      // the thread ID
    }else{
       P->nlwp = 1;
       P->tgid = Pid;
       P->tid  = Pid;
    }

LEAVE(0x220);
}

///////////////////////////////////////////////////////////////////////

// Reads /proc/*/stat files, being careful not to trip over processes with
// names like ":-) 1 2 3 4 5 6".
static void stat2proc(const char* S, proc_t *restrict P) {
    unsigned num;
    char* tmp;

ENTER(0x160);

    /* fill in default values for older kernels */
    P->processor = 0;
    P->rtprio = -1;
    P->sched = -1;
    P->nlwp = 0;

    S = strchr(S, '(') + 1;
    tmp = strrchr(S, ')');
    num = tmp - S;
    if(unlikely(num >= sizeof P->cmd)) num = sizeof P->cmd - 1;
    memcpy(P->cmd, S, num);
    P->cmd[num] = '\0';
    S = tmp + 2;                 // skip ") "

    num = sscanf(S,
       "%c "
       "%d %d %d %d %d "
       "%lu %lu %lu %lu %lu "
       "%Lu %Lu %Lu %Lu "  /* utime stime cutime cstime */
       "%ld %ld "
       "%d "
       "%ld "
       "%Lu "  /* start_time */
       "%lu "
       "%ld "
       "%lu %"KLF"u %"KLF"u %"KLF"u %"KLF"u %"KLF"u "
       "%*s %*s %*s %*s " /* discard, no RT signals & Linux 2.1 used hex */
       "%"KLF"u %*lu %*lu "
       "%d %d "
       "%lu %lu",
       &P->state,
       &P->ppid, &P->pgrp, &P->session, &P->tty, &P->tpgid,
       &P->flags, &P->min_flt, &P->cmin_flt, &P->maj_flt, &P->cmaj_flt,
       &P->utime, &P->stime, &P->cutime, &P->cstime,
       &P->priority, &P->nice,
       &P->nlwp,
       &P->alarm,
       &P->start_time,
       &P->vsize,
       &P->rss,
       &P->rss_rlim, &P->start_code, &P->end_code, &P->start_stack, &P->kstk_esp, &P->kstk_eip,
/*     P->signal, P->blocked, P->sigignore, P->sigcatch,   */ /* can't use */
       &P->wchan, /* &P->nswap, &P->cnswap, */  /* nswap and cnswap dead for 2.4.xx and up */
/* -- Linux 2.0.35 ends here -- */
       &P->exit_signal, &P->processor,  /* 2.2.1 ends with "exit_signal" */
/* -- Linux 2.2.8 to 2.5.17 end here -- */
       &P->rtprio, &P->sched  /* both added to 2.5.18 */
    );

    if(!P->nlwp){
      P->nlwp = 1;
    }

LEAVE(0x160);
}

/////////////////////////////////////////////////////////////////////////

static void statm2proc(const char* s, proc_t *restrict P) {
    sscanf(s, "%ld %ld %ld %ld %ld %ld %ld",
	   &P->size, &P->resident, &P->share,
	   &P->trs, &P->lrs, &P->drs, &P->dt);
/*    fprintf(stderr, "statm2proc converted %d fields.\n",num); */
}

static int file2str(const char *directory, const char *what, char *ret, int cap) {
    static char filename[80];
    int fd, num_read;

    sprintf(filename, "%s/%s", directory, what);
    fd = open(filename, O_RDONLY, 0);
    if(unlikely(fd==-1)) return -1;
    num_read = read(fd, ret, cap - 1);
    close(fd);
    if(unlikely(num_read<=0)) return -1;
    ret[num_read] = '\0';
    return num_read;
}

static char** file2strvec(const char* directory, const char* what) {
    char buf[2048];	/* read buf bytes at a time */
    char *p, *rbuf = 0, *endbuf, **q, **ret;
    int fd, tot = 0, n, c, end_of_file = 0;
    int align;

    sprintf(buf, "%s/%s", directory, what);
    fd = open(buf, O_RDONLY, 0);
    if(fd==-1) return NULL;

    /* read whole file into a memory buffer, allocating as we go */
    while ((n = read(fd, buf, sizeof buf - 1)) > 0) {
	if (n < (int)(sizeof buf - 1))
	    end_of_file = 1;
	if (n == 0 && rbuf == 0)
	    return NULL;	/* process died between our open and read */
	if (n < 0) {
	    if (rbuf)
		free(rbuf);
	    return NULL;	/* read error */
	}
	if (end_of_file && buf[n-1])		/* last read char not null */
	    buf[n++] = '\0';			/* so append null-terminator */
	rbuf = xrealloc(rbuf, tot + n);		/* allocate more memory */
	memcpy(rbuf + tot, buf, n);		/* copy buffer into it */
	tot += n;				/* increment total byte ctr */
	if (end_of_file)
	    break;
    }
    close(fd);
    if (n <= 0 && !end_of_file) {
	if (rbuf) free(rbuf);
	return NULL;		/* read error */
    }
    endbuf = rbuf + tot;			/* count space for pointers */
    align = (sizeof(char*)-1) - ((tot + sizeof(char*)-1) & (sizeof(char*)-1));
    for (c = 0, p = rbuf; p < endbuf; p++)
    	if (!*p)
	    c += sizeof(char*);
    c += sizeof(char*);				/* one extra for NULL term */

    rbuf = xrealloc(rbuf, tot + c + align);	/* make room for ptrs AT END */
    endbuf = rbuf + tot;			/* addr just past data buf */
    q = ret = (char**) (endbuf+align);		/* ==> free(*ret) to dealloc */
    *q++ = p = rbuf;				/* point ptrs to the strings */
    endbuf--;					/* do not traverse final NUL */
    while (++p < endbuf)
    	if (!*p)				/* NUL char implies that */
	    *q++ = p+1;				/* next string -> next char */

    *q = 0;					/* null ptr list terminator */
    return ret;
}

// warning: interface may change
int read_cmdline(char *restrict const dst, unsigned sz, unsigned pid){
    char name[32];
    int fd;
    unsigned n = 0;
    dst[0] = '\0';
    snprintf(name, sizeof name, "/proc/%u/cmdline", pid);
    fd = open(name, O_RDONLY);
    if(fd==-1) return 0;
    for(;;){
        ssize_t r = read(fd,dst+n,sz-n);
        if(r==-1){
            if(errno==EINTR) continue;
            break;
        }
        n += r;
        if(n==sz) break; // filled the buffer
        if(r==0) break;  // EOF
    }
    close(fd);
    if(n){
        int i;
        if(n==sz) n--;
        dst[n] = '\0';
        i=n;
        while(i--){
            int c = dst[i];
            if(c<' ' || c>'~') dst[i]=' ';
        }
    }
    return n;
}

/* These are some nice GNU C expression subscope "inline" functions.
 * The can be used with arbitrary types and evaluate their arguments
 * exactly once.
 */

/* Test if item X of type T is present in the 0 terminated list L */
#   define XinL(T, X, L) ( {			\
	    T  x = (X), *l = (L);		\
	    while (*l && *l != x) l++;		\
	    *l == x;				\
	} )

/* Test if item X of type T is present in the list L of length N */
#   define XinLN(T, X, L, N) ( {		\
	    T x = (X), *l = (L);		\
	    int i = 0, n = (N);			\
	    while (i < n && l[i] != x) i++;	\
	    i < n && l[i] == x;			\
	} )

//////////////////////////////////////////////////////////////////////////////////
// This reads process info from /proc in the traditional way, for one process.
// The pid (tgid? tid?) is already in p, and a path to it in path, with some
// room to spare.
static proc_t* simple_readproc(PROCTAB *restrict const PT, proc_t *restrict const p) {
    static struct stat sb;		// stat() buffer
    static char sbuf[1024];	// buffer for stat,statm
    char *restrict const path = PT->path;
    unsigned flags = PT->flags;

    if (unlikely(stat(path, &sb) == -1))	/* no such dirent (anymore) */
	goto next_proc;

    if ((flags & PROC_UID) && !XinLN(uid_t, sb.st_uid, PT->uids, PT->nuid))
	goto next_proc;			/* not one of the requested uids */

    p->euid = sb.st_uid;			/* need a way to get real uid */
    p->egid = sb.st_gid;			/* need a way to get real gid */

    if (flags & PROC_FILLSTAT) {         /* read, parse /proc/#/stat */
	if (unlikely( file2str(path, "stat", sbuf, sizeof sbuf) == -1 ))
	    goto next_proc;			/* error reading /proc/#/stat */
	stat2proc(sbuf, p);				/* parse /proc/#/stat */
    }

    if (unlikely(flags & PROC_FILLMEM)) {	/* read, parse /proc/#/statm */
	if (likely( file2str(path, "statm", sbuf, sizeof sbuf) != -1 ))
	    statm2proc(sbuf, p);		/* ignore statm errors here */
    }						/* statm fields just zero */

    if (flags & PROC_FILLSTATUS) {         /* read, parse /proc/#/status */
       if (likely( file2str(path, "status", sbuf, sizeof sbuf) != -1 )){
           status2proc(sbuf, p, 1);
       }
    }

    // if multithreaded, some values are crap
    if(p->nlwp > 1){
      p->wchan = (KLONG)~0ull;
    }

    /* some number->text resolving which is time consuming and kind of insane */
    if (flags & PROC_FILLUSR){
	memcpy(p->euser,   user_from_uid(p->euid), sizeof p->euser);
        if(flags & PROC_FILLSTATUS) {
            memcpy(p->ruser,   user_from_uid(p->ruid), sizeof p->ruser);
            memcpy(p->suser,   user_from_uid(p->suid), sizeof p->suser);
            memcpy(p->fuser,   user_from_uid(p->fuid), sizeof p->fuser);
        }
    }

    /* some number->text resolving which is time consuming and kind of insane */
    if (flags & PROC_FILLGRP){
        memcpy(p->egroup, group_from_gid(p->egid), sizeof p->egroup);
        if(flags & PROC_FILLSTATUS) {
            memcpy(p->rgroup, group_from_gid(p->rgid), sizeof p->rgroup);
            memcpy(p->sgroup, group_from_gid(p->sgid), sizeof p->sgroup);
            memcpy(p->fgroup, group_from_gid(p->fgid), sizeof p->fgroup);
        }
    }

    if ((flags & PROC_FILLCOM) || (flags & PROC_FILLARG))	/* read+parse /proc/#/cmdline */
	p->cmdline = file2strvec(path, "cmdline");
    else
        p->cmdline = NULL;

    if (unlikely(flags & PROC_FILLENV))			/* read+parse /proc/#/environ */
	p->environ = file2strvec(path, "environ");
    else
        p->environ = NULL;

    return p;
next_proc:
    return NULL;
}

//////////////////////////////////////////////////////////////////////////////////
// This reads /proc/*/task/* data, for one task.
// p is the POSIX process (task group summary) (not needed by THIS implementation)
// t is the POSIX thread (task group member, generally not the leader)
// path is a path to the task, with some room to spare.
static proc_t* simple_readtask(PROCTAB *restrict const PT, const proc_t *restrict const p, proc_t *restrict const t, char *restrict const path) {
    static struct stat sb;		// stat() buffer
    static char sbuf[1024];	// buffer for stat,statm
    unsigned flags = PT->flags;

//printf("hhh\n");
    if (unlikely(stat(path, &sb) == -1))	/* no such dirent (anymore) */
	goto next_task;

//    if ((flags & PROC_UID) && !XinLN(uid_t, sb.st_uid, PT->uids, PT->nuid))
//	goto next_task;			/* not one of the requested uids */

    t->euid = sb.st_uid;			/* need a way to get real uid */
    t->egid = sb.st_gid;			/* need a way to get real gid */

//printf("iii\n");
    if (flags & PROC_FILLSTAT) {         /* read, parse /proc/#/stat */
	if (unlikely( file2str(path, "stat", sbuf, sizeof sbuf) == -1 ))
	    goto next_task;			/* error reading /proc/#/stat */
	stat2proc(sbuf, t);				/* parse /proc/#/stat */
    }

    if (unlikely(flags & PROC_FILLMEM)) {	/* read, parse /proc/#/statm */
#if 0
	if (likely( file2str(path, "statm", sbuf, sizeof sbuf) != -1 ))
	    statm2proc(sbuf, t);		/* ignore statm errors here */
#else
	t->size     = p->size;
	t->resident = p->resident;
	t->share    = p->share;
	t->trs      = p->trs;
	t->lrs      = p->lrs;
	t->drs      = p->drs;
	t->dt       = p->dt;
#endif
    }						/* statm fields just zero */

    if (flags & PROC_FILLSTATUS) {         /* read, parse /proc/#/status */
       if (likely( file2str(path, "status", sbuf, sizeof sbuf) != -1 )){
           status2proc(sbuf, t, 0);
       }
    }

    /* some number->text resolving which is time consuming */
    if (flags & PROC_FILLUSR){
	memcpy(t->euser,   user_from_uid(t->euid), sizeof t->euser);
        if(flags & PROC_FILLSTATUS) {
            memcpy(t->ruser,   user_from_uid(t->ruid), sizeof t->ruser);
            memcpy(t->suser,   user_from_uid(t->suid), sizeof t->suser);
            memcpy(t->fuser,   user_from_uid(t->fuid), sizeof t->fuser);
        }
    }

    /* some number->text resolving which is time consuming */
    if (flags & PROC_FILLGRP){
        memcpy(t->egroup, group_from_gid(t->egid), sizeof t->egroup);
        if(flags & PROC_FILLSTATUS) {
            memcpy(t->rgroup, group_from_gid(t->rgid), sizeof t->rgroup);
            memcpy(t->sgroup, group_from_gid(t->sgid), sizeof t->sgroup);
            memcpy(t->fgroup, group_from_gid(t->fgid), sizeof t->fgroup);
        }
    }

#if 0
    if ((flags & PROC_FILLCOM) || (flags & PROC_FILLARG))	/* read+parse /proc/#/cmdline */
	t->cmdline = file2strvec(path, "cmdline");
    else
        t->cmdline = NULL;

    if (unlikely(flags & PROC_FILLENV))			/* read+parse /proc/#/environ */
	t->environ = file2strvec(path, "environ");
    else
        t->environ = NULL;
#else
    t->cmdline = p->cmdline;  // better not free these until done with all threads!
    t->environ = p->environ;
#endif

    t->ppid = p->ppid;  // ought to put the per-task ppid somewhere

    return t;
next_task:
    return NULL;
}

//////////////////////////////////////////////////////////////////////////////////
// This finds processes in /proc in the traditional way.
// Return non-zero on success.
static int simple_nextpid(PROCTAB *restrict const PT, proc_t *restrict const p) {
  static struct direct *ent;		/* dirent handle */
  char *restrict const path = PT->path;
  for (;;) {
    ent = readdir(PT->procfs);
    if(unlikely(unlikely(!ent) || unlikely(!ent->d_name))) return 0;
    if(likely( likely(*ent->d_name > '0') && likely(*ent->d_name <= '9') )) break;
  }
  p->tgid = strtoul(ent->d_name, NULL, 10);
  p->tid = p->tgid;
  memcpy(path, "/proc/", 6);
  strcpy(path+6, ent->d_name);  // trust /proc to not contain evil top-level entries
  return 1;
}

//////////////////////////////////////////////////////////////////////////////////
// This finds tasks in /proc/*/task/ in the traditional way.
// Return non-zero on success.
static int simple_nexttid(PROCTAB *restrict const PT, const proc_t *restrict const p, proc_t *restrict const t, char *restrict const path) {
  static struct direct *ent;		/* dirent handle */
  if(PT->taskdir_user != p->tgid){
    if(PT->taskdir){
      closedir(PT->taskdir);
    }
    // use "path" as some tmp space
    snprintf(path, PROCPATHLEN, "/proc/%d/task", p->tgid);
    PT->taskdir = opendir(path);
    if(!PT->taskdir) return 0;
    PT->taskdir_user = p->tgid;
  }
  for (;;) {
    ent = readdir(PT->taskdir);
    if(unlikely(unlikely(!ent) || unlikely(!ent->d_name))) return 0;
    if(likely( likely(*ent->d_name > '0') && likely(*ent->d_name <= '9') )) break;
  }
  t->tid = strtoul(ent->d_name, NULL, 10);
  t->tgid = p->tgid;
  t->ppid = p->ppid;  // cover for kernel behavior? we want both actually...?
  snprintf(path, PROCPATHLEN, "/proc/%d/task/%s", p->tgid, ent->d_name);
  return 1;
}

//////////////////////////////////////////////////////////////////////////////////
// This "finds" processes in a list that was given to openproc().
// Return non-zero on success. (tgid was handy)
static int listed_nextpid(PROCTAB *restrict const PT, proc_t *restrict const p) {
  char *restrict const path = PT->path;
  pid_t tgid = *(PT->pids)++;
  if(likely( tgid )){
    snprintf(path, PROCPATHLEN, "/proc/%d", tgid);
    p->tgid = tgid;
    p->tid = tgid;  // they match for leaders
  }
  return tgid;
}

//////////////////////////////////////////////////////////////////////////////////
/* readproc: return a pointer to a proc_t filled with requested info about the
 * next process available matching the restriction set.  If no more such
 * processes are available, return a null pointer (boolean false).  Use the
 * passed buffer instead of allocating space if it is non-NULL.  */

/* This is optimized so that if a PID list is given, only those files are
 * searched for in /proc.  If other lists are given in addition to the PID list,
 * the same logic can follow through as for the no-PID list case.  This is
 * fairly complex, but it does try to not to do any unnecessary work.
 */
proc_t* readproc(PROCTAB *restrict const PT, proc_t *restrict p) {
  proc_t *ret;
  proc_t *saved_p;

  PT->did_fake=0;
//  if (PT->taskdir) {
//    closedir(PT->taskdir);
//    PT->taskdir = NULL;
//    PT->taskdir_user = -1;
//  }

  saved_p = p;
  if(!p) p = xcalloc(p, sizeof *p); /* passed buf or alloced mem */

  for(;;){
    // fills in the path, plus p->tid and p->tgid
    if (unlikely(! PT->finder(PT,p) )) goto out;

    // go read the process data
    ret = PT->reader(PT,p);
    if(ret) return ret;
  }

out:
  if(!saved_p) free(p);
  // FIXME: maybe set tid to -1 here, for "-" in display?
  return NULL;
}

//////////////////////////////////////////////////////////////////////////////////
// readtask: return a pointer to a proc_t filled with requested info about the
// next task available.  If no more such tasks are available, return a null
// pointer (boolean false).  Use the passed buffer instead of allocating
// space if it is non-NULL.
proc_t* readtask(PROCTAB *restrict const PT, const proc_t *restrict const p, proc_t *restrict t) {
  static char path[PROCPATHLEN];       // must hold /proc/2000222000/task/2000222000/cmdline
  proc_t *ret;
  proc_t *saved_t;

  saved_t = t;
  if(!t) t = xcalloc(t, sizeof *t); /* passed buf or alloced mem */

  // 1. got to fake a thread for old kernels
  // 2. for single-threaded processes, this is faster (but must patch up stuff that differs!)
  if(task_dir_missing || p->nlwp < 2){
    if(PT->did_fake) goto out;
    PT->did_fake=1;
    memcpy(t,p,sizeof(proc_t));
    // use the per-task pending, not per-tgid pending
#ifdef SIGNAL_STRING
	memcpy(&t->signal, &t->_sigpnd, sizeof t->signal);
#else
	t->signal = t->_sigpnd;
#endif
    return t;
  }

  for(;;){
    // fills in the path, plus t->tid and t->tgid
    if (unlikely(! PT->taskfinder(PT,p,t,path) )) goto out;  // simple_nexttid

    // go read the task data
    ret = PT->taskreader(PT,p,t,path);          // simple_readtask
    if(ret) return ret;
  }

out:
  if(!saved_t) free(t);
  return NULL;
}

//////////////////////////////////////////////////////////////////////////////////

// initiate a process table scan
PROCTAB* openproc(int flags, ...) {
    va_list ap;
    struct stat sbuf;
    static int did_stat;
    PROCTAB* PT = xmalloc(sizeof(PROCTAB));

    if(!did_stat){
      task_dir_missing = stat("/proc/self/task", &sbuf);
      did_stat = 1;
    }
    PT->taskdir = NULL;
    PT->taskdir_user = -1;
    PT->taskfinder = simple_nexttid;
    PT->taskreader = simple_readtask;

    PT->reader = simple_readproc;
    if (flags & PROC_PID){
      PT->procfs = NULL;
      PT->finder = listed_nextpid;
    }else{
      PT->procfs = opendir("/proc");
      if(!PT->procfs) return NULL;
      PT->finder = simple_nextpid;
    }
    PT->flags = flags;

    va_start(ap, flags);		/*  Init args list */
    if (flags & PROC_PID)
    	PT->pids = va_arg(ap, pid_t*);
    else if (flags & PROC_UID) {
    	PT->uids = va_arg(ap, uid_t*);
	PT->nuid = va_arg(ap, int);
    }
    va_end(ap);				/*  Clean up args list */

    return PT;
}

// terminate a process table scan
void closeproc(PROCTAB* PT) {
    if (PT){
        if (PT->procfs) closedir(PT->procfs);
        if (PT->taskdir) closedir(PT->taskdir);
        memset(PT,'#',sizeof(PROCTAB));
        free(PT);
    }
}

// deallocate the space allocated by readproc if the passed rbuf was NULL
void freeproc(proc_t* p) {
    if (!p)	/* in case p is NULL */
	return;
    /* ptrs are after strings to avoid copying memory when building them. */
    /* so free is called on the address of the address of strvec[0]. */
    if (p->cmdline)
	free((void*)*p->cmdline);
    if (p->environ)
	free((void*)*p->environ);
    free(p);
}


//////////////////////////////////////////////////////////////////////////////////
void look_up_our_self(proc_t *p) {
    char sbuf[1024];

    if(file2str("/proc/self", "stat", sbuf, sizeof sbuf) == -1){
        fprintf(stderr, "Error, do this: mount -t proc none /proc\n");
        _exit(47);
    }
    stat2proc(sbuf, p);    // parse /proc/self/stat
}

HIDDEN_ALIAS(readproc);
HIDDEN_ALIAS(readtask);

/* Convenient wrapper around openproc and readproc to slurp in the whole process
 * table subset satisfying the constraints of flags and the optional PID list.
 * Free allocated memory with exit().  Access via tab[N]->member.  The pointer
 * list is NULL terminated.
 */
proc_t** readproctab(int flags, ...) {
    PROCTAB* PT = NULL;
    proc_t** tab = NULL;
    int n = 0;
    va_list ap;

    va_start(ap, flags);		/* pass through args to openproc */
    if (flags & PROC_UID) {
	/* temporary variables to ensure that va_arg() instances
	 * are called in the right order
	 */
	uid_t* u;
	int i;

	u = va_arg(ap, uid_t*);
	i = va_arg(ap, int);
	PT = openproc(flags, u, i);
    }
    else if (flags & PROC_PID)
	PT = openproc(flags, va_arg(ap, void*)); /* assume ptr sizes same */
    else
	PT = openproc(flags);
    va_end(ap);
    do {					/* read table: */
	tab = xrealloc(tab, (n+1)*sizeof(proc_t*));/* realloc as we go, using */
	tab[n] = readproc_direct(PT, NULL);     /* final null to terminate */
    } while (tab[n++]);				  /* stop when NULL reached */
    closeproc(PT);
    return tab;
}

// Try again, this time with threads and selection.
proc_data_t *readproctab2(int(*want_proc)(proc_t *buf), int(*want_task)(proc_t *buf), PROCTAB *restrict const PT) {
    proc_t** ptab = NULL;
    unsigned n_proc_alloc = 0;
    unsigned n_proc = 0;

    proc_t** ttab = NULL;
    unsigned n_task_alloc = 0;
    unsigned n_task = 0;

    proc_t*  data = NULL;
    unsigned n_alloc = 0;
    unsigned long n_used = 0;

    proc_data_t *pd;

    for(;;){
        proc_t *tmp;
        if(n_alloc == n_used){
          //proc_t *old = data;
          n_alloc = n_alloc*5/4+30;  // grow by over 25%
          data = realloc(data,sizeof(proc_t)*n_alloc);
          //if(!data) return NULL;
        }
        if(n_proc_alloc == n_proc){
          //proc_t **old = ptab;
          n_proc_alloc = n_proc_alloc*5/4+30;  // grow by over 25%
          ptab = realloc(ptab,sizeof(proc_t*)*n_proc_alloc);
          //if(!ptab) return NULL;
        }
        tmp = readproc_direct(PT, data+n_used);
        if(!tmp) break;
        if(!want_proc(tmp)) continue;
        ptab[n_proc++] = (proc_t*)(n_used++);
        if(!(  PT->flags & PROC_LOOSE_TASKS  )) continue;
        for(;;){
          proc_t *t;
          if(n_alloc == n_used){
            proc_t *old = data;
            n_alloc = n_alloc*5/4+30;  // grow by over 25%
            data = realloc(data,sizeof(proc_t)*n_alloc);
	    // have to move tmp too
	    tmp = data+(tmp-old);
            //if(!data) return NULL;
          }
          if(n_task_alloc == n_task){
            //proc_t **old = ttab;
            n_task_alloc = n_task_alloc*5/4+1;  // grow by over 25%
            ttab = realloc(ttab,sizeof(proc_t*)*n_task_alloc);
            //if(!ttab) return NULL;
          }
          t = readtask_direct(PT, tmp, data+n_used);
          if(!t) break;
          if(!want_task(t)) continue;
          ttab[n_task++] = (proc_t*)(n_used++);
        }
    }

    pd = malloc(sizeof(proc_data_t));
    pd->proc = ptab;
    pd->task = ttab;
    pd->nproc = n_proc;
    pd->ntask = n_task;
    if(PT->flags & PROC_LOOSE_TASKS){
      pd->tab = ttab;
      pd->n   = n_task;
    }else{
      pd->tab = ptab;
      pd->n   = n_proc;
    }
    // change array indexes to pointers
    while(n_proc--) ptab[n_proc] = data+(long)(ptab[n_proc]);
    while(n_task--) ttab[n_task] = data+(long)(ttab[n_task]);

    return pd;
}

/*
 * get_proc_stats - lookup a single tasks information and fill out a proc_t
 *
 * On failure, returns NULL.  On success, returns 'p' and 'p' is a valid
 * and filled out proc_t structure.
 */
proc_t * get_proc_stats(pid_t pid, proc_t *p) {
	static char path[PATH_MAX], sbuf[1024];
	struct stat statbuf;

	sprintf(path, "/proc/%d", pid);
	if (stat(path, &statbuf)) {
		perror("stat");
		return NULL;
	}

	if (file2str(path, "stat", sbuf, sizeof sbuf) >= 0)
		stat2proc(sbuf, p);	/* parse /proc/#/stat */
	if (file2str(path, "statm", sbuf, sizeof sbuf) >= 0)
		statm2proc(sbuf, p);	/* ignore statm errors here */
	if (file2str(path, "status", sbuf, sizeof sbuf) >= 0)
		status2proc(sbuf, p, 0 /*FIXME*/);

	return p;
}
