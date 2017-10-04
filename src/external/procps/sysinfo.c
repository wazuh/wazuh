// Copyright (C) 1992-1998 by Michael K. Johnson, johnsonm@redhat.com
// Copyright 1998-2003 Albert Cahalan
//
// This file is placed under the conditions of the GNU Library
// General Public License, version 2, or any later version.
// See file COPYING for information on distribution conditions.
//
// File for parsing top-level /proc entities. */
//
// June 2003, Fabian Frederick, disk and slab info

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>

#include <unistd.h>
#include <fcntl.h>
#include "version.h"
#include "sysinfo.h" /* include self to verify prototypes */

#ifndef HZ
#include <netinet/in.h>  /* htons */
#endif

long smp_num_cpus;     /* number of CPUs */

#define BAD_OPEN_MESSAGE					\
"Error: /proc must be mounted\n"				\
"  To mount /proc at boot you need an /etc/fstab line like:\n"	\
"      /proc   /proc   proc    defaults\n"			\
"  In the meantime, run \"mount /proc /proc -t proc\"\n"

#define STAT_FILE    "/proc/stat"
static int stat_fd = -1;
#define UPTIME_FILE  "/proc/uptime"
static int uptime_fd = -1;
#define LOADAVG_FILE "/proc/loadavg"
static int loadavg_fd = -1;
#define MEMINFO_FILE "/proc/meminfo"
static int meminfo_fd = -1;
#define VMINFO_FILE "/proc/vmstat"
static int vminfo_fd = -1;

// As of 2.6.24 /proc/meminfo seems to need 888 on 64-bit,
// and would need 1258 if the obsolete fields were there.
static char buf[2048];

/* This macro opens filename only if necessary and seeks to 0 so
 * that successive calls to the functions are more efficient.
 * It also reads the current contents of the file into the global buf.
 */
#define FILE_TO_BUF(filename, fd) do{				\
    static int local_n;						\
    if (fd == -1 && (fd = open(filename, O_RDONLY)) == -1) {	\
	fputs(BAD_OPEN_MESSAGE, stderr);			\
	fflush(NULL);						\
	_exit(102);						\
    }								\
    lseek(fd, 0L, SEEK_SET);					\
    if ((local_n = read(fd, buf, sizeof buf - 1)) < 0) {	\
	perror(filename);					\
	fflush(NULL);						\
	_exit(103);						\
    }								\
    buf[local_n] = '\0';					\
}while(0)

/* evals 'x' twice */
#define SET_IF_DESIRED(x,y) do{  if(x) *(x) = (y); }while(0)


/***********************************************************************/
int uptime(double *restrict uptime_secs, double *restrict idle_secs) {
    double up=0, idle=0;
    char *restrict savelocale;

    FILE_TO_BUF(UPTIME_FILE,uptime_fd);
    savelocale = setlocale(LC_NUMERIC, NULL);
    setlocale(LC_NUMERIC,"C");
    if (sscanf(buf, "%lf %lf", &up, &idle) < 2) {
        setlocale(LC_NUMERIC,savelocale);
        fputs("bad data in " UPTIME_FILE "\n", stderr);
	    return 0;
    }
    setlocale(LC_NUMERIC,savelocale);
    SET_IF_DESIRED(uptime_secs, up);
    SET_IF_DESIRED(idle_secs, idle);
    return up;	/* assume never be zero seconds in practice */
}

/***********************************************************************
 * Some values in /proc are expressed in units of 1/HZ seconds, where HZ
 * is the kernel clock tick rate. One of these units is called a jiffy.
 * The HZ value used in the kernel may vary according to hacker desire.
 * According to Linus Torvalds, this is not true. He considers the values
 * in /proc as being in architecture-dependant units that have no relation
 * to the kernel clock tick rate. Examination of the kernel source code
 * reveals that opinion as wishful thinking.
 *
 * In any case, we need the HZ constant as used in /proc. (the real HZ value
 * may differ, but we don't care) There are several ways we could get HZ:
 *
 * 1. Include the kernel header file. If it changes, recompile this library.
 * 2. Use the sysconf() function. When HZ changes, recompile the C library!
 * 3. Ask the kernel. This is obviously correct...
 *
 * Linus Torvalds won't let us ask the kernel, because he thinks we should
 * not know the HZ value. Oh well, we don't have to listen to him.
 * Someone smuggled out the HZ value. :-)
 *
 * This code should work fine, even if Linus fixes the kernel to match his
 * stated behavior. The code only fails in case of a partial conversion.
 *
 * Recent update: on some architectures, the 2.4 kernel provides an
 * ELF note to indicate HZ. This may be for ARM or user-mode Linux
 * support. This ought to be investigated. Note that sysconf() is still
 * unreliable, because it doesn't return an error code when it is
 * used with a kernel that doesn't support the ELF note. On some other
 * architectures there may be a system call or sysctl() that will work.
 */

unsigned long long Hertz;

static void old_Hertz_hack(void){
  unsigned long long user_j, nice_j, sys_j, other_j;  /* jiffies (clock ticks) */
  double up_1, up_2, seconds;
  unsigned long long jiffies;
  unsigned h;
  char *restrict savelocale;

  savelocale = setlocale(LC_NUMERIC, NULL);
  setlocale(LC_NUMERIC, "C");
  do{
    FILE_TO_BUF(UPTIME_FILE,uptime_fd);  sscanf(buf, "%lf", &up_1);
    /* uptime(&up_1, NULL); */
    FILE_TO_BUF(STAT_FILE,stat_fd);
    sscanf(buf, "cpu %Lu %Lu %Lu %Lu", &user_j, &nice_j, &sys_j, &other_j);
    FILE_TO_BUF(UPTIME_FILE,uptime_fd);  sscanf(buf, "%lf", &up_2);
    /* uptime(&up_2, NULL); */
  } while((long long)( (up_2-up_1)*1000.0/up_1 )); /* want under 0.1% error */
  setlocale(LC_NUMERIC, savelocale);
  jiffies = user_j + nice_j + sys_j + other_j;
  seconds = (up_1 + up_2) / 2;
  h = (unsigned)( (double)jiffies/seconds/smp_num_cpus );
  /* actual values used by 2.4 kernels: 32 64 100 128 1000 1024 1200 */
  switch(h){
  case    9 ...   11 :  Hertz =   10; break; /* S/390 (sometimes) */
  case   18 ...   22 :  Hertz =   20; break; /* user-mode Linux */
  case   30 ...   34 :  Hertz =   32; break; /* ia64 emulator */
  case   48 ...   52 :  Hertz =   50; break;
  case   58 ...   61 :  Hertz =   60; break;
  case   62 ...   65 :  Hertz =   64; break; /* StrongARM /Shark */
  case   95 ...  105 :  Hertz =  100; break; /* normal Linux */
  case  124 ...  132 :  Hertz =  128; break; /* MIPS, ARM */
  case  195 ...  204 :  Hertz =  200; break; /* normal << 1 */
  case  247 ...  252 :  Hertz =  250; break;
  case  253 ...  260 :  Hertz =  256; break;
  case  393 ...  408 :  Hertz =  400; break; /* normal << 2 */
  case  790 ...  808 :  Hertz =  800; break; /* normal << 3 */
  case  990 ... 1010 :  Hertz = 1000; break; /* ARM */
  case 1015 ... 1035 :  Hertz = 1024; break; /* Alpha, ia64 */
  case 1180 ... 1220 :  Hertz = 1200; break; /* Alpha */
  default:
#ifdef HZ
    Hertz = (unsigned long long)HZ;    /* <asm/param.h> */
#else
    /* If 32-bit or big-endian (not Alpha or ia64), assume HZ is 100. */
    Hertz = (sizeof(long)==sizeof(int) || htons(999)==999) ? 100UL : 1024UL;
#endif
    fprintf(stderr, "Unknown HZ value! (%d) Assume %Ld.\n", h, Hertz);
  }
}

// same as:   euid != uid || egid != gid
#ifndef AT_SECURE
#define AT_SECURE      23     // secure mode boolean (true if setuid, etc.)
#endif

#ifndef AT_CLKTCK
#define AT_CLKTCK       17    // frequency of times()
#endif

#define NOTE_NOT_FOUND 42

extern char** environ;

/* for ELF executables, notes are pushed before environment and args */
static unsigned long find_elf_note(unsigned long findme){
  unsigned long *ep = (unsigned long *)environ;
  while(*ep++);
  while(*ep){
    if(ep[0]==findme) return ep[1];
    ep+=2;
  }
  return NOTE_NOT_FOUND;
}

int have_privs;

static int check_for_privs(void){
  unsigned long rc = find_elf_note(AT_SECURE);
  if(rc==NOTE_NOT_FOUND){
    // not valid to run this code after UID or GID change!
    // (if needed, may use AT_UID and friends instead)
    rc = geteuid() != getuid() || getegid() != getgid();
  }
  return !!rc;
}

static void init_libproc(void) __attribute__((constructor));
static void init_libproc(void){
  have_privs = check_for_privs();
  // ought to count CPUs in /proc/stat instead of relying
  // on glibc, which foolishly tries to parse /proc/cpuinfo
  //
  // SourceForge has an old Alpha running Linux 2.2.20 that
  // appears to have a non-SMP kernel on a 2-way SMP box.
  // _SC_NPROCESSORS_CONF returns 2, resulting in HZ=512
  // _SC_NPROCESSORS_ONLN returns 1, which should work OK
  smp_num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
  if(smp_num_cpus<1) smp_num_cpus=1; /* SPARC glibc is buggy */

  if(linux_version_code > LINUX_VERSION(2, 4, 0)){
    Hertz = find_elf_note(AT_CLKTCK);
    if(Hertz!=NOTE_NOT_FOUND) return;
    fputs("2.4+ kernel w/o ELF notes? -- report this\n", stderr);
  }
  old_Hertz_hack();
}

#if 0
/***********************************************************************
 * The /proc filesystem calculates idle=jiffies-(user+nice+sys) and we
 * recover jiffies by adding up the 4 or 5 numbers we are given. SMP kernels
 * (as of pre-2.4 era) can report idle time going backwards, perhaps due
 * to non-atomic reads and updates. There is no locking for these values.
 */
#ifndef NAN
#define NAN (-0.0)
#endif
#define JT unsigned long long
void eight_cpu_numbers(double *restrict uret, double *restrict nret, double *restrict sret, double *restrict iret, double *restrict wret, double *restrict xret, double *restrict yret, double *restrict zret){
    double tmp_u, tmp_n, tmp_s, tmp_i, tmp_w, tmp_x, tmp_y, tmp_z;
    double scale;  /* scale values to % */
    static JT old_u, old_n, old_s, old_i, old_w, old_x, old_y, old_z;
    JT new_u, new_n, new_s, new_i, new_w, new_x, new_y, new_z;
    JT ticks_past; /* avoid div-by-0 by not calling too often :-( */

    tmp_w = 0.0;
    new_w = 0;
    tmp_x = 0.0;
    new_x = 0;
    tmp_y = 0.0;
    new_y = 0;
    tmp_z = 0.0;
    new_z = 0;

    FILE_TO_BUF(STAT_FILE,stat_fd);
    sscanf(buf, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu", &new_u, &new_n, &new_s, &new_i, &new_w, &new_x, &new_y, &new_z);
    ticks_past = (new_u+new_n+new_s+new_i+new_w+new_x+new_y+new_z)-(old_u+old_n+old_s+old_i+old_w+old_x+old_y+old_z);
    if(ticks_past){
      scale = 100.0 / (double)ticks_past;
      tmp_u = ( (double)new_u - (double)old_u ) * scale;
      tmp_n = ( (double)new_n - (double)old_n ) * scale;
      tmp_s = ( (double)new_s - (double)old_s ) * scale;
      tmp_i = ( (double)new_i - (double)old_i ) * scale;
      tmp_w = ( (double)new_w - (double)old_w ) * scale;
      tmp_x = ( (double)new_x - (double)old_x ) * scale;
      tmp_y = ( (double)new_y - (double)old_y ) * scale;
      tmp_z = ( (double)new_z - (double)old_z ) * scale;
    }else{
      tmp_u = NAN;
      tmp_n = NAN;
      tmp_s = NAN;
      tmp_i = NAN;
      tmp_w = NAN;
      tmp_x = NAN;
      tmp_y = NAN;
      tmp_z = NAN;
    }
    SET_IF_DESIRED(uret, tmp_u);
    SET_IF_DESIRED(nret, tmp_n);
    SET_IF_DESIRED(sret, tmp_s);
    SET_IF_DESIRED(iret, tmp_i);
    SET_IF_DESIRED(wret, tmp_w);
    SET_IF_DESIRED(xret, tmp_x);
    SET_IF_DESIRED(yret, tmp_y);
    SET_IF_DESIRED(zret, tmp_z);
    old_u=new_u;
    old_n=new_n;
    old_s=new_s;
    old_i=new_i;
    old_w=new_w;
    old_x=new_x;
    old_y=new_y;
    old_z=new_z;
}
#undef JT
#endif

/***********************************************************************/
void loadavg(double *restrict av1, double *restrict av5, double *restrict av15) {
    double avg_1=0, avg_5=0, avg_15=0;
    char *restrict savelocale;

    FILE_TO_BUF(LOADAVG_FILE,loadavg_fd);
    savelocale = setlocale(LC_NUMERIC, NULL);
    setlocale(LC_NUMERIC, "C");
    if (sscanf(buf, "%lf %lf %lf", &avg_1, &avg_5, &avg_15) < 3) {
	fputs("bad data in " LOADAVG_FILE "\n", stderr);
	exit(1);
    }
    setlocale(LC_NUMERIC, savelocale);
    SET_IF_DESIRED(av1,  avg_1);
    SET_IF_DESIRED(av5,  avg_5);
    SET_IF_DESIRED(av15, avg_15);
}

  static char buff[BUFFSIZE]; /* used in the procedures */
/***********************************************************************/

static void crash(const char *filename) {
    perror(filename);
    exit(EXIT_FAILURE);
}

/***********************************************************************/

static void getrunners(unsigned int *restrict running, unsigned int *restrict blocked) {
  struct direct *ent;
  DIR *proc;

  *running=0;
  *blocked=0;

  if((proc=opendir("/proc"))==NULL) crash("/proc");

  while(( ent=readdir(proc) )) {
    char tbuf[32];
    char *cp;
    int fd;
    char c;

    if (!isdigit(ent->d_name[0])) continue;
    sprintf(tbuf, "/proc/%s/stat", ent->d_name);

    fd = open(tbuf, O_RDONLY, 0);
    if (fd == -1) continue;
    memset(tbuf, '\0', sizeof tbuf); // didn't feel like checking read()
    if (read(fd, tbuf, sizeof tbuf - 1) < 0) { // need 32 byte buffer at most
        perror(tbuf);
        fflush(NULL);
        _exit(103);
    }
    close(fd);

    cp = strrchr(tbuf, ')');
    if(!cp) continue;
    c = cp[2];

    if (c=='R') {
      (*running)++;
      continue;
    }
    if (c=='D') {
      (*blocked)++;
      continue;
    }
  }
  closedir(proc);
}

/***********************************************************************/

void getstat(jiff *restrict cuse, jiff *restrict cice, jiff *restrict csys, jiff *restrict cide, jiff *restrict ciow, jiff *restrict cxxx, jiff *restrict cyyy, jiff *restrict czzz,
	     unsigned long *restrict pin, unsigned long *restrict pout, unsigned long *restrict s_in, unsigned long *restrict sout,
	     unsigned *restrict intr, unsigned *restrict ctxt,
	     unsigned int *restrict running, unsigned int *restrict blocked,
	     unsigned int *restrict btime, unsigned int *restrict processes) {
  static int fd;
  unsigned long long llbuf = 0;
  int need_vmstat_file = 0;
  int need_proc_scan = 0;
  const char* b;
  buff[BUFFSIZE-1] = 0;  /* ensure null termination in buffer */

  if(fd){
    lseek(fd, 0L, SEEK_SET);
  }else{
    fd = open("/proc/stat", O_RDONLY, 0);
    if(fd == -1) crash("/proc/stat");
  }
  if (read(fd,buff,BUFFSIZE-1) < 0) {
      perror("/proc/stat");
      fflush(NULL);
      _exit(103);
  }
  *intr = 0;
  *ciow = 0;  /* not separated out until the 2.5.41 kernel */
  *cxxx = 0;  /* not separated out until the 2.6.0-test4 kernel */
  *cyyy = 0;  /* not separated out until the 2.6.0-test4 kernel */
  *czzz = 0;  /* not separated out until the 2.6.11 kernel */

  b = strstr(buff, "cpu ");
  if(b) sscanf(b,  "cpu  %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu", cuse, cice, csys, cide, ciow, cxxx, cyyy, czzz);

  b = strstr(buff, "page ");
  if(b) sscanf(b,  "page %lu %lu", pin, pout);
  else need_vmstat_file = 1;

  b = strstr(buff, "swap ");
  if(b) sscanf(b,  "swap %lu %lu", s_in, sout);
  else need_vmstat_file = 1;

  b = strstr(buff, "intr ");
  if(b) sscanf(b,  "intr %Lu", &llbuf);
  *intr = llbuf;

  b = strstr(buff, "ctxt ");
  if(b) sscanf(b,  "ctxt %Lu", &llbuf);
  *ctxt = llbuf;

  b = strstr(buff, "btime ");
  if(b) sscanf(b,  "btime %u", btime);

  b = strstr(buff, "processes ");
  if(b) sscanf(b,  "processes %u", processes);

  b = strstr(buff, "procs_running ");
  if(b) sscanf(b,  "procs_running %u", running);
  else need_proc_scan = 1;

  b = strstr(buff, "procs_blocked ");
  if(b) sscanf(b,  "procs_blocked %u", blocked);
  else need_proc_scan = 1;

  if(need_proc_scan){   /* Linux 2.5.46 (approximately) and below */
    getrunners(running, blocked);
  }

  (*running)--;   // exclude vmstat itself

  if(need_vmstat_file){  /* Linux 2.5.40-bk4 and above */
    vminfo();
    *pin  = vm_pgpgin;
    *pout = vm_pgpgout;
    *s_in = vm_pswpin;
    *sout = vm_pswpout;
  }
}

/***********************************************************************/
/*
 * Copyright 1999 by Albert Cahalan; all rights reserved.
 * This file may be used subject to the terms and conditions of the
 * GNU Library General Public License Version 2, or any later version
 * at your option, as published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Library General Public License for more details.
 */

typedef struct mem_table_struct {
  const char *name;     /* memory type name */
  unsigned long *slot; /* slot in return struct */
} mem_table_struct;

static int compare_mem_table_structs(const void *a, const void *b){
  return strcmp(((const mem_table_struct*)a)->name,((const mem_table_struct*)b)->name);
}

/* example data, following junk, with comments added:
 *
 * MemTotal:        61768 kB    old
 * MemFree:          1436 kB    old
 * MemShared:           0 kB    old (now always zero; not calculated)
 * Buffers:          1312 kB    old
 * Cached:          20932 kB    old
 * Active:          12464 kB    new
 * Inact_dirty:      7772 kB    new
 * Inact_clean:      2008 kB    new
 * Inact_target:        0 kB    new
 * Inact_laundry:       0 kB    new, and might be missing too
 * HighTotal:           0 kB
 * HighFree:            0 kB
 * LowTotal:        61768 kB
 * LowFree:          1436 kB
 * SwapTotal:      122580 kB    old
 * SwapFree:        60352 kB    old
 * Inactive:        20420 kB    2.5.41+
 * Dirty:               0 kB    2.5.41+
 * Writeback:           0 kB    2.5.41+
 * Mapped:           9792 kB    2.5.41+
 * Slab:             4564 kB    2.5.41+
 * Committed_AS:     8440 kB    2.5.41+
 * PageTables:        304 kB    2.5.41+
 * ReverseMaps:      5738       2.5.41+
 * SwapCached:          0 kB    2.5.??+
 * HugePages_Total:   220       2.5.??+
 * HugePages_Free:    138       2.5.??+
 * Hugepagesize:     4096 kB    2.5.??+
 */

/* obsolete */
unsigned long kb_main_shared;
/* old but still kicking -- the important stuff */
unsigned long kb_main_buffers;
unsigned long kb_main_cached;
unsigned long kb_main_free;
unsigned long kb_main_total;
unsigned long kb_swap_free;
unsigned long kb_swap_total;
/* recently introduced */
unsigned long kb_high_free;
unsigned long kb_high_total;
unsigned long kb_low_free;
unsigned long kb_low_total;
/* 2.4.xx era */
unsigned long kb_active;
unsigned long kb_inact_laundry;
unsigned long kb_inact_dirty;
unsigned long kb_inact_clean;
unsigned long kb_inact_target;
unsigned long kb_swap_cached;  /* late 2.4 and 2.6+ only */
/* derived values */
unsigned long kb_swap_used;
unsigned long kb_main_used;
/* 2.5.41+ */
unsigned long kb_writeback;
unsigned long kb_slab;
unsigned long nr_reversemaps;
unsigned long kb_committed_as;
unsigned long kb_dirty;
unsigned long kb_inactive;
unsigned long kb_mapped;
unsigned long kb_pagetables;
// seen on a 2.6.x kernel:
static unsigned long kb_vmalloc_chunk;
static unsigned long kb_vmalloc_total;
static unsigned long kb_vmalloc_used;
// seen on 2.6.24-rc6-git12
static unsigned long kb_anon_pages;
static unsigned long kb_bounce;
static unsigned long kb_commit_limit;
static unsigned long kb_nfs_unstable;
static unsigned long kb_swap_reclaimable;
static unsigned long kb_swap_unreclaimable;

void meminfo(void){
  char namebuf[16]; /* big enough to hold any row name */
  mem_table_struct findme = { namebuf, NULL};
  mem_table_struct *found;
  char *head;
  char *tail;
  static const mem_table_struct mem_table[] = {
  {"Active",       &kb_active},       // important
  {"AnonPages",    &kb_anon_pages},
  {"Bounce",       &kb_bounce},
  {"Buffers",      &kb_main_buffers}, // important
  {"Cached",       &kb_main_cached},  // important
  {"CommitLimit",  &kb_commit_limit},
  {"Committed_AS", &kb_committed_as},
  {"Dirty",        &kb_dirty},        // kB version of vmstat nr_dirty
  {"HighFree",     &kb_high_free},
  {"HighTotal",    &kb_high_total},
  {"Inact_clean",  &kb_inact_clean},
  {"Inact_dirty",  &kb_inact_dirty},
  {"Inact_laundry",&kb_inact_laundry},
  {"Inact_target", &kb_inact_target},
  {"Inactive",     &kb_inactive},     // important
  {"LowFree",      &kb_low_free},
  {"LowTotal",     &kb_low_total},
  {"Mapped",       &kb_mapped},       // kB version of vmstat nr_mapped
  {"MemFree",      &kb_main_free},    // important
  {"MemShared",    &kb_main_shared},  // important, but now gone!
  {"MemTotal",     &kb_main_total},   // important
  {"NFS_Unstable", &kb_nfs_unstable},
  {"PageTables",   &kb_pagetables},   // kB version of vmstat nr_page_table_pages
  {"ReverseMaps",  &nr_reversemaps},  // same as vmstat nr_page_table_pages
  {"SReclaimable", &kb_swap_reclaimable}, // "swap reclaimable" (dentry and inode structures)
  {"SUnreclaim",   &kb_swap_unreclaimable},
  {"Slab",         &kb_slab},         // kB version of vmstat nr_slab
  {"SwapCached",   &kb_swap_cached},
  {"SwapFree",     &kb_swap_free},    // important
  {"SwapTotal",    &kb_swap_total},   // important
  {"VmallocChunk", &kb_vmalloc_chunk},
  {"VmallocTotal", &kb_vmalloc_total},
  {"VmallocUsed",  &kb_vmalloc_used},
  {"Writeback",    &kb_writeback},    // kB version of vmstat nr_writeback
  };
  const int mem_table_count = sizeof(mem_table)/sizeof(mem_table_struct);

  FILE_TO_BUF(MEMINFO_FILE,meminfo_fd);

  kb_inactive = ~0UL;

  head = buf;
  for(;;){
    tail = strchr(head, ':');
    if(!tail) break;
    *tail = '\0';
    if(strlen(head) >= sizeof(namebuf)){
      head = tail+1;
      goto nextline;
    }
    strcpy(namebuf,head);
    found = bsearch(&findme, mem_table, mem_table_count,
        sizeof(mem_table_struct), compare_mem_table_structs
    );
    head = tail+1;
    if(!found) goto nextline;
    *(found->slot) = strtoul(head,&tail,10);
nextline:
    tail = strchr(head, '\n');
    if(!tail) break;
    head = tail+1;
  }
  if(!kb_low_total){  /* low==main except with large-memory support */
    kb_low_total = kb_main_total;
    kb_low_free  = kb_main_free;
  }
  if(kb_inactive==~0UL){
    kb_inactive = kb_inact_dirty + kb_inact_clean + kb_inact_laundry;
  }
  kb_swap_used = kb_swap_total - kb_swap_free;
  kb_main_used = kb_main_total - kb_main_free;
}

/*****************************************************************/

/* read /proc/vminfo only for 2.5.41 and above */

typedef struct vm_table_struct {
  const char *name;     /* VM statistic name */
  unsigned long *slot;       /* slot in return struct */
} vm_table_struct;

static int compare_vm_table_structs(const void *a, const void *b){
  return strcmp(((const vm_table_struct*)a)->name,((const vm_table_struct*)b)->name);
}

// see include/linux/page-flags.h and mm/page_alloc.c
unsigned long vm_nr_dirty;           // dirty writable pages
unsigned long vm_nr_writeback;       // pages under writeback
unsigned long vm_nr_pagecache;       // pages in pagecache -- gone in 2.5.66+ kernels
unsigned long vm_nr_page_table_pages;// pages used for pagetables
unsigned long vm_nr_reverse_maps;    // includes PageDirect
unsigned long vm_nr_mapped;          // mapped into pagetables
unsigned long vm_nr_slab;            // in slab
unsigned long vm_pgpgin;             // kB disk reads  (same as 1st num on /proc/stat page line)
unsigned long vm_pgpgout;            // kB disk writes (same as 2nd num on /proc/stat page line)
unsigned long vm_pswpin;             // swap reads     (same as 1st num on /proc/stat swap line)
unsigned long vm_pswpout;            // swap writes    (same as 2nd num on /proc/stat swap line)
unsigned long vm_pgalloc;            // page allocations
unsigned long vm_pgfree;             // page freeings
unsigned long vm_pgactivate;         // pages moved inactive -> active
unsigned long vm_pgdeactivate;       // pages moved active -> inactive
unsigned long vm_pgfault;           // total faults (major+minor)
unsigned long vm_pgmajfault;       // major faults
unsigned long vm_pgscan;          // pages scanned by page reclaim
unsigned long vm_pgrefill;       // inspected by refill_inactive_zone
unsigned long vm_pgsteal;       // total pages reclaimed
unsigned long vm_kswapd_steal; // pages reclaimed by kswapd
// next 3 as defined by the 2.5.52 kernel
unsigned long vm_pageoutrun;  // times kswapd ran page reclaim
unsigned long vm_allocstall; // times a page allocator ran direct reclaim
unsigned long vm_pgrotated; // pages rotated to the tail of the LRU for immediate reclaim
// seen on a 2.6.8-rc1 kernel, apparently replacing old fields
static unsigned long vm_pgalloc_dma;          //
static unsigned long vm_pgalloc_high;         //
static unsigned long vm_pgalloc_normal;       //
static unsigned long vm_pgrefill_dma;         //
static unsigned long vm_pgrefill_high;        //
static unsigned long vm_pgrefill_normal;      //
static unsigned long vm_pgscan_direct_dma;    //
static unsigned long vm_pgscan_direct_high;   //
static unsigned long vm_pgscan_direct_normal; //
static unsigned long vm_pgscan_kswapd_dma;    //
static unsigned long vm_pgscan_kswapd_high;   //
static unsigned long vm_pgscan_kswapd_normal; //
static unsigned long vm_pgsteal_dma;          //
static unsigned long vm_pgsteal_high;         //
static unsigned long vm_pgsteal_normal;       //
// seen on a 2.6.8-rc1 kernel
static unsigned long vm_kswapd_inodesteal;    //
static unsigned long vm_nr_unstable;          //
static unsigned long vm_pginodesteal;         //
static unsigned long vm_slabs_scanned;        //

void vminfo(void){
  char namebuf[16]; /* big enough to hold any row name */
  vm_table_struct findme = { namebuf, NULL};
  vm_table_struct *found;
  char *head;
  char *tail;
  static const vm_table_struct vm_table[] = {
  {"allocstall",          &vm_allocstall},
  {"kswapd_inodesteal",   &vm_kswapd_inodesteal},
  {"kswapd_steal",        &vm_kswapd_steal},
  {"nr_dirty",            &vm_nr_dirty},           // page version of meminfo Dirty
  {"nr_mapped",           &vm_nr_mapped},          // page version of meminfo Mapped
  {"nr_page_table_pages", &vm_nr_page_table_pages},// same as meminfo PageTables
  {"nr_pagecache",        &vm_nr_pagecache},       // gone in 2.5.66+ kernels
  {"nr_reverse_maps",     &vm_nr_reverse_maps},    // page version of meminfo ReverseMaps GONE
  {"nr_slab",             &vm_nr_slab},            // page version of meminfo Slab
  {"nr_unstable",         &vm_nr_unstable},
  {"nr_writeback",        &vm_nr_writeback},       // page version of meminfo Writeback
  {"pageoutrun",          &vm_pageoutrun},
  {"pgactivate",          &vm_pgactivate},
  {"pgalloc",             &vm_pgalloc},  // GONE (now separate dma,high,normal)
  {"pgalloc_dma",         &vm_pgalloc_dma},
  {"pgalloc_high",        &vm_pgalloc_high},
  {"pgalloc_normal",      &vm_pgalloc_normal},
  {"pgdeactivate",        &vm_pgdeactivate},
  {"pgfault",             &vm_pgfault},
  {"pgfree",              &vm_pgfree},
  {"pginodesteal",        &vm_pginodesteal},
  {"pgmajfault",          &vm_pgmajfault},
  {"pgpgin",              &vm_pgpgin},     // important
  {"pgpgout",             &vm_pgpgout},     // important
  {"pgrefill",            &vm_pgrefill},  // GONE (now separate dma,high,normal)
  {"pgrefill_dma",        &vm_pgrefill_dma},
  {"pgrefill_high",       &vm_pgrefill_high},
  {"pgrefill_normal",     &vm_pgrefill_normal},
  {"pgrotated",           &vm_pgrotated},
  {"pgscan",              &vm_pgscan},  // GONE (now separate direct,kswapd and dma,high,normal)
  {"pgscan_direct_dma",   &vm_pgscan_direct_dma},
  {"pgscan_direct_high",  &vm_pgscan_direct_high},
  {"pgscan_direct_normal",&vm_pgscan_direct_normal},
  {"pgscan_kswapd_dma",   &vm_pgscan_kswapd_dma},
  {"pgscan_kswapd_high",  &vm_pgscan_kswapd_high},
  {"pgscan_kswapd_normal",&vm_pgscan_kswapd_normal},
  {"pgsteal",             &vm_pgsteal},  // GONE (now separate dma,high,normal)
  {"pgsteal_dma",         &vm_pgsteal_dma},
  {"pgsteal_high",        &vm_pgsteal_high},
  {"pgsteal_normal",      &vm_pgsteal_normal},
  {"pswpin",              &vm_pswpin},     // important
  {"pswpout",             &vm_pswpout},     // important
  {"slabs_scanned",       &vm_slabs_scanned},
  };
  const int vm_table_count = sizeof(vm_table)/sizeof(vm_table_struct);

  vm_pgalloc = 0;
  vm_pgrefill = 0;
  vm_pgscan = 0;
  vm_pgsteal = 0;

  FILE_TO_BUF(VMINFO_FILE,vminfo_fd);

  head = buf;
  for(;;){
    tail = strchr(head, ' ');
    if(!tail) break;
    *tail = '\0';
    if(strlen(head) >= sizeof(namebuf)){
      head = tail+1;
      goto nextline;
    }
    strcpy(namebuf,head);
    found = bsearch(&findme, vm_table, vm_table_count,
        sizeof(vm_table_struct), compare_vm_table_structs
    );
    head = tail+1;
    if(!found) goto nextline;
    *(found->slot) = strtoul(head,&tail,10);
nextline:

//if(found) fprintf(stderr,"%s=%d\n",found->name,*(found->slot));
//else      fprintf(stderr,"%s not found\n",findme.name);

    tail = strchr(head, '\n');
    if(!tail) break;
    head = tail+1;
  }
  if(!vm_pgalloc)
    vm_pgalloc  = vm_pgalloc_dma + vm_pgalloc_high + vm_pgalloc_normal;
  if(!vm_pgrefill)
    vm_pgrefill = vm_pgrefill_dma + vm_pgrefill_high + vm_pgrefill_normal;
  if(!vm_pgscan)
    vm_pgscan   = vm_pgscan_direct_dma + vm_pgscan_direct_high + vm_pgscan_direct_normal
                + vm_pgscan_kswapd_dma + vm_pgscan_kswapd_high + vm_pgscan_kswapd_normal;
  if(!vm_pgsteal)
    vm_pgsteal  = vm_pgsteal_dma + vm_pgsteal_high + vm_pgsteal_normal;
}

///////////////////////////////////////////////////////////////////////
// based on Fabian Frederick's /proc/diskstats parser


unsigned int getpartitions_num(struct disk_stat *disks, int ndisks){
  int i=0;
  int partitions=0;

  for (i=0;i<ndisks;i++){
	partitions+=disks[i].partitions;
  }
  return partitions;

}

/////////////////////////////////////////////////////////////////////////////

unsigned int getdiskstat(struct disk_stat **disks, struct partition_stat **partitions){
  FILE* fd;
  int cDisk = 0;
  int cPartition = 0;
  int fields;
  unsigned dummy;

  *disks = NULL;
  *partitions = NULL;
  buff[BUFFSIZE-1] = 0;
  fd = fopen("/proc/diskstats", "rb");
  if(!fd) crash("/proc/diskstats");

  for (;;) {
    if (!fgets(buff,BUFFSIZE-1,fd)){
      fclose(fd);
      break;
    }
    fields = sscanf(buff, " %*d %*d %*s %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %u", &dummy);
    if (fields == 1){
      (*disks) = realloc(*disks, (cDisk+1)*sizeof(struct disk_stat));
      sscanf(buff,  "   %*d    %*d %15s %u %u %llu %u %u %u %llu %u %u %u %u",
        //&disk_major,
        //&disk_minor,
        (*disks)[cDisk].disk_name,
        &(*disks)[cDisk].reads,
        &(*disks)[cDisk].merged_reads,
        &(*disks)[cDisk].reads_sectors,
        &(*disks)[cDisk].milli_reading,
        &(*disks)[cDisk].writes,
        &(*disks)[cDisk].merged_writes,
        &(*disks)[cDisk].written_sectors,
        &(*disks)[cDisk].milli_writing,
        &(*disks)[cDisk].inprogress_IO,
        &(*disks)[cDisk].milli_spent_IO,
        &(*disks)[cDisk].weighted_milli_spent_IO
      );
        (*disks)[cDisk].partitions=0;
      cDisk++;
    }else{
      (*partitions) = realloc(*partitions, (cPartition+1)*sizeof(struct partition_stat));
      fflush(stdout);
      sscanf(buff,  "   %*d    %*d %15s %u %llu %u %u",
        //&part_major,
        //&part_minor,
        (*partitions)[cPartition].partition_name,
        &(*partitions)[cPartition].reads,
        &(*partitions)[cPartition].reads_sectors,
        &(*partitions)[cPartition].writes,
        &(*partitions)[cPartition].requested_writes
      );
      (*partitions)[cPartition++].parent_disk = cDisk-1;
      (*disks)[cDisk-1].partitions++;
    }
  }

  return cDisk;
}

/////////////////////////////////////////////////////////////////////////////
// based on Fabian Frederick's /proc/slabinfo parser

unsigned int getslabinfo (struct slab_cache **slab){
  FILE* fd;
  int cSlab = 0;
  buff[BUFFSIZE-1] = 0;
  *slab = NULL;
  fd = fopen("/proc/slabinfo", "rb");
  if(!fd) crash("/proc/slabinfo");
  while (fgets(buff,BUFFSIZE-1,fd)){
    if(!memcmp("slabinfo - version:",buff,19)) continue; // skip header
    if(*buff == '#')                           continue; // skip comments
    (*slab) = realloc(*slab, (cSlab+1)*sizeof(struct slab_cache));
    sscanf(buff,  "%47s %u %u %u %u",  // allow 47; max seen is 24
      (*slab)[cSlab].name,
      &(*slab)[cSlab].active_objs,
      &(*slab)[cSlab].num_objs,
      &(*slab)[cSlab].objsize,
      &(*slab)[cSlab].objperslab
    ) ;
    cSlab++;
  }
  fclose(fd);
  return cSlab;
}

///////////////////////////////////////////////////////////////////////////

unsigned get_pid_digits(void){
  char pidbuf[24];
  char *endp;
  long rc;
  int fd;
  static unsigned ret;

  if(ret) goto out;
  ret = 5;
  fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
  if(fd==-1) goto out;
  rc = read(fd, pidbuf, sizeof pidbuf);
  close(fd);
  if(rc<3) goto out;
  pidbuf[rc] = '\0';
  rc = strtol(pidbuf,&endp,10);
  if(rc<42) goto out;
  if(*endp && *endp!='\n') goto out;
  rc--;  // the pid_max value is really the max PID plus 1
  ret = 0;
  while(rc){
    rc /= 10;
    ret++;
  }
out:
  return ret;
}
