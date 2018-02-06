/*
 * Copyright 1998-2003 by Albert Cahalan; all rights resered.
 * This file may be used subject to the terms and conditions of the
 * GNU Library General Public License Version 2, or any later version
 * at your option, as published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Library General Public License for more details.
 */
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sig.h"

/* Linux signals:
 *
 * SIGSYS is required by Unix98.
 * SIGEMT is part of SysV, BSD, and ancient UNIX tradition.
 *
 * They are provided by these Linux ports: alpha, mips, sparc, and sparc64.
 * You get SIGSTKFLT and SIGUNUSED instead on i386, m68k, ppc, and arm.
 * (this is a Linux & libc bug -- both must be fixed)
 *
 * Total garbage: SIGIO SIGINFO SIGIOT SIGLOST SIGCLD
 *                 (popular ones are handled as aliases)
 * Nearly garbage: SIGSTKFLT SIGUNUSED (nothing else to fill slots)
 */

/* Linux 2.3.29 replaces SIGUNUSED with the standard SIGSYS signal */
#ifndef SIGSYS
#  warning Standards require that <signal.h> define SIGSYS
#  define SIGSYS SIGUNUSED
#endif

/* If we see both, it is likely SIGSTKFLT (junk) was replaced. */
#ifdef SIGEMT
#  undef SIGSTKFLT
#endif

#ifndef SIGRTMIN
#  warning Standards require that <signal.h> define SIGRTMIN; assuming 32
#  define SIGRTMIN 32
#endif

/* It seems the SPARC libc does not know the kernel supports SIGPWR. */
#ifndef SIGPWR
#  warning Your header files lack SIGPWR. (assuming it is number 29)
#  define SIGPWR 29
#endif

typedef struct mapstruct {
  const char *name;
  int num;
} mapstruct;


static const mapstruct sigtable[] = {
  {"ABRT",   SIGABRT},  /* IOT */
  {"ALRM",   SIGALRM},
  {"BUS",    SIGBUS},
  {"CHLD",   SIGCHLD},  /* CLD */
  {"CONT",   SIGCONT},
#ifdef SIGEMT
  {"EMT",    SIGEMT},
#endif
  {"FPE",    SIGFPE},
  {"HUP",    SIGHUP},
  {"ILL",    SIGILL},
  {"INT",    SIGINT},
  {"KILL",   SIGKILL},
  {"PIPE",   SIGPIPE},
  {"POLL",   SIGPOLL},  /* IO */
  {"PROF",   SIGPROF},
  {"PWR",    SIGPWR},
  {"QUIT",   SIGQUIT},
  {"SEGV",   SIGSEGV},
#ifdef SIGSTKFLT
  {"STKFLT", SIGSTKFLT},
#endif
  {"STOP",   SIGSTOP},
  {"SYS",    SIGSYS},   /* UNUSED */
  {"TERM",   SIGTERM},
  {"TRAP",   SIGTRAP},
  {"TSTP",   SIGTSTP},
  {"TTIN",   SIGTTIN},
  {"TTOU",   SIGTTOU},
  {"URG",    SIGURG},
  {"USR1",   SIGUSR1},
  {"USR2",   SIGUSR2},
  {"VTALRM", SIGVTALRM},
  {"WINCH",  SIGWINCH},
  {"XCPU",   SIGXCPU},
  {"XFSZ",   SIGXFSZ}
};

static const int number_of_signals = sizeof(sigtable)/sizeof(mapstruct);

static int compare_signal_names(const void *a, const void *b){
  return strcasecmp( ((const mapstruct*)a)->name, ((const mapstruct*)b)->name );
}

/* return -1 on failure */
int signal_name_to_number(const char *restrict name){
  long val;
  int offset;

  /* clean up name */
  if(!strncasecmp(name,"SIG",3)) name += 3;

  if(!strcasecmp(name,"CLD")) return SIGCHLD;
  if(!strcasecmp(name,"IO"))  return SIGPOLL;
  if(!strcasecmp(name,"IOT")) return SIGABRT;

  /* search the table */
  {
    const mapstruct ms = {name,0};
    const mapstruct *restrict const ptr = bsearch(
      &ms,
      sigtable,
      number_of_signals,
      sizeof(mapstruct),
      compare_signal_names
    );
    if(ptr) return ptr->num;
  }

  if(!strcasecmp(name,"RTMIN")) return SIGRTMIN;
  if(!strcasecmp(name,"EXIT"))  return 0;
  if(!strcasecmp(name,"NULL"))  return 0;

  offset = 0;
  if(!strncasecmp(name,"RTMIN+",6)){
    name += 6;
    offset = SIGRTMIN;
  }

  /* not found, so try as a number */
  {
    char *endp;
    val = strtol(name,&endp,10);
    if(*endp || endp==name) return -1; /* not valid */
  }
  if(val+SIGRTMIN>127) return -1; /* not valid */
  return val+offset;
}

const char *signal_number_to_name(int signo){
  static char buf[32];
  int n = number_of_signals;
  signo &= 0x7f; /* need to process exit values too */
  while(n--){
    if(sigtable[n].num==signo) return sigtable[n].name;
  }
  if(signo == SIGRTMIN) return "RTMIN";
  if(signo) sprintf(buf, "RTMIN+%d", signo-SIGRTMIN);
  else      strcpy(buf,"0");  /* AIX has NULL; Solaris has EXIT */
  return buf;
}

int print_given_signals(int argc, const char *restrict const *restrict argv, int max_line){
  char buf[1280]; /* 128 signals, "RTMIN+xx" is largest */
  int ret = 0;  /* to be used as exit code by caller */
  int place = 0; /* position on this line */
  int amt;
  if(argc > 128) return 1;
  while(argc--){
    char tmpbuf[16];
    const char *restrict const txt = *argv;
    if(*txt >= '0' && *txt <= '9'){
      long val;
      char *endp;
      val = strtol(txt,&endp,10);
      if(*endp){
        fprintf(stderr, "Signal \"%s\" not known.\n", txt);
        ret = 1;
        goto end;
      }
      amt = sprintf(tmpbuf, "%s", signal_number_to_name(val));
    }else{
      int sno;
      sno = signal_name_to_number(txt);
      if(sno == -1){
        fprintf(stderr, "Signal \"%s\" not known.\n", txt);
        ret = 1;
        goto end;
      }
      amt = sprintf(tmpbuf, "%d", sno);
    }

    if(!place){
      strcpy(buf,tmpbuf);
      place = amt;
      goto end;
    }
    if(amt+place+1 > max_line){
      printf("%s\n", buf);
      strcpy(buf,tmpbuf);
      place = amt;
      goto end;
    }
    sprintf(buf+place, " %s", tmpbuf);
    place += amt+1;
end:
    argv++;
  }
  if(place) printf("%s\n", buf);
  return ret;
}

void pretty_print_signals(void){
  int i = 0;
  while(++i <= number_of_signals){
    int n;
    n = printf("%2d %s", i, signal_number_to_name(i));
    if(i%7) printf("%*c",n,' ');
    else printf("\n");
  }
  if((i-1)%7) printf("\n");
}

void unix_print_signals(void){
  int pos = 0;
  int i = 0;
  while(++i <= number_of_signals){
    if(i-1) printf("%c", (pos>73)?(pos=0,'\n'):(pos++,' ') );
    pos += printf("%s", signal_number_to_name(i));
  }
  printf("\n");
}

/* sanity check */
static int init_signal_list(void) __attribute__((constructor));
static int init_signal_list(void){
  if(number_of_signals != 31){
    fprintf(stderr, "WARNING: %d signals -- adjust and recompile.\n", number_of_signals);
  }
  return 0;
}
