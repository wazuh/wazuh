/* spike #37396 — exec probe userspace loader. */
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <string.h>
struct exec_event { unsigned pid, ppid; unsigned long long cgroup_id; char comm[16]; };
static volatile int stop; static void oi(int s){(void)s;stop=1;}
static int on(void*c,void*d,size_t s){(void)c;(void)s;struct exec_event*e=d;
  printf("EXEC pid=%u ppid=%u cgroup_id=%llu comm=%s\n",e->pid,e->ppid,e->cgroup_id,e->comm);return 0;}
int main(void){signal(SIGINT,oi);
  struct rlimit r={RLIM_INFINITY,RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK,&r);
  struct bpf_object*o=bpf_object__open_file("exec_probe.bpf.o",0);
  if(!o){fprintf(stderr,"open fail\n");return 1;}
  if(bpf_object__load(o)){fprintf(stderr,"load failed (need root+BTF)\n");return 1;}
  struct bpf_program*p; bpf_object__for_each_program(p,o){
    if(!bpf_program__attach(p)){fprintf(stderr,"attach failed %s\n",bpf_program__section_name(p));return 1;}}
  int fd=bpf_object__find_map_fd_by_name(o,"erb");
  struct ring_buffer*rb=ring_buffer__new(fd,on,0,0);
  if(!rb){fprintf(stderr,"rb fail\n");return 1;}
  fprintf(stderr,"exec probe running (tracepoint/sched_process_exec)\n");
  while(!stop){int n=ring_buffer__poll(rb,200);if(n<0&&n!=-EINTR)break;}
  return 0;}
