#include <linux/perf_event.h>
#include <perf/core.h>
#include <perf/cpumap.h>
#include <perf/event.h>
#include <perf/evlist.h>
#include <perf/evsel.h>
#include <perf/mmap.h>
#include <perf/threadmap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#define rmb()   asm volatile("lfence" ::: "memory")

struct __attribute__ ((__packed__)) sample {
  uint32_t pid, tid;
  uint64_t stream_id;
  uint32_t size;
  char data[];
};

struct trace_entry {
     unsigned short      type;
     unsigned char       flags;
     unsigned char       preempt_count;
     int                 pid;
};

struct syscall_mmap_enter_args {
  struct trace_entry  ent;
  int     sys_nr;
  unsigned long addr;
  unsigned long len;      
  unsigned long prot;      
  unsigned long flags;    
  unsigned long fd; 
  unsigned long off;      
};

struct syscall_munmap_enter_args {
  struct trace_entry  ent;
  int     sys_nr;
  unsigned long addr; 
  unsigned long len;       
};

struct syscall_mmap_exit_args {
  struct trace_entry  ent;
  int     sys_nr;
  long    ret;
};

static const int sys_enter_mmap_id = 101;  // see: /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/id
static const int sys_exit_mmap_id = 100;  // see: /sys/kernel/debug/tracing/events/syscalls/sys_exit_mmap/id
static const int sys_enter_munmap_id = 576;  // see: /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/id

static int libperf_print(enum libperf_print_level level, const char *fmt, va_list ap)
{
    return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
    struct perf_evlist *evlist;
    struct perf_evsel *evsel;
    struct perf_mmap *map;
    struct perf_cpu_map *cpus;
    union perf_event *event;
    int err;

    struct perf_event_attr attr = {
        .type = PERF_TYPE_TRACEPOINT,
        .disabled = 1,
        .precise_ip = 1,
        .exclude_kernel = 1,
        .exclude_user = 0,
        .exclude_hv = 1,
        .wakeup_events = 1,
        .sample_period = 1,
        .sample_type = PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_TID | PERF_SAMPLE_RAW,
    };

    libperf_init(libperf_print);

    cpus = perf_cpu_map__new(NULL);
    if (!cpus) {
        fprintf(stderr, "failed to create cpus\n");
        return -1;
    }

    evlist = perf_evlist__new();
    if (!evlist) {
        fprintf(stderr, "failed to create evlist\n");
        goto out_cpus;
    }

    // event: sys_enter_mmap 
    attr.config = sys_enter_mmap_id;     
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to create event\n");
        goto out_cpus;
    }
    perf_evlist__add(evlist, evsel);

    // event: sys_exit_mmap
    attr.config = sys_exit_mmap_id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to create event\n");
        goto out_cpus;
    }
    perf_evlist__add(evlist, evsel);

    // event: sys_enter_munmap
    attr.config = sys_enter_munmap_id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to create event\n");
        goto out_cpus;
    }
    perf_evlist__add(evlist, evsel);
    //evsel->sample_id = 10;
    //perf_evlist__id_add(evlist, evsel, 0, NULL, 10);

    perf_evlist__set_maps(evlist, cpus, NULL);

    err = perf_evlist__open(evlist);
    if (err) {
        fprintf(stderr, "failed to open evlist\n");
        goto out_evlist;
    }

    err = perf_evlist__mmap(evlist, 4);
    if (err) {
        fprintf(stderr, "failed to mmap evlist\n");
        goto out_evlist;
    }

    int num_mmap_enters = 0;
    int num_mmap_exits = 0;

    perf_evlist__enable(evlist);

    while (1) {

      printf("num_mmap_enters: %d, num_mmap_exits: %d\n", num_mmap_enters, num_mmap_exits);

      perf_evlist__poll(evlist, -1);

      //perf_evlist__disable(evlist);

      printf("-----\n");

      perf_evlist__for_each_mmap(evlist, map, false) {


          if (perf_mmap__read_init(map) < 0)
              continue;

          rmb();
          
	  while ((event = perf_mmap__read_event(map)) != NULL) {
              const __u32 type = event->header.type; 

              if (type != PERF_RECORD_SAMPLE) {
                //printf("other type: %d\n", type);
                //return -1;
                perf_mmap__consume(map);
                continue;
              }

              struct sample *sample = (struct sample *) event->sample.array;
              struct trace_entry *entry = (struct trace_entry *) sample->data;
              int sys_type = entry->type;

              //printf("stream_id: %ld, ent_type: %d\n", sample->stream_id, sys_type);

              if (sys_type == sys_enter_mmap_id) {
                num_mmap_enters += 1;
                struct syscall_mmap_enter_args *args = (struct syscall_mmap_enter_args *) sample->data;
                printf("sys_enter_mmap(pid=%d,tid=%d) - addr: 0x%lx, len: 0x%lx,\
                        prot: 0x%lx, flags: 0x%lx, fd: 0x%lx, off: 0x%lx\n",\
                        sample->pid, sample->tid, args->addr, args->len, args->prot,\
                        args->flags, args->fd, args->off);

              } else if (sys_type == sys_exit_mmap_id) {
                num_mmap_exits += 1;
                struct syscall_mmap_exit_args *args = (struct syscall_mmap_exit_args *) sample->data;
                printf("sys_exit_mmap(pid=%d,tid=%d) - ret=%ld\n", sample->pid, sample->tid, args->ret);

              } else if (sys_type == sys_enter_munmap_id) {
                struct syscall_munmap_enter_args *args = (struct syscall_munmap_enter_args *) sample->data;
                printf("sys_enter_munmap(pid=%d,tid=%d) - addr: 0x%lx, len: 0x%lx\n", 
                sample->pid, sample->tid, args->addr, args->len);
              }

              perf_mmap__consume(map);

          }

          perf_mmap__read_done(map);

      }

    }


  out_evlist:
    perf_evlist__delete(evlist);
  out_cpus:
    perf_cpu_map__put(cpus);

  return err;
}
