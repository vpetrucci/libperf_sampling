#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/poll.h>
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

struct syscall_mmap_enter {
  struct trace_entry  ent;
  int     nr;
  unsigned long addr;
  unsigned long len;      
  unsigned long prot;      
  unsigned long flags;    
  unsigned long fd; 
  unsigned long off;      
};

struct syscall_munmap_enter {
  struct trace_entry  ent;
  int     nr;
  unsigned long addr; 
  unsigned long len;       
};

struct syscall_mmap_exit {
  struct trace_entry  ent;
  int     nr;
  long    ret;
};

static const int mmap_pages = 8; 
static size_t page_size;
static size_t mmap_size;
struct perf_event_mmap_page *mmap_buf;
uint64_t id_enter_mmap, id_exit_mmap, id_enter_munmap; 

void process_smpl_buf(int fd)
{

  ioctl(fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);

  // read from ring buffer
  uint64_t head = mmap_buf->data_head;
  //printf("head: %ld\n", head);

  rmb();
  
  struct perf_event_header *header = (struct perf_event_header *)((char *)mmap_buf + page_size);
  uint64_t consumed = 0;

  while (consumed < head) {
      if (header->size == 0) {
        fprintf(stderr, "Error: invalid header size = 0\n");
        return;
      }

      //printf("type: %d\n", header->type);
      if (header->type == PERF_RECORD_SAMPLE) {

        struct sample *sample = (struct sample *)((char *)(header) + 8);

        if (sample->stream_id == id_enter_mmap) {
          struct syscall_mmap_enter *mmap_enter;
          mmap_enter = (struct syscall_mmap_enter *) sample->data;
          printf("sys_enter_mmap(pid=%d, tid=%d) - addr: 0x%lx, len: 0x%lx,\
                  prot: 0x%lx, flags: 0x%lx, fd: 0x%lx, off: 0x%lx\n",\
                  sample->pid, sample->tid, mmap_enter->addr, mmap_enter->len, mmap_enter->prot,\
                  mmap_enter->flags, mmap_enter->fd, mmap_enter->off);

          // get next event that must be sys_exit_mmap
          consumed += header->size;
          header = (struct perf_event_header *)((char *)header + header->size);
          struct sample *sample = (struct sample *)((char *)(header) + 8);
          if (sample->stream_id != id_exit_mmap) {
            printf("Ops got stream_id == %ld\n", sample->stream_id);
            continue;
          }

          struct syscall_mmap_exit *mmap_exit;
          mmap_exit = (struct syscall_mmap_exit *) sample->data;
          printf("sys_exit_mmap(pid=%d, tid=%d) - ret=%ld\n", sample->pid, sample->tid, mmap_exit->ret);

        } else if (sample->stream_id == id_enter_munmap) {
          struct syscall_munmap_enter *munmap_enter;
          munmap_enter = (struct syscall_munmap_enter *) sample->data;          
          printf("sys_enter_munmap(pid=%d, tid=%d) - addr: 0x%08lx, len: 0x%08lx\n", 
            sample->pid, sample->tid, munmap_enter->addr, munmap_enter->len);

        } 

      }

      consumed += header->size;
      header = (struct perf_event_header *)((char *)header + header->size);

  }
  //printf("head = %" PRIu64 " compared to max = %zu\n", head, map_size);

  ioctl(fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
}

int main()
{
  struct perf_event_attr pea;
  int fd1, fd2, fd3;
  int ret;

  memset(&pea, 0, sizeof(struct perf_event_attr));
  
  pea.type = PERF_TYPE_TRACEPOINT;
  pea.size = sizeof(struct perf_event_attr);
  pea.disabled = 1;
  pea.exclude_kernel = 1;
  pea.exclude_hv = 1;
  pea.wakeup_events = 1;
  pea.sample_period = 1;
  pea.sample_type = PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_TID | PERF_SAMPLE_RAW;
  //pea.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;

  pea.config = 101;  // see: /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/id  
  fd1 = syscall(__NR_perf_event_open, &pea, -1, 0, -1, 0);
  if (fd1 == -1) {
    fprintf(stderr, "Error: cannot attach event\n");
    exit(1);
  }    
  ioctl(fd1, PERF_EVENT_IOC_ID, &id_enter_mmap);

  pea.config = 100;  // see: /sys/kernel/debug/tracing/events/syscalls/sys_exit_mmap/id
  fd2 = syscall(__NR_perf_event_open, &pea, -1, 0, fd1, 0);
  if (fd2 == -1) {
    fprintf(stderr, "Error: cannot attach event\n");
    exit(1);
  }  
  ioctl(fd2, PERF_EVENT_IOC_ID, &id_exit_mmap);

  pea.config = 576;  // see: /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/id
  fd3 = syscall(__NR_perf_event_open, &pea, -1, 0, fd1, 0);
  if (fd3 == -1) {
    fprintf(stderr, "Error: cannot attach event\n");
    exit(1);
  }  
  ioctl(fd3, PERF_EVENT_IOC_ID, &id_enter_munmap);

  page_size = (size_t)sysconf(_SC_PAGESIZE);
  mmap_size = page_size * (mmap_pages + 1);
  mmap_buf = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd1, 0);
  if (mmap_buf == MAP_FAILED) {
    fprintf(stderr, "Error: cannot map buffer\n");
    exit(1);
  }

  // send samples for all events to first event's buffer
  ret = ioctl(fd2, PERF_EVENT_IOC_SET_OUTPUT, fd1);
  if (ret) {
    fprintf(stderr, "Error: cannot redirect sampling output\n");
    exit(1);
  }
  ret = ioctl(fd3, PERF_EVENT_IOC_SET_OUTPUT, fd1);
  if (ret) {
    fprintf(stderr, "Error: cannot redirect sampling output\n");
    exit(1);
  }

  // start sampling (from leader fd)
  ioctl(fd1, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
  ioctl(fd1, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

  struct pollfd pollfds[1];
  pollfds[0].fd = fd1;  // leader fd
  pollfds[0].events = POLLIN;

  for(;;) {
    ret = poll(pollfds, 1, -1);
    if (ret < 0 && errno == EINTR) {
      break;
    }
    process_smpl_buf(fd1);  // leader fd
  }

  return 0;

}

