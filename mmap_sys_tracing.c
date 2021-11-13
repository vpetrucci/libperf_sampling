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

#define rmb()   asm volatile("lfence" ::: "memory")

struct __attribute__((__packed__)) sample {
    uint64_t ip;
    uint64_t addr;
    uint64_t weight;
    union perf_mem_data_src data_src;
};

struct read_format {
    uint64_t nr;
    struct {
        uint64_t value;
        uint64_t id;
    } values[ /*2 */ ];
};

static const int mmap_pages = 4;        // power of 2
static size_t page_size;
static size_t map_size;
struct perf_event_mmap_page *mmap_buf;

int main()
{
    struct perf_event_attr pea;
    int fd1, fd2, fd3;
    uint64_t id1, id2, id3;
    int ret;

    memset(&pea, 0, sizeof(struct perf_event_attr));

    pea.type = PERF_TYPE_TRACEPOINT;
    pea.size = sizeof(struct perf_event_attr);
    pea.disabled = 1;
    pea.exclude_kernel = 1;
    pea.exclude_hv = 1;
    pea.wakeup_events = 1;
    pea.sample_period = 1;
    pea.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_RAW;
    pea.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;

    pea.config = 101;           // see: /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/id  
    fd1 = syscall(__NR_perf_event_open, &pea, -1, 0, -1, 0);
    if (fd1 == -1) {
        fprintf(stderr, "Error: cannot attach event\n");
        exit(1);
    }
    ioctl(fd1, PERF_EVENT_IOC_ID, &id1);

    pea.config = 100;           // see: /sys/kernel/debug/tracing/events/syscalls/sys_exit_mmap/id
    fd2 = syscall(__NR_perf_event_open, &pea, -1, 0, fd1, 0);
    if (fd2 == -1) {
        fprintf(stderr, "Error: cannot attach event\n");
        exit(1);
    }
    ioctl(fd2, PERF_EVENT_IOC_ID, &id2);

    pea.config = 576;           // see: /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/id
    fd3 = syscall(__NR_perf_event_open, &pea, -1, 0, fd1, 0);
    if (fd3 == -1) {
        fprintf(stderr, "Error: cannot attach event\n");
        exit(1);
    }
    ioctl(fd3, PERF_EVENT_IOC_ID, &id3);

    page_size = (size_t) sysconf(_SC_PAGESIZE);
    map_size = page_size + page_size * mmap_pages;
    mmap_buf = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
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

    ioctl(fd1, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(fd1, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

    sleep(15);

    ioctl(fd1, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);

    // read from ring buffer
    uint64_t head = mmap_buf->data_head;

    printf("head: %lld\n", head);

    rmb();

    struct perf_event_header *header = (struct perf_event_header *) ((char *) mmap_buf + page_size);
    uint64_t consumed = 0;

    while (consumed < head) {
        if (header->size == 0) {
            fprintf(stderr, "Error: invalid header size = 0\n");
            return -1;
        }

        printf("type: %d\n", header->type);
        if (header->type == PERF_RECORD_SAMPLE) {

            struct sample *sample = (struct sample *) ((char *) (header) + 8);

            printf("pc=%" PRIx64 "\n", sample->ip);

        }

        consumed += header->size;
        header = (struct perf_event_header *) ((char *) header + header->size);

    }

    printf("head = %" PRIu64 " compared to max = %zu\n", head, map_size);

    return 0;

}
