#include <linux/perf_event.h>
#include <linux/types.h>
#include <perf/core.h>
#include <perf/cpumap.h>
#include <perf/event.h>
#include <perf/evlist.h>
#include <perf/evsel.h>
#include <perf/mmap.h>
#include <perf/threadmap.h>
#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <event.h>

static int libperf_print(enum libperf_print_level level, const char *fmt, va_list ap)
{
    return vfprintf(stderr, fmt, ap);
}

/*const char *path_sys_enter_mmap = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/id";

static int filename__read_int(const char *filename, int *value)
{
    char line[64];
    int fd = open(filename, O_RDONLY), err = -1;

    if (fd < 0)
        return -1;

    if (read(fd, line, sizeof(line)) > 0) {
        *value = atoi(line);
        err = 0;
    }

    close(fd);
    return err;
}*/

static int count = 0;

void event_handler(int signum, siginfo_t * info, void *uc)
{
    count++;
}

int main(int argc, char **argv)
{
    struct perf_evlist *evlist;
    struct perf_evsel *evsel;
    struct perf_mmap *map;
    struct perf_cpu_map *cpus;
    struct perf_event_attr attr = {
        .type = PERF_TYPE_TRACEPOINT,
        .sample_period = 1,
        .wakeup_watermark = 1,
        .disabled = 1,
	.watermark = 0,
	.wakeup_events = 1,
        //.exclude_kernel    = 1,
        .exclude_callchain_kernel = 1,
        //.exclude_callchain_user = 0,
        .sample_stack_user = 2048,
        //.branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_ANY,
        //.sample_type = PERF_SAMPLE_BRANCH_STACK,
        .sample_type = PERF_SAMPLE_ID | PERF_SAMPLE_RAW | PERF_SAMPLE_STACK_USER,
    };

    /*iint id;
       if (filename__read_int(path_sys_enter_mmap, &id)) {
       fprintf(stderr, "Error: failed to read tracepoint id: %s - ", path_sys_enter_mmap);
       perror("");
       return -1;
       } */
    //attr.config = id;
    attr.config = 101 | 100 | 576;      // (syscalls/sys_enter_mmap && syscalls/sys_exit_mmap && syscalls/sys_enter_munmap)

    int err = -1;
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

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to create load event\n");
        goto out_cpus;
    }

    perf_evlist__add(evlist, evsel);
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

    #define FD(e, x, y) (*(int *)xyarray__entry(e->fd, x, y))
    //int evt_fd = FD(evsel, cpus, 0);
    //int get_group_fd

    //struct xyarray *xy = evsel->fd;
    //int num_events = xy->entries / (xy->row_size / xy->entry_size);
    //int evt_fd = xyarray__entry(xy, 0, 0);
    //printf("events: %d, fd: %d\n", num_events, evt_fd);
    //printf("fd: %d\n", evt_fd);

    union perf_event *event;

    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = event_handler;
    assert(sigaction(SIGIO, &sa, NULL) != -1);

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGIO);

    sigprocmask(SIG_BLOCK, &mask, &oldmask);
    while (count < 2) {
        sigsuspend(&oldmask);
    }
    printf("finish...\n");
    exit(0);

    while (1) {
        perf_evlist__enable(evlist);
        sleep(1);
        perf_evlist__disable(evlist);

        printf("-----\n");

        perf_evlist__for_each_mmap(evlist, map, false) {
            if (perf_mmap__read_init(map) < 0)
                continue;

            while ((event = perf_mmap__read_event(map)) != NULL) {
                const __u32 type = event->header.type;
                __u64 sample_id, *array;
                //const u64 *pdata;
                //struct perf_sample sample;

                if (type != PERF_RECORD_SAMPLE) {
                    perf_mmap__consume(map);
                    continue;
                }
                //perf_evsel__parse_sample(evsel, event, &sample);

                /*array = event->sample.array;

                   sample_id = *array;
                   array++;

                   printf("sample_id: %lld\n", sample_id);
                 */

                //printf("sample_id: %lld\n", sample.id);

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
