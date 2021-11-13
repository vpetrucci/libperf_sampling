#gcc -o e2p event2perf.c -lpfm

gcc -g -I/include -o sampling_mem sampling_mem.c -lperf -lpfm

gcc -g -I/include -o mmap_sys_tracing mmap_sys_tracing2.c -lperf

#gcc -g -I/include -I /home/cc/linux-5.14.16/tools/lib/perf/include/ -I /home/cc/linux-5.14.16/include/ -I /usr/src/linux-headers-5.14.0-1005-oem/arch/x86/include/generated/ -o mmap_tracing2 mmap_tracing2.c -lperf
