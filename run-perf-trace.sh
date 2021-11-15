sudo perf trace -e syscalls:sys_enter_mmap,syscalls:sys_exit_mmap -- ./prog_wait
