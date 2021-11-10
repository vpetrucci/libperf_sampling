/home/cc/gapbs/bc -f /home/cc/gapbs/benchmark/kron.sg -n1 & 
pid=$!
sudo perf record --call-graph dwarf -e syscalls:sys_enter_mmap -aR &
wait $pid
sudo killall perf

