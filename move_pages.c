#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <numa.h>
#include <numaif.h>             // move_pages()
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#define NODE_0_DRAM 0
#define NODE_1_DRAM 1
#define NODE_2_PMEM 2
#define NODE_3_PMEM 3

int main(int argc, char **argv)
{

    if (argc != 5) {
        fprintf(stderr, "need 4 args: <pid> <addr> <len> <numa_node>\n");
        return -1;
    }

    if ((numa_available() < 0)) {
        fprintf(stderr, "error: not a numa machine\n");
        return -1;
    }

    size_t pid = atol(argv[1]);
    size_t addr = atol(argv[2]);
    size_t len = atol(argv[3]);
    unsigned node = atol(argv[4]);

    //struct bitmask *new_nodes = numa_bitmask_alloc(num_nodes);
    //numa_bitmask_setbit(new_nodes, node);

    int num_nodes = numa_max_node() + 1;
    if (num_nodes < 2) {
        fprintf(stderr, "error: a minimum of 2 nodes is required\n");
        exit(1);
    }

    // len must be page-aligned
    size_t pagesize = getpagesize();
    assert((len % pagesize) == 0);

    unsigned long page_count = len / pagesize;
    void **pages_addr;
    int *status;
    int *nodes;

    pages_addr = malloc(sizeof(char *) * page_count);
    status = malloc(sizeof(int *) * page_count);
    nodes = malloc(sizeof(int *) * page_count);

    if (!pages_addr || !status || !nodes) {
       fprintf(stderr, "Unable to allocate memory\n");
       exit(1);
    }

    for (int i = 0; i < page_count; i++) {
        pages_addr[i] = (void *) addr + i * pagesize;
        nodes[i] = node;
        status[i] = -1;
    }

    printf("Moving pages of process %lu from addr = %lu, len = %lu, to numa node: %d\n", pid, addr, len, node);
    if (numa_move_pages(pid, page_count, pages_addr, nodes, status, MPOL_MF_MOVE) == -1) {
        fprintf(stderr, "error code: %d\n", errno);
        perror("error description:");
    }

    return 0;
}
