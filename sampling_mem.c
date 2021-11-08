#include <linux/perf_event.h>
#include <perf/evlist.h>
#include <perf/evsel.h>
#include <perf/cpumap.h>
#include <perf/threadmap.h>
#include <perf/mmap.h>
#include <perf/core.h>
#include <perf/event.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <perfmon/pfmlib_perf_event.h>

char *concat(const char *s1, const char *s2)
{
	char *result = malloc(strlen(s1) + strlen(s2) + 1);
	if (result == NULL) {
		return "malloc failed in concat\n";
	}
	strcpy(result, s1);
	strcat(result, s2);
	return result;
}

int is_served_by_local_cache1(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		if (data_src.mem_lvl & PERF_MEM_LVL_L1) {
			return 1;
		}
	}
	return 0;
}

int is_served_by_local_cache2(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		if (data_src.mem_lvl & PERF_MEM_LVL_L2) {
			return 1;
		}
	}
	return 0;
}

int is_served_by_local_cache3(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		if (data_src.mem_lvl & PERF_MEM_LVL_L3) {
			return 1;
		}
	}
	return 0;
}

int is_served_by_local_lfb(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		if (data_src.mem_lvl & PERF_MEM_LVL_LFB) {
			return 1;
		}
	}
	return 0;
}

int is_served_by_local_cache(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		if (data_src.mem_lvl & PERF_MEM_LVL_L1) {
			return 1;
		}
		if (data_src.mem_lvl & PERF_MEM_LVL_LFB) {
			return 1;
		}
		if (data_src.mem_lvl & PERF_MEM_LVL_L2) {
			return 1;
		}
		if (data_src.mem_lvl & PERF_MEM_LVL_L3) {
			return 1;
		}
	}
	return 0;
}

int is_served_by_local_memory(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		if (data_src.mem_lvl & PERF_MEM_LVL_LOC_RAM) {
			return 1;
		}
	}
	return 0;
}

int is_served_by_remote_cache_or_local_memory(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT
	    && data_src.mem_lvl & PERF_MEM_LVL_REM_CCE1) {
		return 1;
	}
	return 0;
}

int is_served_by_remote_memory(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		if (data_src.mem_lvl & PERF_MEM_LVL_REM_RAM1) {
			return 1;
		} else if (data_src.mem_lvl & PERF_MEM_LVL_REM_RAM2) {
			return 1;
		}
	}
	return 0;
}

int is_served_by_local_NA_miss(union perf_mem_data_src data_src)
{
	if (data_src.mem_lvl & PERF_MEM_LVL_NA) {
		return 1;
	}
	if (data_src.mem_lvl & PERF_MEM_LVL_MISS
	    && data_src.mem_lvl & PERF_MEM_LVL_L3) {
		return 1;
	}
	return 0;
}

char *get_data_src_opcode(union perf_mem_data_src data_src)
{
	char *res = concat("", "");
	char *old_res;
	if (data_src.mem_op & PERF_MEM_OP_NA) {
		old_res = res;
		res = concat(res, "NA");
		free(old_res);
	}
	if (data_src.mem_op & PERF_MEM_OP_LOAD) {
		old_res = res;
		res = concat(res, "Load");
		free(old_res);
	}
	if (data_src.mem_op & PERF_MEM_OP_STORE) {
		old_res = res;
		res = concat(res, "Store");
		free(old_res);
	}
	if (data_src.mem_op & PERF_MEM_OP_PFETCH) {
		old_res = res;
		res = concat(res, "Prefetch");
		free(old_res);
	}
	if (data_src.mem_op & PERF_MEM_OP_EXEC) {
		old_res = res;
		res = concat(res, "Exec code");
		free(old_res);
	}
	return res;
}

char *get_data_src_level(union perf_mem_data_src data_src)
{
	char *res = concat("", "");
	char *old_res;
	if (data_src.mem_lvl & PERF_MEM_LVL_NA) {
		old_res = res;
		res = concat(res, "NA");
		free(old_res);
	}
	if (data_src.mem_lvl & PERF_MEM_LVL_L1) {
		old_res = res;
		res = concat(res, "L1");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_LFB) {
		old_res = res;
		res = concat(res, "LFB");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_L2) {
		old_res = res;
		res = concat(res, "L2");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_L3) {
		old_res = res;
		res = concat(res, "L3");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_LOC_RAM) {
		old_res = res;
		res = concat(res, "Local_RAM");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_REM_RAM1) {
		old_res = res;
		res = concat(res, "Remote_RAM_1_hop");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_REM_RAM2) {
		old_res = res;
		res = concat(res, "Remote_RAM_2_hops");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_REM_CCE1) {
		old_res = res;
		res = concat(res, "Remote_Cache_1_hop");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_REM_CCE2) {
		old_res = res;
		res = concat(res, "Remote_Cache_2_hops");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_IO) {
		old_res = res;
		res = concat(res, "I/O_Memory");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_UNC) {
		old_res = res;
		res = concat(res, "Uncached_Memory");
		free(old_res);
	}
	if (data_src.mem_lvl & PERF_MEM_LVL_HIT) {
		old_res = res;
		res = concat(res, "_Hit");
		free(old_res);
	} else if (data_src.mem_lvl & PERF_MEM_LVL_MISS) {
		old_res = res;
		res = concat(res, "_Miss");
		free(old_res);
	}
	return res;
}

static int
libperf_print(enum libperf_print_level level, const char *fmt, va_list ap)
{
	return vfprintf(stderr, fmt, ap);
}

union u64_swap {
	__u64 val64;
	__u32 val32[2];
};

int encode_event(const char *event_name)
{
	pfm_perf_encode_arg_t perf_encoded;
	struct perf_event_attr perf_attr;
	memset(&perf_encoded, 0, sizeof(perf_encoded));
	perf_encoded.size = sizeof(perf_encoded);
	perf_encoded.attr = &perf_attr;
	memset(&perf_attr, 0, sizeof(perf_attr));

	int ret =
	    pfm_get_os_event_encoding(event_name, PFM_PLM3, PFM_OS_PERF_EVENT,
				      &perf_encoded);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "cannot encode event %s: %s", event_name,
			pfm_strerror(ret));
		return -1;
	}

	return perf_attr.config;
}

int main(int argc, char **argv)
{
	struct perf_evlist *evlist;
	struct perf_evsel *load_evsel;
	struct perf_evsel *store_evsel;
	struct perf_mmap *map;
	struct perf_cpu_map *cpus;

	int curr_err = pfm_initialize();
	if (curr_err != PFM_SUCCESS) {
		return -1;
	}

	int load_event = encode_event("MEM_TRANS_RETIRED:LOAD_LATENCY:ldlat=3");
	assert(load_event != -1);

	int store_event = encode_event("MEM_UOPS_RETIRED:ALL_STORES");
	assert(store_event != -1);

	struct perf_event_attr load_attr = {
		.type = PERF_TYPE_RAW,
		//.config = 0x1cd,      // see libpfm4
		.config = load_event,	// see libpfm4
		.disabled = 1,
		.precise_ip = 2,
		.exclude_kernel = 1,
		.exclude_user = 0,
		.exclude_hv = 1,
		.freq = 1,
		.sample_freq = 100,
		//.sample_period = 1000,
		//.sample_type = PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_CPU|PERF_SAMPLE_PERIOD,
		.sample_type =
		    PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CPU |
		    PERF_SAMPLE_WEIGHT | PERF_SAMPLE_DATA_SRC,
	};
	struct perf_event_attr store_attr = {
		.type = PERF_TYPE_RAW,
		//.config = 0x82d0,      // see libpfm4
		.config = store_event,	// see libpfm4
		.disabled = 1,
		.precise_ip = 2,
		.exclude_kernel = 1,
		.exclude_user = 0,
		.exclude_hv = 1,
		//.freq = 1,
		//.sample_freq = 100,
		.sample_period = 1000,
		//.sample_type = PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_CPU|PERF_SAMPLE_PERIOD,
		.sample_type =
		    PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CPU |
		    PERF_SAMPLE_WEIGHT | PERF_SAMPLE_DATA_SRC,
	};

	int err = -1;
	union perf_event *event;

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

	load_evsel = perf_evsel__new(&load_attr);
	if (!load_evsel) {
		fprintf(stderr, "failed to create load event\n");
		goto out_cpus;
	}
	store_evsel = perf_evsel__new(&store_attr);
	if (!store_evsel) {
		fprintf(stderr, "failed to create load event\n");
		goto out_cpus;
	}

	perf_evlist__add(evlist, load_evsel);
	//perf_evlist__add(evlist, store_evsel);

	perf_evlist__set_maps(evlist, cpus, NULL);

	err = perf_evlist__open(evlist);
	if (err) {
		fprintf(stderr, "failed to open evlist\n");
		goto out_evlist;
	}

	err = perf_evlist__mmap(evlist, 64);
	if (err) {
		fprintf(stderr, "failed to mmap evlist\n");
		goto out_evlist;
	}

	while (1) {

		perf_evlist__enable(evlist);
		//perf_evlist__poll(evlist, 1000);
		sleep(5);
		perf_evlist__disable(evlist);

                printf("-----\n");

		perf_evlist__for_each_mmap(evlist, map, false) {
			if (perf_mmap__read_init(map) < 0)
				continue;

			while ((event = perf_mmap__read_event(map)) != NULL) {
				int cpu, pid, tid;
				__u64 ip, weight, *array;
				union u64_swap u;
				union perf_mem_data_src data_src;

				int na_miss_count = 0;
				int cache1_count = 0;
				int cache2_count = 0;
				int cache3_count = 0;
				int lfb_count = 0;
				int memory_count = 0;
				int remote_memory_count = 0;
				int remote_cache_count = 0;
				int total_count = 0;

				array = event->sample.array;

				ip = *array;
				array++;

				u.val64 = *array;
				pid = u.val32[0];
				tid = u.val32[1];
				array++;

				u.val64 = *array;
				cpu = u.val32[0];
				array++;

				weight = *array;
				array++;

				data_src.val = *array;

				if (is_served_by_local_NA_miss(data_src)) {
					na_miss_count++;
				}
				if (is_served_by_local_cache1(data_src)) {
					cache1_count++;
				}
				if (is_served_by_local_cache2(data_src)) {
					cache2_count++;
				}
				if (is_served_by_local_cache3(data_src)) {
					cache3_count++;
				}
				if (is_served_by_local_lfb(data_src)) {
					lfb_count++;
				}
				if (is_served_by_local_memory(data_src)) {
					memory_count++;
				}
				if (is_served_by_remote_memory(data_src)) {
					remote_memory_count++;
				}
				if (is_served_by_remote_cache_or_local_memory
				    (data_src)) {
					remote_cache_count++;
				}
				total_count++;

				fprintf(stdout,
					"cpu: %3d, pid: %6d, tid: %6d, ip: %20llx, src level: %s, latency: %6lld\n",
					cpu, pid, tid, ip,
					get_data_src_level(data_src), weight);

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
