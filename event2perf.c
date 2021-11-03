/**
 * This example program converts PMU event names into perf configurations.
 * All libpfm events are supported.
 *
 * To get a list of possible events, run libpfm's
 *   $ ./exmaples/showevtinfo -L
 *
 * This code is adopted from libpfm's examples/check_events.c
 * 2014, Jeremia Baer <baerj@student.ethz.ch>
 */

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>

#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>

int pmu_is_present(pfm_pmu_t p)
{
	pfm_pmu_info_t pinfo;
	int ret;

	memset(&pinfo, 0, sizeof(pinfo));
	ret = pfm_get_pmu_info(p, &pinfo);
	return ret == PFM_SUCCESS ? pinfo.is_present : 0;
}

int main(int argc, const char **argv)
{
	int i, j, ret;
	const char **p; // list of events to check
	pfm_pmu_encode_arg_t   pmu_encoded;
	pfm_perf_encode_arg_t  perf_encoded;
	struct perf_event_attr perf_attr;

	// Initialize pfm library (required before we can use it)
	ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
		errx(1, "cannot initialize library: %s\n", pfm_strerror(ret));

	// Which event to check...
	const char *arg[3];
	if (argc < 2  && pmu_is_present(PFM_PMU_PERF_EVENT)) {
		printf("You can provide events as arguments!\n");
		printf("Showing examples...\n");
		arg[0] = "PERF_COUNT_HW_CPU_CYCLES";
		arg[1] = "PERF_COUNT_HW_INSTRUCTIONS";
		arg[2] = NULL;
		p = arg;
	} else {
		p = argv+1;
	}

	if (!*p)
		errx(1, "you must pass at least one event");

	// Go trough all events
	memset(&pmu_encoded, 0, sizeof(pmu_encoded));
	memset(&perf_encoded, 0, sizeof(perf_encoded));
	while(*p) {
		char *fqstr = NULL;
		pmu_encoded.fstr = &fqstr;
		perf_encoded.size = sizeof(perf_encoded);
		perf_encoded.attr = &perf_attr;
		memset(&perf_attr, 0, sizeof(perf_attr));
		
		// pfm_get_os_event_encoding:
		//   event_string
		//   privilege_levels
		//   os_type
		//     PFM_OS_NONE        -> pfm_pmu_encode_arg_t
		//     PERF_OS_PERF_EVENT -> pfm_perf_encode_arg_t
		//   encoding (corresponding to os_type)
		ret = pfm_get_os_event_encoding(*p, PFM_PLM0|PFM_PLM3, PFM_OS_NONE, &pmu_encoded);
		if (ret != PFM_SUCCESS) {
			errx(1, "cannot encode event %s: %s", *p, pfm_strerror(ret));
		}
		ret = pfm_get_os_event_encoding(*p, PFM_PLM3, PFM_OS_PERF_EVENT, &perf_encoded);
		if (ret != PFM_SUCCESS) {
			errx(1, "cannot encode event %s: %s", *p, pfm_strerror(ret));
		}

		printf("==================================================\n");
		printf("Requested Event : %s\n", *p);
		printf("Actual Event    : %s\n", fqstr);
		printf("IDX             : %d\n", pmu_encoded.idx);
		printf("Codes           :");
		for(j=0; j < pmu_encoded.count; j++) {
			printf(" 0x%"PRIx64, pmu_encoded.codes[j]);
		}
		putchar('\n');
		//printf("perf idx: %d\n", perf_encoded.idx);
		printf("Perf            : TYPE   = %"PRIx64"\n",
			perf_attr.type);
		printf("                  CONFIG = %"PRIx64"\n",
			perf_attr.config);

		free(fqstr);
		p++;
	}
	// cleanup
	if (pmu_encoded.codes) {
		free(pmu_encoded.codes);
	}

	// done
	return 0;
}
