// https://github.com/darlinghq/darling/blob/master/src/startup/mldr/commpage.c
#include "commpage.h"
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <tgmath.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static const char* SIGNATURE32 = "commpage 32-bit";
static const char* SIGNATURE64 = "commpage 64-bit";

static uint64_t get_cpu_caps(void);

#define CGET(p) (commpage + ((p)-_COMM_PAGE64_BASE_ADDRESS))

void commpage_setup(uint8_t *commpage)
{
	uint64_t* cpu_caps64;
	uint32_t* cpu_caps;
	uint16_t* version;
	char* signature;
	uint64_t my_caps;
	uint8_t *ncpus, *nactivecpus;
	uint8_t *physcpus, *logcpus;
	uint8_t *user_page_shift, *kernel_page_shift;

    fprintf(stderr, "Setting up commpage at %p\n", commpage);

	signature = (char*)CGET(_COMM_PAGE_SIGNATURE);
	version = (uint16_t*)CGET(_COMM_PAGE_VERSION);
	cpu_caps64 = (uint64_t*)CGET(_COMM_PAGE_CPU_CAPABILITIES64);
   	cpu_caps = (uint32_t*)CGET(_COMM_PAGE_CPU_CAPABILITIES);

	strcpy(signature, SIGNATURE64);
	*version = _COMM_PAGE_THIS_VERSION;

	ncpus = (uint8_t*)CGET(_COMM_PAGE_NCPUS);
    *ncpus = 1;  // ghost
	//*ncpus = sysconf(_SC_NPROCESSORS_CONF);

	nactivecpus = (uint8_t*)CGET(_COMM_PAGE_ACTIVE_CPUS);
    *nactivecpus = 1;  // ghost
	//*nactivecpus = sysconf(_SC_NPROCESSORS_ONLN);

	// Better imprecise information than no information
	physcpus = (uint8_t*)CGET(_COMM_PAGE_PHYSICAL_CPUS);
	logcpus = (uint8_t*)CGET(_COMM_PAGE_LOGICAL_CPUS);
	*physcpus = *logcpus = *ncpus;

	// I'm not sure if Linux has seperate page sizes for kernel and user space.
	// Apple's code uses left shift logical (1 << user_page_shift) to get the page size value.
	// Since it's very unlikely that the page size won't be a power of 2, we can use __builtin_ctzl()
	// as a substitute for log2().
	user_page_shift = (uint8_t*)CGET(_COMM_PAGE_USER_PAGE_SHIFT_64);
	kernel_page_shift = (uint8_t*)CGET(_COMM_PAGE_KERNEL_PAGE_SHIFT);
	*kernel_page_shift = *user_page_shift = (uint8_t)__builtin_ctzl(sysconf(_SC_PAGESIZE));

	my_caps = get_cpu_caps();
	if (*ncpus == 1)
		my_caps |= kUP;

	*cpu_caps = (uint32_t) my_caps;
	*cpu_caps64 = my_caps;

    uint64_t* memsize = (uint64_t*)CGET(_COMM_PAGE_MEMORY_SIZE);
    *memsize = 1 * 1024 * 1024 * 1024;  // ghost: no idea if correct
}

uint64_t get_cpu_caps(void)
{
	uint64_t caps = 0;

    // ghost: TODO
	return caps;
}
