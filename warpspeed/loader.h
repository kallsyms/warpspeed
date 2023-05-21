// https://github.com/darlinghq/darling/blob/master/src/startup/mldr/loader.h
#ifndef _MLDR_LOADER_H_
#define _MLDR_LOADER_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <mach-o/loader.h>

struct vm_mmap {
    void *hyper;
    void *guest_pa;
    void *guest_va;
    size_t len;
    int prot;
};

struct load_results {
	unsigned long mh;
	unsigned long entry_point;
	unsigned long stack_size;
	unsigned long dyld_all_image_location;
	unsigned long dyld_all_image_size;
	uint8_t uuid[16];

	unsigned long vm_addr_max;
	bool _32on64;
	unsigned long base;
	uint32_t bprefs[4];
	char* root_path;
	size_t root_path_length;
	unsigned long stack_top;
	char* socket_path;
	int kernfd;
	int lifetime_pipe;

	size_t argc;
	size_t envc;
	char** argv;
	char** envp;

    // ghost: TODO TERRIBEL
    size_t n_mappings;
    struct vm_mmap mappings[100];
};

void load(const char* path, bool expect_dylinker, struct load_results* lr);
void setup_stack64(const char* filepath, struct load_results* lr);

#endif // _MLDR_LOADER_H_
