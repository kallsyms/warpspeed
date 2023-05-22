// https://github.com/darlinghq/darling/blob/master/src/startup/mldr/loader.c
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "common.h"
#include "commpage.h"
#include "loader.h"

#ifndef PAGE_SIZE
#	define PAGE_SIZE	16384
#endif
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE-1))
#define PAGE_ROUNDUP(x) (((((x)-1) / PAGE_SIZE)+1) * PAGE_SIZE)

#define MAP_FIXED_NOREPLACE MAP_FIXED
static void* compatible_mmap(struct load_results *lr, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (addr == 0) {
        return MAP_FAILED;
    }
    length = PAGE_ROUNDUP(length);

    LOG("alloc %lu = mmap(addr=%p, len=0x%lx, prot=0x%x, flags=0x%x, fd=%d, offset=%llx)\n", lr->n_mappings, addr, length, prot, flags, fd, offset);

    if (lr->n_mappings > 0 && lr->mappings[lr->n_mappings - 1].guest_va == addr) {
        struct vm_mmap prev = lr->mappings[lr->n_mappings - 1];
        if (prev.len != length || prev.prot != prot) {
            LOG("prior %p alloc was ( %lx, %x), now is (%lx, %x)\n", addr, prev.len, prev.prot, length, prot);
        }
    } else {
        lr->mappings[lr->n_mappings++] = (struct vm_mmap){
            .hyper = addr,
            .guest_va = addr,
            .len = length,
            .prot = prot,
        };
    }
    return mmap(addr, length, PROT_READ | PROT_WRITE, flags | MAP_PRIVATE, fd, offset);
}

// https://github.com/darlinghq/darling/blob/dec20ddf3892ff35f0a688a047d8931faf4471c4/src/startup/mldr/mldr.c#L454
static int native_prot(int prot)
{
	int protOut = 0;

	if (prot & VM_PROT_READ)
		protOut |= PROT_READ;
	if (prot & VM_PROT_WRITE)
		protOut |= PROT_WRITE;
	if (prot & VM_PROT_EXECUTE)
		protOut |= PROT_EXEC;

	return protOut;
}

// fwd decl
static void load64(int fd, bool expect_dylinker, struct load_results* lr);

// https://github.com/darlinghq/darling/blob/dec20ddf3892ff35f0a688a047d8931faf4471c4/src/startup/mldr/mldr.c#LL332C1
static void load_fat(int fd, bool expect_dylinker, struct load_results* lr) {
	struct fat_header fhdr;
	int bpref_index = -1;

	if (read(fd, &fhdr, sizeof(fhdr)) != sizeof(fhdr))
	{
		LOG("Cannot read fat file header.\n");
		exit(1);
	}

    const bool swap = fhdr.magic == FAT_CIGAM;

// https://gist.github.com/atr000/249599
#define bswap_16(value) \
((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define SWAP32(x) x = bswap_32(x)

	if (swap)
		SWAP32(fhdr.nfat_arch);

	uint32_t i;
	for (i = 0; i < fhdr.nfat_arch; i++)
	{
		struct fat_arch arch;

		if (read(fd, &arch, sizeof(arch)) != sizeof(arch))
		{
			LOG("Cannot read fat_arch header.\n");
			exit(1);
		}

        if (swap)
		{
			SWAP32(arch.cputype);
			SWAP32(arch.cpusubtype);
			SWAP32(arch.offset);
			SWAP32(arch.size);
			SWAP32(arch.align);
		}

        // ghost: !forced_arch removed - always look for arm64
        if (arch.cputype == CPU_TYPE_ARM64) {
            LOG("Found arm64 part of fat binary\n");
            if (lseek(fd, arch.offset, SEEK_SET) == -1)
            {
                LOG("Cannot seek to selected arch in fat binary.\n");
                exit(1);
            }
            load64(fd, expect_dylinker, lr);
            return;
        }
	}

    LOG("No supported architecture found in fat binary.\n");
    exit(1);
}

// https://github.com/darlinghq/darling/blob/dec20ddf3892ff35f0a688a047d8931faf4471c4/src/startup/mldr/mldr.c#L275
void load(const char* path, bool expect_dylinker, struct load_results* lr)
{
	int fd;
	uint32_t magic;

	fd = open(path, O_RDONLY);
	if (fd == -1)
	{
		LOG("Cannot open %s: %s\n", path, strerror(errno));
		exit(1);
	}

	// We need to read argv[1] and detect whether it's a 32 or 64-bit application.
	// Then load the appropriate version of dyld from the fat file.
	// In case the to-be-executed executable contains both, we prefer the 64-bit version,
	// unless a special property has been passed to sys_posix_spawn() to force the 32-bit
	// version. See posix_spawnattr_setbinpref_np().

	if (read(fd, &magic, sizeof(magic)) != sizeof(magic))
	{
		LOG("Cannot read the file header of %s.\n", path);
		exit(1);
	}

	if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
	{
		lseek(fd, 0, SEEK_SET);
        LOG("Loading 64bit binary %s\n", path);
		load64(fd, expect_dylinker, lr);
	}
	else if (magic == FAT_MAGIC || magic == FAT_CIGAM)
	{
		lseek(fd, 0, SEEK_SET);
        LOG("Loading fat binary %s\n", path);
		load_fat(fd, expect_dylinker, lr);
	}
	else
	{
		LOG("Unknown file format: %s.\n", path);
		exit(1);
	}

	close(fd);
}

static void setup_space(struct load_results* lr, bool is_64_bit) {
    LOG("setup_space\n");

	uint8_t *commpage = (uint8_t*) mmap((void*)0xf00d0000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (commpage == MAP_FAILED)
	{
		LOG("Cannot mmap commpage: %s\n", strerror(errno));
		exit(1);
	}
    lr->mappings[lr->n_mappings++] = (struct vm_mmap){
        .hyper = commpage,
        .guest_va = _COMM_PAGE64_BASE_ADDRESS,
        .len = PAGE_SIZE,
        .prot = PROT_READ | PROT_WRITE,
    };
    lr->mappings[lr->n_mappings++] = (struct vm_mmap){
        .hyper = commpage,
        .guest_va = _COMM_PAGE64_RO_ADDRESS,
        .len = PAGE_SIZE,
        .prot = PROT_READ,
    };
    commpage_setup(commpage);

	struct rlimit limit;
	getrlimit(RLIMIT_STACK, &limit);
	// allocate a few pages 16 pages if it's less than the limit; otherwise, allocate the limit
	unsigned long size = PAGE_SIZE * 16;
	if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < size) {
		size = limit.rlim_cur;
	}
    size = PAGE_ROUNDUP(size);

	uint8_t *stack = (uint8_t*) mmap((void*)0xdead0000, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED)
	{
		LOG("Cannot mmap stack: %s\n", strerror(errno));
		exit(1);
	}
    lr->mappings[lr->n_mappings++] = (struct vm_mmap){
        .hyper = stack,
        .guest_va = stack,
        .len = size,
        .prot = PROT_READ | PROT_WRITE,
    };
    lr->stack_top = stack + size - 0x1000;

}


// Definitions:
// FUNCTION_NAME (load32/load64)
// SEGMENT_STRUCT (segment_command/SEGMENT_STRUCT)
// SEGMENT_COMMAND (LC_SEGMENT/SEGMENT_COMMAND)
// MACH_HEADER_STRUCT (mach_header/MACH_HEADER_STRUCT)
// SECTION_STRUCT (section/SECTION_STRUCT)

#define FUNCTION_NAME load64
#define SEGMENT_STRUCT segment_command_64
#define SEGMENT_COMMAND LC_SEGMENT_64
#define MACH_HEADER_STRUCT mach_header_64
#define SECTION_STRUCT section_64
#define MAP_EXTRA 0

static void FUNCTION_NAME(int fd, bool expect_dylinker, struct load_results* lr)
{
	struct MACH_HEADER_STRUCT header;
	uint8_t* cmds;
	uintptr_t entryPoint = 0, entryPointDylinker = 0;
	struct MACH_HEADER_STRUCT* mappedHeader = NULL;
	uintptr_t slide = 0;
	uintptr_t mmapSize = 0;
	bool pie = false;
	uint32_t fat_offset;
	void* tmp_map_base = NULL;

	if (!expect_dylinker)
	{
		setup_space(lr, true);
	}

	fat_offset = lseek(fd, 0, SEEK_CUR);

	if (read(fd, &header, sizeof(header)) != sizeof(header))
	{
		LOG("Cannot read the mach header.\n");
		exit(1);
	}

	if (header.filetype != (expect_dylinker ? MH_DYLINKER : MH_EXECUTE))
	{
		LOG("Found unexpected Mach-O file type: %u\n", header.filetype);
		exit(1);
	}

	tmp_map_base = mmap(NULL, PAGE_ROUNDUP(sizeof(header) + header.sizeofcmds), PROT_READ, MAP_PRIVATE, fd, fat_offset);
	if (tmp_map_base == MAP_FAILED) {
		LOG("Failed to mmap header + commands\n");
		exit(1);
	}

	cmds = (void*)((char*)tmp_map_base + sizeof(header));

	if ((header.filetype == MH_EXECUTE && header.flags & MH_PIE) || header.filetype == MH_DYLINKER)
	{
		uintptr_t base = -1;

		// Go through all SEGMENT_COMMAND commands to get the total continuous range required.
		for (uint32_t i = 0, p = 0; i < header.ncmds; i++)
		{
			struct SEGMENT_STRUCT* seg = (struct SEGMENT_STRUCT*) &cmds[p];

			// Load commands are always sorted, so this will get us the maximum address.
			if (seg->cmd == SEGMENT_COMMAND && strcmp(seg->segname, "__PAGEZERO") != 0)
			{
				if (base == -1)
				{
					base = seg->vmaddr;
					//if (base != 0 && header.filetype == MH_DYLINKER)
					//	goto no_slide;
				}
				mmapSize = seg->vmaddr + seg->vmsize - base;
			}

			p += seg->cmdsize;
		}

		slide = (uintptr_t) mmap((void*) base, mmapSize, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_EXTRA, -1, 0);
		if (slide == (uintptr_t)MAP_FAILED)
		{
			LOG("Cannot mmap anonymous memory range: %s\n", strerror(errno));
			exit(1);
		}

		// unmap it so we can map the actual segments later using MAP_FIXED_NOREPLACE;
		// we're the only thread running, so there's no chance this memory range will become occupied from now until then
		munmap((void*)slide, mmapSize);

		if (slide + mmapSize > lr->vm_addr_max)
			lr->vm_addr_max = lr->base = slide + mmapSize;
		slide -= base;

		pie = true;
	}

    LOG("slide: %lx\n", slide);

	for (uint32_t i = 0, p = 0; i < header.ncmds && p < header.sizeofcmds; i++)
	{
		struct load_command* lc;

		lc = (struct load_command*) &cmds[p];

		switch (lc->cmd)
		{
			case SEGMENT_COMMAND:
			{
				struct SEGMENT_STRUCT* seg = (struct SEGMENT_STRUCT*) lc;
				void* rv;

				// This logic is wrong and made up. But it's the only combination where
				// some apps stop crashing (TBD why) and LLDB recognized the memory layout
				// of processes started as suspended.
				int maxprot = native_prot(seg->maxprot);
				int initprot = native_prot(seg->initprot);
				int useprot = (initprot & PROT_EXEC) ? maxprot : initprot;

				if (seg->filesize < seg->vmsize)
				{
					unsigned long map_addr;
					if (slide != 0)
					{
						unsigned long addr = seg->vmaddr;

						if (addr != 0)
							addr += slide;

						// Some segments' filesize != vmsize, thus this mprotect().
                        LOG("segment fsz<vmsz, slide\n");
						rv = compatible_mmap(lr, (void*)addr, seg->vmsize, useprot, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
						if (rv == (void*)MAP_FAILED)
						{
							if (seg->vmaddr == 0 && useprot == 0) {
								// this is the PAGEZERO segment;
								// if we can't map it, assume everything is fine and the system has already made that area inaccessible
								rv = 0;
							} else {
								LOG("Cannot mmap segment %s at %p: %s\n", seg->segname, (void*)(uintptr_t)seg->vmaddr, strerror(errno));
								exit(1);
							}
						}
					}
					else
					{
						size_t size = seg->vmsize - seg->filesize;
                        LOG("segment fsz<vmsz, no slide\n");
						rv = compatible_mmap(lr, (void*) PAGE_ALIGN(seg->vmaddr + seg->vmsize - size), PAGE_ROUNDUP(size), useprot,
								MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
						if (rv == (void*)MAP_FAILED)
						{
							if (seg->vmaddr == 0 && useprot == 0) {
								// this is the PAGEZERO segment;
								// if we can't map it, assume everything is fine and the system has already made that area inaccessible
								rv = 0;
							} else {
								LOG("Cannot mmap segment %s at %p: %s\n", seg->segname, (void*)(uintptr_t)seg->vmaddr, strerror(errno));
								exit(1);
							}
						}
					}
				}

				if (seg->filesize > 0)
				{
					unsigned long addr = seg->vmaddr + slide;
					int flag = MAP_FIXED_NOREPLACE;
					if (seg->filesize < seg->vmsize) {
						flag = MAP_FIXED;
					}
                    LOG("segment fsz>0\n");
					rv = compatible_mmap(lr, (void*)addr, seg->filesize, useprot,
							flag | MAP_PRIVATE, fd, seg->fileoff + fat_offset);
					if (rv == (void*)MAP_FAILED)
					{
						if (seg->vmaddr == 0 && useprot == 0) {
							// this is the PAGEZERO segment;
							// if we can't map it, assume everything is fine and the system has already made that area inaccessible
							rv = 0;
						} else {
							LOG("Cannot mmap segment %s at %p: %s\n", seg->segname, (void*)(uintptr_t)seg->vmaddr, strerror(errno));
							exit(1);
						}
					}

					if (seg->fileoff == 0)
						mappedHeader = (struct MACH_HEADER_STRUCT*) (seg->vmaddr + slide);
				}

				if (seg->vmaddr + slide + seg->vmsize > lr->vm_addr_max)
					lr->vm_addr_max = seg->vmaddr + slide + seg->vmsize;

				if (strcmp(SEG_DATA, seg->segname) == 0)
				{
					// Look for section named __all_image_info for GDB integration
					struct SECTION_STRUCT* sect = (struct SECTION_STRUCT*) (seg+1);
					struct SECTION_STRUCT* end = (struct SECTION_STRUCT*) (&cmds[p + lc->cmdsize]);

					while (sect < end)
					{
						if (strncmp(sect->sectname, "__all_image_info", 16) == 0)
						{
							lr->dyld_all_image_location = slide + sect->addr;
							lr->dyld_all_image_size = sect->size;
							break;
						}
						sect++;
					}
				}
				break;
			}
			case LC_UNIXTHREAD:
			{
                uint32_t flavor = ((uint32_t*)lc)[2];
                switch (flavor) {
                    case ARM_THREAD_STATE64: {
                        entryPoint = ((uint32_t*)lc)[0x44];
                        entryPoint += slide;
                        LOG("unixthread entrypoint: %p\n", entryPoint);
                        break;
                    }
                    default:
                        LOG("unhandled unixthread flavor %d\n", flavor);
                        exit(1);
                        break;
                }
				break;
			}
			case LC_LOAD_DYLINKER:
			{
				if (header.filetype != MH_EXECUTE)
				{
					// dylinker can't reference another dylinker
					LOG("Dynamic linker can't reference another dynamic linker\n");
					exit(1);
				}

				struct dylinker_command* dy = (struct dylinker_command*) lc;
				char* path = NULL;
				size_t length = 0;
				static char path_buffer[4096] = {0};

				if (lr->root_path != NULL)
				{
					const size_t root_len = strlen(lr->root_path);
					const size_t linker_len = dy->cmdsize - dy->name.offset;

					length = linker_len + root_len;
					if (length > sizeof(path_buffer) - 1) {
						LOG("Dynamic loader path too long");
						exit(1);
					}
					path = path_buffer;

					// Concat root path and linker path
					memcpy(path, lr->root_path, root_len);
					memcpy(path + root_len, ((char*) dy) + dy->name.offset, linker_len);
					path[length] = '\0';
				}

				if (path == NULL)
				{
					length = dy->cmdsize - dy->name.offset;
					if (length > sizeof(path_buffer) - 1) {
						LOG("Dynamic loader path too long");
						exit(1);
					}
					path = path_buffer;

					memcpy(path, ((char*) dy) + dy->name.offset, length);
					path[length] = '\0';
				}

				if (path == NULL)
				{
					LOG("Failed to load dynamic linker for executable\n");
					exit(1);
				}

                LOG("Loading dylinker %s\n", path);
				load(path, true, lr);

				break;
			}
			case LC_MAIN:
			{
				struct entry_point_command* ee = (struct entry_point_command*) lc;
				if (ee->stacksize > lr->stack_size)
					lr->stack_size = ee->stacksize;
				break;
			}
			case LC_UUID:
			{
				if (header.filetype == MH_EXECUTE)
				{
					struct uuid_command* ue = (struct uuid_command*) lc;
					memcpy(lr->uuid, ue->uuid, sizeof(ue->uuid));
				}
				break;
			}
		}

		p += lc->cmdsize;
	}

	if (header.filetype == MH_EXECUTE)
		lr->mh = (uintptr_t) mappedHeader;
	if (entryPoint && !lr->entry_point) {
        LOG("setting entrypoint: %lx\n", entryPoint);
		lr->entry_point = entryPoint;
    }

	if (tmp_map_base)
		munmap(tmp_map_base, PAGE_ROUNDUP(sizeof(header) + header.sizeofcmds));
}


#undef FUNCTION_NAME
#undef SEGMENT_STRUCT
#undef SEGMENT_COMMAND
#undef MACH_HEADER_STRUCT
#undef SECTION_STRUCT
#undef MAP_EXTRA


// https://github.com/darlinghq/darling/blob/master/src/startup/mldr/stack.c
#define __user

#define EXECUTABLE_PATH "executable_path="

#define __put_user(value, pointer) ({ \
		__typeof__(value) _tmpval = (value); \
		memcpy((pointer), &_tmpval, sizeof(_tmpval)); \
		0; \
	})

void setup_stack64(const char* filepath, struct load_results* lr)
{
	int err = 0;
	// unsigned char rand_bytes[16];
	char *executable_path;
	static char executable_buf[4096];
	user_long_t __user* argv;
	user_long_t __user* envp;
	user_long_t __user* applep;
	user_long_t __user* sp;
	char __user* exepath_user;
	size_t exepath_len;
	char __user* kernfd_user;
	char kernfd[12];
	char __user* elfcalls_user;
	char elfcalls[27];
	char __user* applep_contents[4];

#define user_long_count(_val) (((_val) + (sizeof(user_long_t) - 1)) / sizeof(user_long_t))

	// Produce executable_path=... for applep
	executable_buf[sizeof(executable_buf) - 1] = '\0';
	strncpy(executable_buf, filepath, 4096);
	if (executable_buf[sizeof(executable_buf) - 1] != '\0')
	{
		LOG("File path was too big\n");
		exit(1);
	}

	executable_path = executable_buf;

	/* if (lr->root_path) */
	/* { */
	/* 	exepath_len = strlen(executable_path); */

	/* 	if (strncmp(executable_path, lr->root_path, lr->root_path_length) == 0) */
	/* 	{ */
	/* 		memmove(executable_buf, executable_path + lr->root_path_length, exepath_len - lr->root_path_length + 1); */
	/* 	} */
	/* 	else */
	/* 	{ */
	/* 		// FIXME: potential buffer overflow */
	/* 		memmove(executable_buf + sizeof(SYSTEM_ROOT) - 1, executable_path, exepath_len + 1); */
	/* 		memcpy(executable_buf, SYSTEM_ROOT, sizeof(SYSTEM_ROOT) - 1); */
	/* 	} */
	/* 	executable_path = executable_buf; */
	/* } */

	// printk(KERN_NOTICE "Stack top: %p\n", bprm->p);
	exepath_len = strlen(executable_path);
	sp = (user_long_t*) (lr->stack_top & ~(sizeof(user_long_t)-1));

	// 1 pointer for the mach header
	// 1 user_long_t for the argument count
	// `argc`-count pointers for arguments (+1 for NULL)
	// `envc`-count pointers for env vars (+1 for NULL)
	// `sizeof(applep_contents) / sizeof(*applep_contents)`-count pointers for applep arguments (already includes NULL)
	// space for exepath, kernfd, and elfcalls
	sp -= 1 + 1 + (lr->argc + 1) + (lr->envc + 1) + (sizeof(applep_contents) / sizeof(*applep_contents)) + user_long_count(exepath_len + sizeof(EXECUTABLE_PATH) + sizeof(kernfd) + sizeof(elfcalls));

	exepath_user = (char __user*) lr->stack_top - exepath_len - sizeof(EXECUTABLE_PATH);
	memcpy(exepath_user, EXECUTABLE_PATH, sizeof(EXECUTABLE_PATH)-1);
	memcpy(exepath_user + sizeof(EXECUTABLE_PATH)-1, executable_path, exepath_len + 1);

	snprintf(kernfd, sizeof(kernfd), "kernfd=%d", lr->kernfd);
	kernfd_user = exepath_user - sizeof(kernfd);
	memcpy(kernfd_user, kernfd, sizeof(kernfd));

	#define POINTER_FORMAT "%lx"

	/* snprintf(elfcalls, sizeof(elfcalls), "elf_calls=" POINTER_FORMAT, (unsigned long)(uintptr_t)&_elfcalls); */
	/* elfcalls_user = kernfd_user - sizeof(elfcalls); */
	/* memcpy(elfcalls_user, elfcalls, sizeof(elfcalls)); */

	applep_contents[0] = exepath_user;
	applep_contents[1] = kernfd_user;
	//applep_contents[2] = elfcalls_user;
	applep_contents[2] = NULL;  // ghost
	applep_contents[3] = NULL;

	lr->stack_top = (unsigned long) sp;

	// XXX: skip this for static executables, but we don't support them anyway...
	if (__put_user((user_long_t) lr->mh, sp++))
	{
		LOG("Failed to copy mach header address to stack\n");
		exit(1);
	}
	if (__put_user((user_long_t) lr->argc, sp++))
	{
		LOG("Failed to copy argument count to stack\n");
		exit(1);
	}

	// Fill in argv pointers
	argv = sp;
	for (int i = 0; i < lr->argc; ++i)
	{
		if (!lr->argv[i]) {
			lr->argc = i;
			break;
		}
		if (__put_user((user_long_t) lr->argv[i], argv++))
		{
			LOG("Failed to copy an argument pointer to stack\n");
			exit(1);
		}
	}
	if (__put_user((user_long_t) 0, argv++))
	{
		LOG("Failed to null-terminate the argument pointer array\n");
		exit(1);
	}

	// Fill in envp pointers
	envp = argv;
	for (int i = 0; i < lr->envc; ++i)
	{
		if (!lr->envp[i]) {
			lr->envc = i;
			break;
		}

		if (__put_user((user_long_t) lr->envp[i], envp++))
		{
			LOG("Failed to copy an environment variable pointer to stack\n");
			exit(1);
		}
	}
	if (__put_user((user_long_t) 0, envp++))
	{
		LOG("Failed to null-terminate the environment variable pointer array\n");
		exit(1);
	}

	applep = envp; // envp is now at the end of env pointers

	for (int i = 0; i < sizeof(applep_contents)/sizeof(applep_contents[0]); i++)
	{
		if (__put_user((user_long_t)(unsigned long) applep_contents[i], applep++))
		{
			LOG("Failed to copy an applep value to stack\n");
			exit(1);
		}
	}

	// get_random_bytes(rand_bytes, sizeof(rand_bytes));

	// TODO: produce stack_guard, e.g. stack_guard=0xcdd5c48c061b00fd (must contain 00 somewhere!)
	// TODO: produce malloc_entropy, e.g. malloc_entropy=0x9536cc569d9595cf,0x831942e402da316b
	// TODO: produce main_stack?
}
