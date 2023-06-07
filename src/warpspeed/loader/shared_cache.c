#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach/vm_region.h>
#include <mach/mach_vm.h>
#include <mach/mach.h>

#include "common.h"
#include "loader.h"
#include "dyld_cache_format.h"


// ghost TODO: could we just call https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/SharedCacheRuntime.cpp#L936 directly somehow?

void map_single_cache(char *path, struct load_results *res, vm_address_t base_address, uint64_t cache_offset) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOG("error opening cache: %s", strerror(errno));
        exit(1);
    }

    struct dyld_cache_header cache_header;
    assert(pread(fd, &cache_header, sizeof(cache_header), 0) == sizeof(cache_header));
    LOG("cache base %p\n", cache_header.sharedRegionStart);

    for (int i = 0; i < cache_header.mappingWithSlideCount; i++) {
        struct dyld_cache_mapping_and_slide_info map_and_slide;
        assert(pread(fd, &map_and_slide, sizeof(map_and_slide), cache_header.mappingWithSlideOffset + (i * sizeof(map_and_slide))) == sizeof(map_and_slide));
        LOG("%p %p %p %p %p %p\n", map_and_slide.address, map_and_slide.size, map_and_slide.fileOffset, map_and_slide.slideInfoFileOffset, map_and_slide.slideInfoFileSize, map_and_slide.flags);
        uint64_t slide = base_address - cache_header.sharedRegionStart;
        uint64_t addr = map_and_slide.address + cache_offset + slide;
        LOG("map to %p (slide %p)\n", addr, slide);
        if (mmap(addr, map_and_slide.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, map_and_slide.fileOffset) == MAP_FAILED) {
            LOG("failed to mmap: %s\n", strerror(errno));
            exit(1);
        }
        res->mappings[res->n_mappings++] = (struct vm_mmap) {
            .hyper = (void*)addr,
            .guest_va = addr,
            .len = map_and_slide.size,
            .prot = PROT_READ | PROT_WRITE,
        };
        if (map_and_slide.slideInfoFileSize > 0) {
            uint32_t slide_ver;
            assert(pread(fd, &slide_ver, sizeof(slide_ver), map_and_slide.slideInfoFileOffset) == sizeof(slide_ver));
            switch (slide_ver) {
                case 3: {
                    // https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/SharedCacheRuntime.cpp#L688
                    // https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/cache-builder/dyld_cache_format.h#L337
                    struct dyld_cache_slide_info3 *slideInfo = malloc(map_and_slide.slideInfoFileSize);
                    assert(pread(fd, slideInfo, map_and_slide.slideInfoFileSize, map_and_slide.slideInfoFileOffset) == map_and_slide.slideInfoFileSize);
                    LOG("page_size=%p\n", slideInfo->page_size);
                    LOG("page_starts_count=%d\n", slideInfo->page_starts_count);
                    LOG("auth_value_add=0x%016llX\n", slideInfo->auth_value_add);
                    const uintptr_t authValueAdd = (uintptr_t)(slideInfo->auth_value_add);
                    for (int i=0; i < slideInfo->page_starts_count; ++i) {
                        uint16_t delta = slideInfo->page_starts[i];
                        if ( delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE ) {
                            continue;
                        }

                        delta = delta/sizeof(uint64_t); // initial offset is byte based
                        const uint8_t* pageStart = addr + (i * slideInfo->page_size);
                        union dyld_cache_slide_pointer3* loc = (union dyld_cache_slide_pointer3*)pageStart;
                        do {
                            loc += delta;
                            delta = loc->plain.offsetToNextPointer;
                            if (loc->auth.authenticated) {
                                loc->raw = loc->auth.offsetFromSharedCacheBase + slide + authValueAdd;
                            } else {
                                uint64_t value51      = loc->plain.pointerValue;
                                uint64_t top8Bits     = value51 & 0x0007F80000000000ULL;
                                uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
                                uint64_t targetValue  = ( top8Bits << 13 ) | bottom43Bits;
                                loc->raw = targetValue + slide;
                            }
                            /* LOG("fixing up %p to %p\n", loc, loc->raw); */
                        } while (delta != 0);
                    }
                    free(slideInfo);
                    break;
                }
                default:
                    LOG("unhandled slide ver %d\n", slide_ver);
                    break;
            }
        }
    }

    LOG("subcaches %d\n", cache_header.subCacheArrayCount);

    for (int i = 0; i < cache_header.subCacheArrayCount; i++) {
        struct dyld_subcache_entry subcache;
        assert(pread(fd, &subcache, sizeof(subcache), cache_header.subCacheArrayOffset + (i * sizeof(subcache))) == sizeof(subcache));

        char sub_path[4096];
        snprintf(sub_path, sizeof(sub_path), "%s.%02d", path, i+1);
        map_single_cache(sub_path, res, base_address, subcache.cacheVMOffset);
    }
}

// https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/common/DyldSharedCache.cpp#L1703
vm_address_t map_shared_cache(struct load_results *res) {
    const char *shared_cache_path = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e";
    int fd = open(shared_cache_path, O_RDONLY);
    if (fd < 0) {
        LOG("error opening cache: %s\n", strerror(errno));
        exit(1);
    }
    struct dyld_cache_header cache_header;
    assert(pread(fd, &cache_header, sizeof(cache_header), 0) == sizeof(cache_header));
    vm_address_t shared_cache_base;
    assert(vm_allocate(mach_task_self(), &shared_cache_base, cache_header.sharedRegionSize, VM_FLAGS_ANYWHERE) == KERN_SUCCESS);

    map_single_cache(shared_cache_path, res, shared_cache_base, 0);

    // https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/SharedCacheRuntime.cpp#L632
    void *dyndata = shared_cache_base + cache_header.dynamicDataOffset;
    LOG("mapping dynamic data at %p\n", dyndata);
    if (mmap(dyndata, cache_header.dynamicDataMaxSize, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) {
        LOG("error mmpaing dynamic data: %s\n", strerror(errno));
        exit(1);
    }
    res->mappings[res->n_mappings++] = (struct vm_mmap) {
        .hyper = dyndata,
        .guest_va = dyndata,
        .len = cache_header.dynamicDataMaxSize,
        .prot = PROT_READ | PROT_WRITE,
    };
    struct dyld_cache_dynamic_data_header* dynamicData = (struct dyld_cache_dynamic_data_header*)dyndata;
    strlcpy(dynamicData->magic, DYLD_SHARED_CACHE_DYNAMIC_DATA_MAGIC, 16);
    struct stat cache_stat;
    fstat(fd, &cache_stat);
    dynamicData->fsId = cache_stat.st_dev;
    dynamicData->fsObjId = cache_stat.st_ino;

    close(fd);
    return shared_cache_base;
}
