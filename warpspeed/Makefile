warpspeed: vm.c loader.c commpage.c
	clang -DDEBUG -g -o warpspeed -framework Hypervisor -mmacosx-version-min=11.0 syscall_t.S vm.c shared_cache.c loader.c commpage.c
	codesign --entitlements warpspeed.entitlements --force -s - warpspeed

.PHONY: clean
clean:
	rm -rf warpspeed warpspeed.dSYM
