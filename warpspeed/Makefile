warpspeed: vm.c loader.c commpage.c
	clang -o warpspeed -O2 -framework Hypervisor -mmacosx-version-min=11.0 -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/local/include/ vm.c loader.c commpage.c
	codesign --entitlements warpspeed.entitlements --force -s - warpspeed

.PHONY: clean
clean:
	rm -f warpspeed
