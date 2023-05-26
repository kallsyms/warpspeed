warpspeed: vm.c loader.c commpage.c
	clang -o warpspeed -O2 -framework Hypervisor -mmacosx-version-min=11.0 -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/local/include/ syscall_t.S vm.c loader.c commpage.c
	codesign --entitlements warpspeed.entitlements --force -s - warpspeed

test: test_fork.c
	clang -o test -O2 -framework Hypervisor -mmacosx-version-min=11.0 -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/local/include/ test_fork.c
	codesign --entitlements warpspeed.entitlements --force -s - test

TOOLPATH = $(shell dirname $(shell xcodebuild -find clang))

HelloWorld: HelloWorld.o
	$(TOOLPATH)/ld -o HelloWorld HelloWorld.o -lSystem -syslibroot `xcrun -sdk macosx --show-sdk-path` -e _start -arch arm64

HelloWorld.o: HelloWorld.s
	$(TOOLPATH)/as -o HelloWorld.o HelloWorld.s

.PHONY: clean
clean:
	rm -f warpspeed
