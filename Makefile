CODESIGN := codesign
CARGO := cargo +nightly

TARGET := warpspeed
TARGET_DEBUG := target/debug/$(TARGET)
TARGET_RELEASE := target/release/$(TARGET)

.PHONY: build-debug
build-debug:
	$(CARGO) build
	$(CODESIGN) --entitlements warpspeed.entitlements --force -s - "$(TARGET_DEBUG)"

.PHONY: build-release
build-release:
	$(CARGO) build --release
	$(CODESIGN) --entitlements warpspeed.entitlements --force -s - "$(TARGET_RELEASE)"
