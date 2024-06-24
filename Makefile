CODESIGN := codesign
CARGO := cargo +nightly

TARGET := warpspeed
TARGET_RELEASE := target/release/$(TARGET)
TARGET_DEBUG := target/debug/$(TARGET)

.PHONY: build-release
build-release:
	$(CARGO) build --release
	$(CODESIGN) --entitlements warpspeed.entitlements --force -s - "$(TARGET_RELEASE)"

.PHONY: build-debug
build-debug:
	$(CARGO) build
	$(CODESIGN) --entitlements warpspeed.entitlements --force -s - "$(TARGET_DEBUG)"
