CODESIGN := codesign
CARGO := cargo +nightly

TARGET := warpspeed_rs
TARGET_DEBUG := target/debug/$(TARGET)
TARGET_TEST := target/debug/$(TARGET)
TARGET_RELEASE := target/release/$(TARGET)

.PHONY: build-debug
build-debug:
	$(CARGO) build
	$(CODESIGN) --entitlements warpspeed.entitlements --force -s - "$(TARGET_DEBUG)"

.PHONY: test
test:
	$(CARGO) test --no-run
	$(CODESIGN) --entitlements warpspeed.entitlements --force -s - "$(TARGET_TEST)"
	$(TARGET_TEST)
