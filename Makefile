CODESIGN := codesign
CARGO := cargo +nightly

TARGET := mrr
TARGET_DEBUG := target/debug/$(TARGET)
TARGET_RELEASE := target/release/$(TARGET)

.PHONY: build-debug
build-debug:
	$(CARGO) build
	$(CODESIGN) --entitlements mrr.entitlements --force -s - "$(TARGET_DEBUG)"

.PHONY: build-release
build-release:
	$(CARGO) build --release
	$(CODESIGN) --entitlements mrr.entitlements --force -s - "$(TARGET_RELEASE)"
