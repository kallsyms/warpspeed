CODESIGN := codesign
CARGO := cargo +nightly

TARGET := mrr
TARGET_DEBUG := target/debug/$(TARGET)
# TODO
TARGET_TEST := target/debug/$(TARGET)
TARGET_RELEASE := target/release/$(TARGET)

.PHONY: build-debug
build-debug:
	$(CARGO) build
	$(CODESIGN) --entitlements mrr.entitlements --force -s - "$(TARGET_DEBUG)"

.PHONY: test
test:
	$(CARGO) test --no-run
	$(CODESIGN) --entitlements mrr.entitlements --force -s - "$(TARGET_TEST)"
	$(TARGET_TEST)
