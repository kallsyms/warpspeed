.PHONY: all
all: rust lldb

.PHONY: rust
rust:
	cargo build

.PHONY: lldb
lldb:
	protoc --python_out=lldb/ $(shell find src/recordable -name '*.proto')

.PHONY: clean
clean:
	cargo clean
	rm -f lldb/proto.py
