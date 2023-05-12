#!/bin/bash

DYLD_INSERT_LIBRARIES=${PWD}/target/debug/libmrr_interpose.dylib ./test/echo
ret=$?

echo "Returned ${ret}"
