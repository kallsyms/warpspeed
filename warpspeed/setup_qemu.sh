#!/bin/bash
set -xueo pipefail

dirs=$1
tmpf="/tmp/commands"

echo 'gdb-remote localhost:1234' > $tmpf

pushd $dirs
for addr in *; do
    echo "memory write -i ${dirs}/${addr} ${addr}" >> $tmpf
done
popd

asm=$(rasm2 -a arm -b 64 -f test.S | sed 's/.\{2\}/& /g')
echo "memory write 0x4000 ${asm}" >> $tmpf
echo "register write pc 0x4000" >> $tmpf

lldb -s $tmpf
