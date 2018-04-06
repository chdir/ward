#!/bin/bash -ex
cd "$(dirname "$0")"
exec {source}< $2 # source.jpg
exec {target}> $4 # target.jpg
LD_LIBRARY_PATH=./bin LD_PRELOAD=./bin/jail LANG=C ./bin/vips --vips-concurrency=1 resize "/proc/self/fd/${source}" "/proc/self/fd/${target}.jpeg" 1

# SYSCALL_DEBUG=1 strace -eopen,openat -E LD_PRELOAD=./jail

