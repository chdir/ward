#!/bin/bash
cd "$(dirname "$0")"
exec 0< $2 # source.jpg
exec 1> $4 # target.jpg
LD_PRELOAD=./jail LANG=C ./magick convert -delete 1--1 -strip -limit Disk 0 -limit Map 0 -limit Memory 50M -limit Width 9999 -limit Height 9999 $1:-[0] $3:-

# SYSCALL_DEBUG=1 strace -eopen,openat -E LD_PRELOAD=./a.out
