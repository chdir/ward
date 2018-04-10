#!/bin/bash -ex
cd "$(dirname "$0")"
exec {source}< $2 # source.jpg
exec {target}> $4 # target.jpg
D_PRELOAD=./bin/jail TMPDIR=/var/www/upload/user/ VIPS_DISC_THRESHOLD=5m LANG=C ./bin/vips --vips-concurrency=1 resize "/proc/self/fd/${source}" "/proc/self/fd/${target}.jpeg" 1

