#!/bin/sh

redis-server /usr/local/etc/redis/redis.conf

python3 main.py "$@"
