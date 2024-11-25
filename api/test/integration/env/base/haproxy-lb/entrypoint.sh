#!/usr/bin/env bash

haproxy -f /etc/haproxy/haproxy.conf
tail -f /dev/null
