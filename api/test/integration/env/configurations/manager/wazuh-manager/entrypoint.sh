#!/usr/bin/env bash

sleep 1

# We stop workers to work with single manager
/var/ossec/bin/ossec-control stop

/usr/bin/supervisord
