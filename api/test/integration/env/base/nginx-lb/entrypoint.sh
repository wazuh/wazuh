#!/usr/bin/env bash

until service nginx start; do
  echo "nginx couldn´t start - sleeping for 1 second"
  sleep 1
done

tail -f /var/log/nginx/error.log
