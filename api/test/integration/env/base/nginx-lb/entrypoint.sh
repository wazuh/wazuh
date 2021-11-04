#!/usr/bin/env bash

if [ $1 == "standalone" ]; then
  # Remove workers upstream configurations (in upstream mycluster and upstream register)
  sed -i -E '/wazuh-worker1|wazuh-worker2/d' /etc/nginx/nginx.conf;
fi

until service nginx start; do
  echo "nginx couldn´t start - sleeping for 1 second"
  sleep 1
done

tail -f /var/log/nginx/error.log
