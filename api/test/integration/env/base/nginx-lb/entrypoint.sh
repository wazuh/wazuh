#!/usr/bin/env bash

if [ $1 == "standalone" ]; then
  # Remove workers upstream configurations (in upstream mycluster and upstream register)
  sed -i -E '/wazuh-worker1|wazuh-worker2/d' /etc/nginx/nginx.conf;
fi

 exec nginx -g 'daemon off;' 
