FROM nginx

# Variable used to indicate which nginx configuration should be copied
ARG DOCKER_COMPOSE_FILE

# Copy both nginx configurations to the nginx folder
COPY nginx_cluster.conf /etc/nginx/nginx_cluster.conf
COPY nginx_no_cluster.conf /etc/nginx/nginx_no_cluster.conf

# Copy nginx_cluster.conf or nginx_no_cluster.conf to nginx.conf to set the nginx configuration
RUN if [ "$DOCKER_COMPOSE_FILE" = "docker-compose_standalone.yml" ] ; then cp /etc/nginx/nginx_no_cluster.conf /etc/nginx/nginx.conf ;  else cp /etc/nginx/nginx_cluster.conf /etc/nginx/nginx.conf ; fi

ADD entrypoint.sh /scripts/entrypoint.sh
