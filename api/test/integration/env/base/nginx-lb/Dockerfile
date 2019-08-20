FROM nginx

#RUN apt-get update && apt-get install -y vim && apt-get install -y net-tools && apt-get install -y procps

COPY nginx.conf /etc/nginx/nginx.conf

ADD entrypoint.sh /scripts/entrypoint.sh
